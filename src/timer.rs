//! A timer scheduler: one worker thread runs callbacks at their deadlines.
//!
//! [`Timer::schedule`] registers a callback and returns an [`Entry`], through
//! which it can be cancelled or moved to another time for as long as it is
//! pending. Deadlines are monotonic [`Instant`]s, so wall-clock changes do not
//! disturb them (and, as with every `Instant` on Linux, time spent suspended
//! does not count).
//!
//! Callbacks run on the worker thread, one at a time and outside the internal
//! lock, so they may schedule, cancel and reschedule freely, themselves
//! included. A slow callback delays the ones behind it. A callback that
//! returns a [`Next`] stays registered: that is how a periodic timer is made.
//!
//! Every entry has a name, and [`Timer::snapshot`] lists what is registered:
//! when each is due, whether it is running, and how often it has run. That is
//! what to show when debugging which timers there are.
//!
//! Long times are safe: a deadline too far away for an `Instant` to hold means
//! "never", and the entry stays pending and cancellable. The worker also never
//! waits longer than [`MAX_WAIT`] at once, however far away the next deadline
//! is.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io;
use std::panic::{self, AssertUnwindSafe};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, Weak};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// The longest the worker sleeps in one go. It only bounds a single wait; the
/// worker goes back to sleep until the real deadline.
const MAX_WAIT: Duration = Duration::from_secs(3600);

/// What a callback asks for when it returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    /// Done: the entry is removed.
    Stop,
    /// Run again this long from now.
    After(Duration),
    /// Run again at this time.
    At(Instant),
}

type Callback = Box<dyn FnMut() -> Next + Send>;

struct Slot {
    name: String,
    /// How many times the callback has run, and when it last started and how
    /// long that took. Only for [`Timer::snapshot`].
    runs: u64,
    last_run: Option<Instant>,
    last_took: Option<Duration>,
    running: bool,
    /// `None` while it is running on the worker thread.
    callback: Option<Callback>,
    /// Its place in the queue; `None` if it is running or is never due.
    key: Option<(Instant, u64)>,
    /// Bumped by every reschedule, so the worker can tell that the entry was
    /// moved while its callback ran, and then ignores the callback's [`Next`].
    epoch: u64,
}

#[derive(Default)]
struct State {
    slots: HashMap<u64, Slot>,
    /// Due time, then insertion order (so equal times run first come, first
    /// served), to the slot's id. Holds exactly the slots whose `key` is set.
    queue: BTreeMap<(Instant, u64), u64>,
    next_id: u64,
    next_seq: u64,
    stopped: bool,
}

impl State {
    /// Put a slot in the queue at `at`, or take it out of the queue for good
    /// if `at` is `None`.
    fn place(&mut self, id: u64, at: Option<Instant>) {
        let Some(slot) = self.slots.get_mut(&id) else {
            return;
        };
        if let Some(old) = slot.key.take() {
            self.queue.remove(&old);
        }
        if let Some(at) = at {
            let key = (at, self.next_seq);
            self.next_seq += 1;
            slot.key = Some(key);
            self.queue.insert(key, id);
        }
    }

    fn remove(&mut self, id: u64) -> Option<Slot> {
        let slot = self.slots.remove(&id)?;
        if let Some(key) = slot.key {
            self.queue.remove(&key);
        }
        Some(slot)
    }

    /// Record the outcome of a callback. Returns a callback to drop once the
    /// lock is released: dropping one may drop an [`Entry`], which locks.
    fn finish(
        &mut self,
        id: u64,
        epoch: u64,
        callback: Callback,
        outcome: thread::Result<Next>,
    ) -> Option<Callback> {
        let Some(slot) = self.slots.get_mut(&id) else {
            return Some(callback); // cancelled while it ran
        };
        slot.running = false;
        slot.last_took = slot.last_run.map(|t| t.elapsed());
        if slot.epoch != epoch {
            slot.callback = Some(callback); // moved while it ran: that wins
            return None;
        }
        let next = outcome.unwrap_or_else(|_| {
            eprintln!("timer: a callback panicked, removing it");
            Next::Stop
        });
        let at = match next {
            Next::Stop => {
                self.remove(id);
                return Some(callback);
            }
            Next::After(after) => deadline(after),
            Next::At(at) => Some(at),
        };
        slot.callback = Some(callback);
        self.place(id, at);
        None
    }
}

/// `after` from now, or `None` if that is beyond what an `Instant` can hold.
fn deadline(after: Duration) -> Option<Instant> {
    Instant::now().checked_add(after)
}

struct Shared {
    state: Mutex<State>,
    wake: Condvar,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        // Callbacks never run under the lock, so poisoning would be a bug in
        // this module; the state is consistent between statements anyway.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn add(&self, name: String, at: Option<Instant>, callback: Callback) -> Option<u64> {
        let mut state = self.lock();
        if state.stopped {
            return None;
        }
        let id = state.next_id;
        state.next_id += 1;
        state.slots.insert(
            id,
            Slot {
                name,
                runs: 0,
                last_run: None,
                last_took: None,
                running: false,
                callback: Some(callback),
                key: None,
                epoch: 0,
            },
        );
        state.place(id, at);
        drop(state);
        self.wake.notify_one();
        Some(id)
    }

    fn cancel(&self, id: u64) -> bool {
        let removed = self.lock().remove(id);
        // Dropped here, after the lock: the callback may own an `Entry`.
        removed.is_some()
    }

    fn reschedule(&self, id: u64, at: Option<Instant>) -> bool {
        let mut state = self.lock();
        let Some(slot) = state.slots.get_mut(&id) else {
            return false;
        };
        slot.epoch += 1;
        state.place(id, at);
        drop(state);
        self.wake.notify_one();
        true
    }

    fn pending(&self, id: u64) -> bool {
        self.lock().slots.contains_key(&id)
    }

    fn snapshot(&self) -> Vec<Info> {
        let state = self.lock();
        let mut all: Vec<Info> = state
            .slots
            .iter()
            .map(|(&id, slot)| Info {
                id,
                name: slot.name.clone(),
                due: slot.key.map(|(at, _)| at),
                running: slot.running,
                runs: slot.runs,
                last_run: slot.last_run,
                last_took: slot.last_took,
            })
            .collect();
        // Soonest first, the ones that are never due last, ties by age.
        all.sort_by_key(|i| (i.due.is_none(), i.due, i.id));
        all
    }

    fn run(&self) {
        let mut state = self.lock();
        while !state.stopped {
            let now = Instant::now();
            let Some((&(at, _), &id)) = state.queue.first_key_value() else {
                state = self.wake.wait(state).unwrap_or_else(PoisonError::into_inner);
                continue;
            };
            if at > now {
                let wait = (at - now).min(MAX_WAIT);
                state = self
                    .wake
                    .wait_timeout(state, wait)
                    .unwrap_or_else(PoisonError::into_inner)
                    .0;
                continue;
            }

            state.place(id, None);
            let Some(slot) = state.slots.get_mut(&id) else {
                continue;
            };
            let epoch = slot.epoch;
            let Some(mut callback) = slot.callback.take() else {
                continue;
            };
            slot.running = true;
            slot.runs += 1;
            slot.last_run = Some(now);
            drop(state);
            let outcome = panic::catch_unwind(AssertUnwindSafe(&mut callback));
            state = self.lock();
            if let Some(dead) = state.finish(id, epoch, callback, outcome) {
                drop(state);
                drop(dead);
                state = self.lock();
            }
        }
    }
}

/// What [`Timer::snapshot`] reports about one registered entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    /// Unique for the life of the timer; the same as the [`Entry`]'s.
    pub id: u64,
    pub name: String,
    /// When it is next due. `None` if it is running now, or never due (it was
    /// scheduled for a time too far away to represent).
    pub due: Option<Instant>,
    /// Its callback is running right now.
    pub running: bool,
    /// How many times its callback has run.
    pub runs: u64,
    /// When the callback last started, and how long that run took.
    pub last_run: Option<Instant>,
    pub last_took: Option<Duration>,
}

/// The scheduler. Dropping it stops the worker thread, and every pending entry
/// with it, without running them.
pub struct Timer {
    shared: Arc<Shared>,
    worker: Option<JoinHandle<()>>,
}

impl Timer {
    /// Start the worker thread. It inherits the caller's signal mask.
    pub fn new() -> io::Result<Timer> {
        let shared = Arc::new(Shared {
            state: Mutex::new(State::default()),
            wake: Condvar::new(),
        });
        let worker = thread::Builder::new().name("timer".into()).spawn({
            let shared = Arc::clone(&shared);
            move || shared.run()
        })?;
        Ok(Timer {
            shared,
            worker: Some(worker),
        })
    }

    /// Run `callback` once `after` has passed. A time too far away to
    /// represent is never reached, but the entry can still be rescheduled.
    /// `name` says what the entry is for, in [`Timer::snapshot`].
    pub fn schedule(
        &self,
        name: impl Into<String>,
        after: Duration,
        callback: impl FnMut() -> Next + Send + 'static,
    ) -> Entry {
        self.register(name.into(), deadline(after), Box::new(callback))
    }

    /// Run `callback` at `at`; at once, if that is in the past.
    pub fn schedule_at(
        &self,
        name: impl Into<String>,
        at: Instant,
        callback: impl FnMut() -> Next + Send + 'static,
    ) -> Entry {
        self.register(name.into(), Some(at), Box::new(callback))
    }

    /// Every registered entry, soonest first: the ones that are never due last.
    pub fn snapshot(&self) -> Vec<Info> {
        self.shared.snapshot()
    }

    /// A handle that can take snapshots but does not keep the timer alive.
    pub fn watcher(&self) -> Watcher {
        Watcher { shared: Arc::downgrade(&self.shared) }
    }

    fn register(&self, name: String, at: Option<Instant>, callback: Callback) -> Entry {
        Entry {
            shared: Arc::downgrade(&self.shared),
            // After shutdown there is nothing to register with; the entry is
            // simply never pending.
            id: self.shared.add(name, at, callback).unwrap_or(u64::MAX),
            detached: false,
        }
    }
}

impl fmt::Debug for Timer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.snapshot()).finish()
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        let abandoned = {
            let mut state = self.shared.lock();
            state.stopped = true;
            state.queue.clear();
            std::mem::take(&mut state.slots)
        };
        self.shared.wake.notify_one();
        // The callbacks go after the lock: they may own entries.
        drop(abandoned);
        if let Some(worker) = self.worker.take() {
            // A callback that drops the timer cannot wait for itself.
            if worker.thread().id() != thread::current().id() {
                let _ = worker.join();
            }
        }
    }
}

/// A way to look at a timer's entries without owning it, or keeping it alive.
/// The default one watches nothing.
#[derive(Clone, Default)]
pub struct Watcher {
    shared: Weak<Shared>,
}

impl Watcher {
    /// [`Timer::snapshot`], or `None` if the timer has been dropped.
    pub fn snapshot(&self) -> Option<Vec<Info>> {
        self.shared.upgrade().map(|shared| shared.snapshot())
    }
}

/// A registered callback. Dropping the entry cancels it, so the callback
/// cannot outlive whatever owns the entry; [`detach`](Entry::detach) it to let
/// it run regardless.
pub struct Entry {
    shared: Weak<Shared>,
    id: u64,
    detached: bool,
}

impl Entry {
    /// Cancel the callback. Returns whether it was still pending: false if it
    /// already ran for the last time, or was cancelled before. A callback that
    /// is running right now finishes, but is not run again.
    pub fn cancel(&self) -> bool {
        self.shared.upgrade().is_some_and(|shared| shared.cancel(self.id))
    }

    /// Move the callback to `after` from now, whether it was waiting for
    /// something nearer or farther. Returns false if it is no longer pending,
    /// which cannot be undone. Called while the callback is running, it takes
    /// precedence over what the callback returns.
    pub fn reschedule(&self, after: Duration) -> bool {
        self.move_to(deadline(after))
    }

    /// Like [`reschedule`](Entry::reschedule), at a given time.
    pub fn reschedule_at(&self, at: Instant) -> bool {
        self.move_to(Some(at))
    }

    fn move_to(&self, at: Option<Instant>) -> bool {
        self.shared
            .upgrade()
            .is_some_and(|shared| shared.reschedule(self.id, at))
    }

    /// The id this entry has in [`Timer::snapshot`].
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Whether the callback is still registered: it has not been cancelled,
    /// has not stopped itself, and the timer is still running.
    pub fn is_pending(&self) -> bool {
        self.shared.upgrade().is_some_and(|shared| shared.pending(self.id))
    }

    /// Let the callback run without keeping the entry. It can no longer be
    /// cancelled or moved, only stop itself, or end with the timer.
    pub fn detach(mut self) {
        self.detached = true;
    }
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry").field("id", &self.id).field("pending", &self.is_pending()).finish()
    }
}

impl Drop for Entry {
    fn drop(&mut self) {
        if !self.detached {
            self.cancel();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    const MS: Duration = Duration::from_millis(1);
    /// Generous: only the failure case waits this long.
    const SLOW: Duration = Duration::from_secs(5);

    fn notify(tx: &mpsc::Sender<u32>, n: u32) -> impl FnMut() -> Next + Send + use<> {
        let tx = tx.clone();
        move || {
            let _ = tx.send(n);
            Next::Stop
        }
    }

    #[test]
    fn runs_once_after_the_delay() {
        let timer = Timer::new().unwrap();
        let (tx, rx) = mpsc::channel();
        let start = Instant::now();
        let entry = timer.schedule("test", 40 * MS, notify(&tx, 1));
        assert!(entry.is_pending());

        assert_eq!(rx.recv_timeout(SLOW), Ok(1));
        assert!(start.elapsed() >= 40 * MS);
        assert!(rx.recv_timeout(100 * MS).is_err(), "ran twice");
        assert!(!entry.is_pending());
        assert!(!entry.cancel());
        assert!(!entry.reschedule(MS), "a finished entry cannot be revived");
    }

    #[test]
    fn runs_in_deadline_order_then_insertion_order() {
        let timer = Timer::new().unwrap();
        let (tx, rx) = mpsc::channel();
        let base = Instant::now() + 60 * MS;
        let _keep = [
            timer.schedule_at("test", base + 30 * MS, notify(&tx, 1)),
            timer.schedule_at("test", base, notify(&tx, 2)),
            timer.schedule_at("test", base + 15 * MS, notify(&tx, 3)),
            timer.schedule_at("test", base + 15 * MS, notify(&tx, 4)),
        ];
        let order: Vec<u32> = (0..4).map(|_| rx.recv_timeout(SLOW).unwrap()).collect();
        assert_eq!(order, [2, 3, 4, 1]);
    }

    #[test]
    fn a_time_in_the_past_runs_at_once() {
        let timer = Timer::new().unwrap();
        let (tx, rx) = mpsc::channel();
        let _entry = timer.schedule_at("test", Instant::now() - Duration::from_secs(1), notify(&tx, 1));
        assert_eq!(rx.recv_timeout(SLOW), Ok(1));
    }

    #[test]
    fn cancel_prevents_the_callback() {
        let timer = Timer::new().unwrap();
        let (tx, rx) = mpsc::channel();
        let entry = timer.schedule("test", 50 * MS, notify(&tx, 1));
        assert!(entry.cancel());
        assert!(!entry.is_pending());
        assert!(!entry.cancel(), "second cancel is a no-op");
        assert!(rx.recv_timeout(200 * MS).is_err());
    }

    #[test]
    fn dropping_an_entry_cancels_it_and_detach_keeps_it() {
        let timer = Timer::new().unwrap();
        let (tx, rx) = mpsc::channel();
        drop(timer.schedule("test", 30 * MS, notify(&tx, 1)));
        timer.schedule("test", 30 * MS, notify(&tx, 2)).detach();
        assert_eq!(rx.recv_timeout(SLOW), Ok(2));
        assert!(rx.recv_timeout(150 * MS).is_err(), "the dropped one ran");
    }

    #[test]
    fn reschedule_later_and_earlier() {
        let timer = Timer::new().unwrap();
        let (tx, rx) = mpsc::channel();

        let start = Instant::now();
        let later = timer.schedule("test", 30 * MS, notify(&tx, 1));
        assert!(later.reschedule(300 * MS));
        assert!(rx.recv_timeout(150 * MS).is_err(), "ran at the old time");
        assert_eq!(rx.recv_timeout(SLOW), Ok(1));
        assert!(start.elapsed() >= 300 * MS);

        let sooner = timer.schedule("test", Duration::from_secs(3600), notify(&tx, 2));
        assert!(sooner.reschedule(10 * MS));
        assert_eq!(rx.recv_timeout(SLOW), Ok(2));
    }

    #[test]
    fn reschedule_at_a_time() {
        let timer = Timer::new().unwrap();
        let (tx, rx) = mpsc::channel();
        let entry = timer.schedule("test", Duration::from_secs(3600), notify(&tx, 1));
        assert!(entry.reschedule_at(Instant::now() + 20 * MS));
        assert_eq!(rx.recv_timeout(SLOW), Ok(1));
    }

    #[test]
    fn a_callback_can_repeat_and_stop() {
        let timer = Timer::new().unwrap();
        let (tx, rx) = mpsc::channel();
        let mut runs = 0;
        let entry = timer.schedule("test", 10 * MS, move || {
            runs += 1;
            let _ = tx.send(runs);
            if runs < 3 { Next::After(10 * MS) } else { Next::Stop }
        });
        let seen: Vec<u32> = (0..3).map(|_| rx.recv_timeout(SLOW).unwrap()).collect();
        assert_eq!(seen, [1, 2, 3]);
        assert!(rx.recv_timeout(100 * MS).is_err());
        assert!(!entry.is_pending());
    }

    #[test]
    fn next_at_is_honoured() {
        let timer = Timer::new().unwrap();
        let (tx, rx) = mpsc::channel();
        let mut first = true;
        let _entry = timer.schedule("test", MS, move || {
            let _ = tx.send(0);
            if std::mem::take(&mut first) {
                Next::At(Instant::now() + 20 * MS)
            } else {
                Next::Stop
            }
        });
        assert_eq!(rx.recv_timeout(SLOW), Ok(0));
        assert_eq!(rx.recv_timeout(SLOW), Ok(0));
    }

    #[test]
    fn absurdly_long_times_do_not_panic() {
        let timer = Timer::new().unwrap();
        let (tx, rx) = mpsc::channel();

        // Too far for an Instant: never due, but registered.
        let never = timer.schedule("test", Duration::MAX, notify(&tx, 1));
        assert!(never.is_pending());
        let year = timer.schedule("test", Duration::from_secs(365 * 24 * 3600), notify(&tx, 2));
        assert!(rx.recv_timeout(100 * MS).is_err());

        // They can still be moved...
        assert!(never.reschedule(10 * MS));
        assert_eq!(rx.recv_timeout(SLOW), Ok(1));
        // ...or cancelled.
        assert!(year.cancel());

        // Moving to "never" parks it without losing it.
        let parked = timer.schedule("test", 10 * MS, notify(&tx, 3));
        assert!(parked.reschedule(Duration::MAX));
        assert!(rx.recv_timeout(100 * MS).is_err());
        assert!(parked.is_pending());
        assert!(parked.reschedule(MS));
        assert_eq!(rx.recv_timeout(SLOW), Ok(3));

        // A callback may ask for "never" too.
        let mut once = true;
        let tx2 = tx.clone();
        let sleeper = timer.schedule("test", MS, move || {
            let _ = tx2.send(4);
            assert!(std::mem::take(&mut once));
            Next::After(Duration::MAX)
        });
        assert_eq!(rx.recv_timeout(SLOW), Ok(4));
        assert!(rx.recv_timeout(100 * MS).is_err());
        assert!(sleeper.cancel());

        // The worker still works afterwards.
        let _ok = timer.schedule("test", MS, notify(&tx, 5));
        assert_eq!(rx.recv_timeout(SLOW), Ok(5));
    }

    #[test]
    fn cancel_while_the_callback_runs_stops_the_repeat() {
        let timer = Timer::new().unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (go_tx, go_rx) = mpsc::channel::<()>();
        let (ran_tx, ran_rx) = mpsc::channel();
        let entry = timer.schedule("test", MS, move || {
            let _ = ran_tx.send(());
            let _ = started_tx.send(());
            let _ = go_rx.recv_timeout(SLOW);
            Next::After(10 * MS)
        });
        started_rx.recv_timeout(SLOW).unwrap();
        assert!(entry.cancel());
        go_tx.send(()).unwrap();

        ran_rx.recv_timeout(SLOW).unwrap();
        assert!(ran_rx.recv_timeout(200 * MS).is_err(), "ran again after cancel");
    }

    #[test]
    fn reschedule_while_the_callback_runs_beats_its_return_value() {
        let timer = Timer::new().unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (go_tx, go_rx) = mpsc::channel::<()>();
        let (ran_tx, ran_rx) = mpsc::channel();
        let entry = timer.schedule("test", MS, move || {
            let _ = ran_tx.send(());
            let _ = started_tx.send(());
            let _ = go_rx.recv_timeout(SLOW);
            Next::After(10 * MS) // ignored: the entry was moved meanwhile
        });
        started_rx.recv_timeout(SLOW).unwrap();
        assert!(entry.reschedule(400 * MS));
        go_tx.send(()).unwrap();

        ran_rx.recv_timeout(SLOW).unwrap();
        assert!(ran_rx.recv_timeout(200 * MS).is_err(), "returned time was used");
        assert!(ran_rx.recv_timeout(SLOW).is_ok(), "never ran at the new time");
    }

    #[test]
    fn a_panicking_callback_is_dropped_and_the_worker_survives() {
        let timer = Timer::new().unwrap();
        let (tx, rx) = mpsc::channel();
        let bad = timer.schedule("test", MS, || panic!("expected, part of the test"));
        let _good = timer.schedule("test", 30 * MS, notify(&tx, 1));
        assert_eq!(rx.recv_timeout(SLOW), Ok(1));
        assert!(!bad.is_pending());
    }

    #[test]
    fn a_callback_can_drop_an_entry_without_deadlock() {
        let timer = Timer::new().unwrap();
        let (tx, rx) = mpsc::channel();
        let victim = timer.schedule("test", Duration::from_secs(3600), notify(&tx, 1));
        let victim_alive = timer.schedule("test", Duration::from_secs(3600), notify(&tx, 2));
        let mut owned = Some(victim);
        let _killer = timer.schedule("test", MS, move || {
            drop(owned.take());
            let _ = tx.send(9);
            Next::Stop
        });
        assert_eq!(rx.recv_timeout(SLOW), Ok(9));
        assert!(victim_alive.is_pending());
    }

    #[test]
    fn cancelling_a_callback_that_owns_an_entry_does_not_deadlock() {
        let timer = Timer::new().unwrap();
        let (tx, _rx) = mpsc::channel();
        let inner = timer.schedule("test", Duration::from_secs(3600), notify(&tx, 1));
        let outer = timer.schedule("test", Duration::from_secs(3600), move || {
            let _owned = &inner;
            Next::Stop
        });
        let (done_tx, done_rx) = mpsc::channel();
        thread::spawn(move || {
            assert!(outer.cancel());
            let _ = done_tx.send(());
        });
        done_rx.recv_timeout(SLOW).expect("cancel deadlocked");
    }

    #[test]
    fn callbacks_can_use_the_timer() {
        let timer = Arc::new(Timer::new().unwrap());
        let (tx, rx) = mpsc::channel();
        let inner = Arc::clone(&timer);
        let keep = Arc::new(Mutex::new(Vec::new()));
        let kept = Arc::clone(&keep);
        timer
            .schedule("test", MS, move || {
                kept.lock().unwrap().push(inner.schedule("test", 10 * MS, notify(&tx, 7)));
                Next::Stop
            })
            .detach();
        assert_eq!(rx.recv_timeout(SLOW), Ok(7));
    }

    #[test]
    fn snapshot_lists_what_is_registered_soonest_first() {
        let timer = Timer::new().unwrap();
        assert!(timer.snapshot().is_empty());

        let (tx, _rx) = mpsc::channel();
        let later = timer.schedule("later", Duration::from_secs(600), notify(&tx, 1));
        let sooner = timer.schedule("sooner", Duration::from_secs(60), notify(&tx, 2));
        let never = timer.schedule("never", Duration::MAX, notify(&tx, 3));
        let parked = timer.schedule("parked", Duration::from_secs(5), notify(&tx, 4));
        assert!(parked.reschedule(Duration::MAX));

        let all = timer.snapshot();
        let names: Vec<&str> = all.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, ["sooner", "later", "never", "parked"]);
        assert_eq!(all[0].id, sooner.id());
        assert_eq!(all[1].id, later.id());
        assert!(all[0].due.unwrap() < all[1].due.unwrap());
        assert!(all[2..].iter().all(|i| i.due.is_none() && !i.running));
        assert!(all.iter().all(|i| i.runs == 0 && i.last_run.is_none() && i.last_took.is_none()));
        let _ = never;

        sooner.cancel();
        assert_eq!(timer.snapshot().len(), 3);
    }

    #[test]
    fn snapshot_counts_runs_and_shows_one_that_is_running() {
        let timer = Timer::new().unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (go_tx, go_rx) = mpsc::channel::<()>();
        let mut runs = 0;
        let entry = timer.schedule("worker", MS, move || {
            runs += 1;
            let _ = started_tx.send(runs);
            let _ = go_rx.recv_timeout(SLOW);
            if runs < 2 { Next::After(MS) } else { Next::After(Duration::MAX) }
        });

        assert_eq!(started_rx.recv_timeout(SLOW), Ok(1));
        let info = &timer.snapshot()[0];
        assert!(info.running && info.due.is_none());
        assert_eq!((info.runs, info.last_took), (1, None));
        go_tx.send(()).unwrap();

        assert_eq!(started_rx.recv_timeout(SLOW), Ok(2));
        go_tx.send(()).unwrap();
        // Parked after its second run; wait for that to be recorded.
        let deadline = Instant::now() + SLOW;
        let info = loop {
            let info = timer.snapshot().remove(0);
            if !info.running || Instant::now() > deadline {
                break info;
            }
            thread::sleep(MS);
        };
        assert_eq!((info.name.as_str(), info.runs, info.running, info.due), ("worker", 2, false, None));
        assert!(info.last_run.is_some() && info.last_took.is_some());
        assert_eq!(info.id, entry.id());
    }

    #[test]
    fn a_watcher_sees_the_timer_until_it_is_dropped() {
        let timer = Timer::new().unwrap();
        let (tx, _rx) = mpsc::channel();
        let _entry = timer.schedule("watched", Duration::from_secs(60), notify(&tx, 1));
        let watcher = timer.watcher();
        assert_eq!(watcher.snapshot().unwrap()[0].name, "watched");
        assert!(Watcher::default().snapshot().is_none());

        drop(timer);
        assert!(watcher.snapshot().is_none());
    }

    #[test]
    fn debug_output_names_the_entries() {
        let timer = Timer::new().unwrap();
        let (tx, _rx) = mpsc::channel();
        let entry = timer.schedule("reaper d0", Duration::from_secs(60), notify(&tx, 1));
        assert!(format!("{timer:?}").contains("reaper d0"));
        assert!(format!("{entry:?}").contains("pending: true"));
    }

    #[test]
    fn dropping_the_timer_stops_it_promptly() {
        let timer = Timer::new().unwrap();
        let (tx, rx) = mpsc::channel();
        let entry = timer.schedule("test", Duration::from_secs(3600), notify(&tx, 1));
        let soon = timer.schedule("test", Duration::from_secs(3600), notify(&tx, 2));
        let start = Instant::now();
        drop(timer);
        assert!(start.elapsed() < Duration::from_secs(2));

        assert!(!entry.is_pending());
        assert!(!entry.cancel());
        assert!(!soon.reschedule(MS));
        assert!(rx.recv_timeout(100 * MS).is_err());
    }

    #[test]
    fn scheduling_with_a_stopped_timer_is_never_pending() {
        let timer = Timer::new().unwrap();
        let shared = Arc::clone(&timer.shared);
        drop(timer);
        let entry = Entry {
            shared: Arc::downgrade(&shared),
            id: shared.add(String::new(), None, Box::new(|| Next::Stop)).unwrap_or(u64::MAX),
            detached: false,
        };
        assert!(!entry.is_pending());
    }
}

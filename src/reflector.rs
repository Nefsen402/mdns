//! Reflects devices between segments, over every address family they serve.
//!
//! Every device discovered on a segment is announced on all the *other*
//! segments, and withdrawn again when it goes away. A segment that announces
//! the device of another does not keep a copy of it: it is given a handle to
//! the device, to read it as it is, and the reflector says when to look at it
//! again, as it changes, or to withdraw it. What the reflector knows is which
//! hostnames it could not reflect, to try again; a failed send is simply
//! retried, and no copy can outlive its source, as there is none to outlive.
//! Dropping the reflector withdraws everything.
//!
//! Every segment reflects to every other one in the same reflector; which
//! interfaces share a reflector is the caller's policy. A reflector with a
//! single segment only tracks and reflects nothing.

use core::cell::{RefCell, RefMut};
use alloc::rc::Rc;
use core::time::Duration;


use crate::time::Instant;

use anyhow::{bail, Result};

use crate::config::{glob, Advertise, Forward, ReflectedWhen};
use crate::device::Shared;
use crate::segment::{Asked, Event, Segment};

use crate::prelude::*;

/// How many notices are kept until taken.
const MAX_NOTICES: usize = 4096;

/// How long after a send failed it is tried again.
const RETRY: Duration = Duration::from_secs(5);

/// A change to a device discovered on one of a reflector's segments, as
/// [`Reflector::watch`] delivers it.
#[derive(Clone, Debug)]
pub struct Notice {
    /// The segment the device was discovered on.
    pub interface: String,
    pub event: Event,
    /// How much longer the daemon keeps the device if it is not heard from
    /// again, to the second; zero if it was removed.
    pub ttl: Duration,
}

pub struct Reflector {
    inner: Rc<Inner>,
}

struct Inner {
    /// The segments it spans, and whether each is untrusted: it is not
    /// announced anything. They come and go with their interfaces.
    members: RefCell<Vec<Member>>,
    /// The interfaces whose segments are untrusted, by name or pattern, whether
    /// they are here or not.
    untrusted: Vec<String>,
    forward: Forward,
    /// What of a device is reflected with it, made once for all the segments
    /// it is shown on.
    advertise: Rc<Advertise>,
    /// What a device has to have to be reflected.
    when: ReflectedWhen,
    /// The TTL the address records of what it reflects are announced with;
    /// `None` keeps each device's own.
    reflect_ttl: Option<Duration>,
    book: RefCell<Book>,
    /// What has happened, for watches, until taken.
    notices: RefCell<Vec<Notice>>,
}

#[derive(Clone)]
struct Member {
    segment: Segment,
    untrusted: bool,
}

#[derive(Default)]
struct Book {
    /// What could not be shown on, or withdrawn from, a segment, to be tried
    /// again.
    failed: Vec<Failed>,
    /// When to try again, as a send failed.
    retry: Option<Instant>,
}

/// One thing a segment could not be told: that a device of the segment of
/// `priority` is to be shown, or, if not `show`, withdrawn.
struct Failed {
    target: Segment,
    priority: u32,
    device: Shared,
    show: bool,
}

impl Reflector {
    /// Start reflecting between `segments`, which must be on different
    /// interfaces, and may be none yet: [`add`](Reflector::add) and
    /// [`remove`](Reflector::remove) say what comes and goes. Devices already
    /// discovered are reflected before this returns.
    ///
    /// Where reflectors share an interface and more than one wants a hostname
    /// announced there, the device of the segment with the lowest priority is
    /// (see [`Segment::priority`]), and the next takes over when it goes.
    pub fn new(segments: Vec<Segment>) -> Result<Reflector> {
        Self::with_untrusted(segments, &[])
    }

    /// Like [`new`](Reflector::new), but the segments on the interfaces named
    /// in `untrusted`, now or when added, are announced nothing: their devices are still
    /// announced to the others, but they do not learn about the devices of the
    /// others, so a network that is not to see the rest can still be seen
    /// from it.
    pub fn with_untrusted(segments: Vec<Segment>, untrusted: &[String]) -> Result<Reflector> {
        Self::with_options(segments, untrusted, Forward::default(), Advertise::default(), ReflectedWhen::default(), None)
    }

    /// Like [`with_untrusted`](Reflector::with_untrusted), putting the
    /// questions asked on each segment to the others as `forward` says,
    /// reflecting as much of a device as `advertise` says, reflecting the
    /// devices that have what `when` asks for, and announcing what it reflects with the address TTL
    /// `reflect_ttl`, if given, in place of each device's own.
    pub fn with_options(
        segments: Vec<Segment>,
        untrusted: &[String],
        forward: Forward,
        advertise: Advertise,
        when: ReflectedWhen,
        reflect_ttl: Option<Duration>,
    ) -> Result<Reflector> {
        for (i, seg) in segments.iter().enumerate() {
            if segments[..i].iter().any(|o| o.interface() == seg.interface()) {
                bail!("more than one segment for interface {}", seg.interface());
            }
        }

        let untrusted: Vec<String> = untrusted.to_vec();
        let members = segments
            .into_iter()
            .map(|segment| Member { untrusted: untrusted.iter().any(|name| glob(name, segment.interface())), segment })
            .collect();

        let inner = Rc::new(Inner {
            members: RefCell::new(members),
            untrusted,
            forward,
            advertise: Rc::new(advertise),
            when,
            reflect_ttl,
            book: RefCell::default(),
            notices: RefCell::default(),
        });

        // What is known already; what changes from now on is handed in by
        // the event loop ([`deliver`]). A device seen both ways is harmless:
        // reflecting is idempotent.
        for member in inner.snapshot() {
            for device in member.segment.shared_devices() {
                inner.relay(&member.segment, &device, false, None);
            }
        }

        #[cfg(test)]
        MADE.with(|made| made.borrow_mut().push(Rc::downgrade(&inner)));
        Ok(Reflector { inner })
    }
}

impl Reflector {
    /// The segments this reflector spans, in the order they came.
    pub fn segments(&self) -> Vec<Segment> {
        self.inner.snapshot().into_iter().map(|m| m.segment).collect()
    }

    /// The interfaces whose segments are announced nothing, of those it spans.
    pub fn untrusted(&self) -> Vec<String> {
        self.inner.snapshot().into_iter().filter(|m| m.untrusted).map(|m| m.segment.interface().to_string()).collect()
    }

    /// Span `segment` too, as its interface has come: what the others have is
    /// announced on it (unless it is untrusted), and what it finds is
    /// announced on them. It must not be on an interface already spanned.
    pub fn add(&self, segment: Segment) -> Result<()> {
        let untrusted = self.inner.untrusted.iter().any(|name| glob(name, segment.interface()));
        {
            let mut members = self.inner.members.borrow_mut();
            if members.iter().any(|m| m.segment.interface() == segment.interface()) {
                bail!("more than one segment for interface {}", segment.interface());
            }
            members.push(Member { segment, untrusted });
        }
        // What the others have is shown on it, and what it has on them.
        let new = self.inner.snapshot().pop().map(|m| m.segment);
        for member in self.inner.snapshot() {
            for device in member.segment.shared_devices() {
                self.inner.relay(&member.segment, &device, false, new.as_ref().filter(|n| !n.is(&member.segment)));
            }
        }
        Ok(())
    }

    /// Stop spanning the segment of `interface`, as it is gone: what this
    /// reflector announced on it is withdrawn, and so is what it announced
    /// elsewhere of what was found on it, which is each device the segment
    /// has, and each one that could not be withdrawn already. What the segment
    /// had found is to be forgotten and delivered ([`deliver`]) first, for the
    /// watches to be told.
    pub fn remove(&self, interface: &str) {
        let removed = {
            let mut members = self.inner.members.borrow_mut();
            let Some(at) = members.iter().position(|m| m.segment.interface() == interface) else { return };
            members.remove(at).segment
        };
        if let Err(e) = removed.withdraw_all(&self.inner.advertise) {
            eprintln!("{interface}: withdrawing what was reflected failed: {e:#}");
        }
        let priority = removed.priority();
        let mut book = self.inner.book();
        let mut devices = removed.shared_devices();
        devices.extend(book.failed.iter().filter(|f| f.priority == priority).map(|f| f.device.clone()));
        book.failed.retain(|f| f.target.interface() != interface && f.priority != priority);
        for member in self.inner.snapshot().iter().filter(|m| !m.untrusted) {
            for device in &devices {
                self.inner.attempt(&mut book, &member.segment, priority, device, false);
            }
        }
        if book.failed.is_empty() {
            book.retry = None;
        }
    }

    /// A [`Notice`] of every device that appeared, changed or went on the
    /// segments this reflector spans since last asked, oldest first. Only so
    /// many are kept for one who never asks.
    pub fn take_notices(&self) -> Vec<Notice> {
        core::mem::take(&mut *self.inner.notices.borrow_mut())
    }
}

impl Reflector {
    /// Act on `event`, a change on `segment`, if that is one this reflector
    /// spans.
    pub fn handle(&self, segment: &Segment, event: Event) {
        self.inner.handle(segment, event);
    }

    /// When it is to try again what it could not send, if anything.
    pub fn next_retry(&self) -> Option<Instant> {
        self.inner.book().retry
    }

    /// Try again what could not be sent, if that is due at `now`.
    pub fn retry(&self, now: Instant) {
        let mut book = self.inner.book();
        if book.retry.is_some_and(|at| at <= now) {
            self.inner.reconcile(&mut book);
        }
    }
}

/// Hand what has changed on each segment of `reflectors` to every one of
/// them that spans it, in the order it happened. A segment several
/// reflectors share is taken from once.
pub fn deliver(reflectors: &[&Reflector]) {
    deliver_to(&reflectors.iter().map(|r| &*r.inner).collect::<Vec<_>>());
}

fn deliver_to(inners: &[&Inner]) {
    let mut segments: Vec<Segment> = Vec::new();
    for seg in inners.iter().flat_map(|i| i.snapshot()).map(|m| m.segment) {
        if !segments.iter().any(|s| s.is(&seg)) {
            segments.push(seg);
        }
    }
    for seg in &segments {
        for event in seg.take_events() {
            log(seg.interface(), &event);
            for inner in inners {
                inner.handle(seg, event.clone());
            }
        }
    }
}

/// Log a change to the devices of `interface`, in a line: what happened, to
/// which device, and what it is known by. The questions passed on are not
/// worth a line each.
fn log(interface: &str, event: &Event) {
    let (what, device) = match event {
        Event::Added(d) => ("added", d),
        Event::Updated(d) => ("updated", d),
        Event::Removed(d) => ("removed", d),
        Event::Question(_) => return,
    };
    let device = device.borrow();
    let name = device.hostname.as_deref().unwrap_or("(no name)");
    let addrs: Vec<String> = device.addrs().map(|a| a.to_string()).collect();
    let addrs = if addrs.is_empty() { "no addresses".to_string() } else { addrs.join(", ") };
    let services = match device.services.len() {
        0 => String::new(),
        1 => ", 1 service".to_string(),
        n => format!(", {n} services"),
    };
    eprintln!("{interface}: {what} {name} ({addrs}{services})");
}

// The reflectors made on this thread, for tests to deliver to as the event
// loop would.
#[cfg(test)]
thread_local! {
    static MADE: RefCell<Vec<alloc::rc::Weak<Inner>>> = const { RefCell::new(Vec::new()) };
}

/// Deliver what has changed to the reflectors made on this thread that are
/// still there, as the event loop does after anything happens.
#[cfg(test)]
pub fn deliver_made() {
    let inners: Vec<Rc<Inner>> = MADE.with(|made| made.borrow().iter().filter_map(alloc::rc::Weak::upgrade).collect());
    deliver_to(&inners.iter().map(|i| &**i).collect::<Vec<_>>());
}

/// Have the reflectors made on this thread retry as if it were `now`.
#[cfg(test)]
pub fn retry_made(now: Instant) {
    let inners: Vec<Rc<Inner>> = MADE.with(|made| made.borrow().iter().filter_map(alloc::rc::Weak::upgrade).collect());
    for inner in inners {
        let mut book = inner.book();
        if book.retry.is_some_and(|at| at <= now) {
            inner.reconcile(&mut book);
        }
    }
}

impl Drop for Reflector {
    fn drop(&mut self) {
        // Nothing is wanted any more: what it announced is withdrawn.
        for seg in self.segments() {
            if let Err(e) = seg.withdraw_all(&self.inner.advertise) {
                eprintln!("{}: withdrawing what was reflected failed: {e:#}", seg.interface());
            }
        }
    }
}

impl Inner {
    fn book(&self) -> RefMut<'_, Book> {
        self.book.borrow_mut()
    }

    /// The segments it spans now, with whether each is untrusted.
    fn snapshot(&self) -> Vec<Member> {
        self.members.borrow().clone()
    }

    fn handle(&self, segment: &Segment, event: Event) {
        if let Some(src) = self.snapshot().iter().position(|m| m.segment.is(segment)) {
            self.apply(src, event);
        }
    }

    /// Note what happened for the watches, before the reflecting.
    fn notify(&self, src: usize, event: &Event) {
        let seg = self.snapshot().swap_remove(src).segment;
        let ttl = match event {
            Event::Removed(_) | Event::Question(_) => Duration::ZERO,
            Event::Added(device) | Event::Updated(device) => seg.lifetime_left(&device.borrow()),
        };
        let mut notices = self.notices.borrow_mut();
        if notices.len() >= MAX_NOTICES {
            notices.remove(0);
        }
        notices.push(Notice { interface: seg.interface().to_string(), event: event.clone(), ttl });
    }

    fn apply(&self, src: usize, event: Event) {
        if let Event::Question(questions) = &event {
            return self.forward(src, questions);
        }
        self.notify(src, &event);
        let from = self.snapshot().swap_remove(src).segment;
        match &event {
            Event::Added(device) | Event::Updated(device) => self.relay(&from, device, false, None),
            Event::Removed(device) => self.relay(&from, device, true, None),
            Event::Question(_) => {}
        }
    }

    /// Put the questions asked on `src`, those [`Forward`] lets through, to
    /// the other segments: those whose devices are announced on it, so whose
    /// answers will be. An untrusted segment is announced nothing, so its
    /// questions are put nowhere.
    fn forward(&self, src: usize, asked: &[Asked]) {
        let members = self.snapshot();
        if members[src].untrusted {
            return;
        }
        let questions: Vec<_> = asked
            .iter()
            .filter(|a| match self.forward {
                Forward::Always => true,
                Forward::Unknown => !a.answered,
                Forward::Never => false,
            })
            .map(|a| a.question.clone())
            .collect();
        if questions.is_empty() {
            return;
        }
        for (target, seg) in members.iter().map(|m| &m.segment).enumerate() {
            if target == src {
                continue;
            }
            if let Err(e) = seg.query_question(&questions) {
                eprintln!("{}: asking on behalf of {} failed: {e:#}", seg.interface(), members[src].segment.interface());
            }
        }
    }

    /// Show `device`, one of `from`, on the other segments, those that are
    /// announced anything, or only on `only`: as it is to be shown there
    /// ([`Device::reflectable`]), or withdraw it if it is not to be, or has
    /// gone (`gone`). It is the one device that every segment shows, which is
    /// as it is now; the segments are told when it changes, to look again.
    ///
    /// Failures are logged and kept, so that [`Inner::reconcile`] tries again.
    fn relay(&self, from: &Segment, device: &Shared, gone: bool, only: Option<&Segment>) {
        let show = !gone && self.reflectable(device);
        let priority = from.priority();
        let mut book = self.book();
        for member in self.snapshot() {
            let target = &member.segment;
            if member.untrusted || target.is(from) || only.is_some_and(|only| !target.is(only)) {
                continue;
            }
            self.attempt(&mut book, target, priority, device, show);
        }
    }

    /// Whether `device` is to be shown on other segments, as it is now.
    fn reflectable(&self, device: &Shared) -> bool {
        let device = device.borrow();
        device.hostname.is_some() && device.reflectable(&self.advertise, &self.when)
    }

    /// Show `device` on `target`, a device of the segment of `priority`, or
    /// withdraw it if not `show`, and keep it to try again if that fails.
    fn attempt(&self, book: &mut Book, target: &Segment, priority: u32, device: &Shared, show: bool) {
        book.failed.retain(|f| !(f.target.is(target) && f.device.is(device)));
        let result = if show {
            target.reflect(priority, device, &self.advertise, self.reflect_ttl).map(drop)
        } else {
            target.remove_reflected(&self.advertise, device).map(drop)
        };
        let failed = result.is_err();
        if let Err(e) = result {
            let host = device.borrow().hostname.clone().unwrap_or_default();
            eprintln!("{}: reflecting {host} failed: {e:#}", target.interface());
            book.failed.push(Failed { target: target.clone(), priority, device: device.clone(), show });
        }
        book.retry = match (book.failed.is_empty(), book.retry) {
            (true, _) => None,
            (false, Some(at)) if !failed => Some(at),
            (false, _) => Some(Instant::now() + RETRY),
        };
    }

    /// Try again everything that could not be shown or withdrawn.
    fn reconcile(&self, book: &mut Book) {
        for failed in core::mem::take(&mut book.failed) {
            let show = failed.show && self.reflectable(&failed.device);
            self.attempt(book, &failed.target, failed.priority, &failed.device, show);
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/reflector.rs"]
mod tests;

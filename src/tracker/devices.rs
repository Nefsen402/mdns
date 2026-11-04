//! The discovered devices of a segment, each held in one place, and how they
//! are found.
//!
//! A device is [kept](Table) and called by its [`Id`]; nothing about it tells
//! it apart from another. It is found by its hostname, or if it has none by
//! the address it was first heard from, and by the addresses it has, the
//! names it answers for, whether it has a service whose host is not known,
//! and when it next needs something done: when something of it runs out, and
//! when it is to be asked again. There is at most one device to a hostname:
//! those that look for one find it before they make one.
//!
//! The tables hold a hash or a time and an id, and confirm by looking into
//! the device, so they can be made again from the devices alone
//! ([`Devices::check`] does, and compares). A table follows a device when it
//! is told that it changed ([`Devices::reindex`]), given what the tables held
//! of it before ([`Indexed`]), or when it is changed by [`Devices::edit`],
//! and when it goes.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::net::IpAddr;
use core::ops::Bound;
use core::time::Duration;

use hashbrown::{DefaultHashBuilder, HashSet};

pub(crate) use crate::table::Id;
use crate::table::{hash_addr, hash_name, Multi, Table};
use super::Entry;
use crate::time::Instant;

/// What the tables hold of a device: the hashes of its addresses and of the
/// names it answers for, each once, in order, and the times it is held under.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub(crate) struct Indexed {
    addrs: Vec<u64>,
    names: Vec<u64>,
    soonest: Option<Instant>,
    refresh_at: Option<Instant>,
}

#[derive(Default)]
pub(crate) struct Devices {
    table: Table<Entry>,
    /// Each address a device has, and the device, by the hash of the address.
    by_addr: Multi,
    /// Each name a device answers for, and the device, by the hash of the name:
    /// its hostname among them.
    by_name: Multi,
    /// Every device, by the hash of the address that first described it: what
    /// finds one with no hostname, and what a sender may describe only so
    /// many of.
    by_from: Multi,
    /// The devices with a service whose host is not known yet (a bare browse
    /// answer): the ones to look at when it is, rather than all of them.
    unresolved: HashSet<Id>,
    /// The devices by the soonest that they, or one of their addresses, runs
    /// out.
    by_soonest: BTreeSet<(Instant, Id)>,
    /// The devices by when they are due to be asked to answer again, if
    /// [`Devices::refresh`] says they are.
    by_refresh: BTreeSet<(Instant, Id)>,
    /// How long before one would run out they are asked to answer again; none
    /// if they are not.
    refresh: Option<Duration>,
    hasher: DefaultHashBuilder,
}

impl Devices {
    pub fn len(&self) -> usize {
        self.table.len()
    }

    pub fn try_get(&self, id: Id) -> Option<&Entry> {
        self.table.try_get(id)
    }

    pub fn get(&self, id: Id) -> &Entry {
        self.table.get(id)
    }

    /// The device, to be changed but not in when it runs out or is asked
    /// again, nor in what it has, unless its changes are then
    /// [indexed](Devices::reindex).
    pub fn get_mut(&mut self, id: Id) -> &mut Entry {
        self.table.get_mut(id)
    }

    /// Change the device with `f`, and have the tables follow. Nothing if it
    /// is gone.
    pub fn edit<R>(&mut self, id: Id, f: impl FnOnce(&mut Entry) -> R) -> Option<R> {
        let was = self.indexed(self.table.try_get(id)?);
        let out = f(self.table.get_mut(id));
        self.reindex_id(id, &was);
        Some(out)
    }

    /// The device with the hostname `host`, ignoring case.
    pub fn find_host(&self, host: &str) -> Option<Id> {
        let hash = hash_name(&self.hasher, host);
        let named = |id: &Id| self.table.get(*id).device.hostname.as_deref().is_some_and(|own| own.eq_ignore_ascii_case(host));
        self.by_name.under(hash).find(named)
    }

    pub fn contains_host(&self, host: &str) -> bool {
        self.find_host(host).is_some()
    }

    /// The device with no hostname that was first heard from `from`.
    pub fn find_nameless(&self, from: &IpAddr) -> Option<Id> {
        let hash = hash_addr(&self.hasher, from);
        let first = |id: &Id| {
            let entry = self.table.get(*id);
            entry.device.hostname.is_none() && entry.from == *from
        };
        self.by_from.under(hash).find(first)
    }

    /// Keep a device that is not here yet, and no other with its hostname if
    /// it has one. It is found by its hostname at once, and by the rest of
    /// what the tables hold when it is [indexed](Devices::reindex), with
    /// nothing for what they held.
    pub fn create(&mut self, entry: Entry) -> Id {
        debug_assert!(entry.device.hostname.as_deref().is_none_or(|host| !self.contains_host(host)), "a hostname is had once");
        let from = hash_addr(&self.hasher, &entry.from);
        let host = entry.device.hostname.as_deref().map(|host| hash_name(&self.hasher, host));
        let id = self.table.insert(entry);
        self.by_from.add(from, id);
        if let Some(host) = host {
            self.by_name.add(host, id);
        }
        id
    }

    pub fn remove(&mut self, id: Id) -> Option<Entry> {
        // From the other tables, by what it was given to them as: what the
        // tables hold is what it was when it was last indexed, the device
        // as it is now, unless it was changed and not reindexed.
        let held = self.indexed(self.table.try_get(id)?);
        let entry = self.table.remove(id);
        self.by_addr.move_between(id, &held.addrs, &[]);
        self.by_name.move_between(id, &held.names, &[]);
        self.by_from.remove(hash_addr(&self.hasher, &entry.from), id);
        self.unresolved.remove(&id);
        self.by_soonest.remove(&(entry.soonest(), id));
        if let Some(at) = held.refresh_at {
            self.by_refresh.remove(&(at, id));
        }
        Some(entry)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Entry> {
        self.table.iter()
    }

    pub fn ids(&self) -> impl Iterator<Item = Id> + '_ {
        self.table.ids()
    }

    /// When `entry` is next due to be asked to answer again, if it is: before
    /// the soonest it or one of its addresses runs out, and not again until
    /// the gap has passed since it was last asked. Not if it is to be
    /// dropped by then, nor if there is nothing to ask it.
    fn refresh_at(&self, entry: &Entry) -> Option<Instant> {
        entry.refresh_due(self.refresh?)
    }

    /// What the tables would hold of `entry`.
    pub fn indexed(&self, entry: &Entry) -> Indexed {
        let mut addrs: Vec<u64> = entry.device.addrs().map(|addr| hash_addr(&self.hasher, &addr)).collect();
        let mut names = Vec::new();
        entry.device.for_each_name(|name| names.push(hash_name(&self.hasher, name)));
        for hashes in [&mut addrs, &mut names] {
            hashes.sort_unstable();
            hashes.dedup();
        }
        Indexed { addrs, names, soonest: Some(entry.soonest()), refresh_at: self.refresh_at(entry) }
    }

    /// What the tables hold of the device, as of now; nothing if it is gone.
    pub fn indexed_of(&self, id: Id) -> Indexed {
        self.table.try_get(id).map(|entry| self.indexed(entry)).unwrap_or_default()
    }

    /// The device was changed from what the tables held of it, `was`: have
    /// them follow. Returns what they hold now, which is what to give the
    /// next time. Nothing if it is gone: they were told when it went.
    pub fn reindex(&mut self, id: Id, was: &Indexed) -> Indexed {
        if self.table.has(id) { self.reindex_id(id, was) } else { Indexed::default() }
    }

    fn reindex_id(&mut self, id: Id, was: &Indexed) -> Indexed {
        let entry = self.table.get(id);
        let now = self.indexed(entry);
        self.by_addr.move_between(id, &was.addrs, &now.addrs);
        self.by_name.move_between(id, &was.names, &now.names);
        if entry.device.services.iter().any(|s| s.target.is_none()) {
            self.unresolved.insert(id);
        } else {
            self.unresolved.remove(&id);
        }
        for (table, was, now) in [
            (&mut self.by_soonest, was.soonest, now.soonest),
            (&mut self.by_refresh, was.refresh_at, now.refresh_at),
        ] {
            if was != now {
                if let Some(at) = was {
                    table.remove(&(at, id));
                }
                if let Some(at) = now {
                    table.insert((at, id));
                }
            }
        }
        now
    }

    /// Set how long before they run out devices are asked to answer again, or
    /// that they are not. It is what [`Devices::refresh_at`] goes by, so the
    /// times they are held under are made again.
    pub fn set_refresh(&mut self, before: Option<Duration>) {
        if self.refresh == before {
            return;
        }
        self.refresh = before;
        self.by_refresh.clear();
        for id in self.table.ids().collect::<Vec<_>>() {
            if let Some(at) = self.refresh_at(self.table.get(id)) {
                self.by_refresh.insert((at, id));
            }
        }
    }

    /// The devices that have `addr`.
    pub fn ids_with_addr<'a>(&'a self, addr: &'a IpAddr) -> impl Iterator<Item = Id> + 'a {
        let hash = hash_addr(&self.hasher, addr);
        self.by_addr.under(hash).filter(move |&id| self.table.get(id).device.has_addr(addr))
    }

    /// The device that has `addr` and was heard of last, if any does.
    pub fn holder_of(&self, addr: &IpAddr) -> Option<Id> {
        self.ids_with_addr(addr).max_by_key(|&id| (self.table.get(id).expires, id))
    }

    /// The devices that answer for `name`, ignoring case.
    pub fn with_name<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Entry> + 'a {
        let hash = hash_name(&self.hasher, name);
        self.by_name.under(hash).map(|id| self.table.get(id)).filter(move |entry| entry.device.has_name(name))
    }

    /// The devices with a service whose host is not known yet.
    pub fn with_unresolved(&self) -> impl Iterator<Item = (Id, &Entry)> {
        self.unresolved.iter().map(|&id| (id, self.table.get(id)))
    }

    /// How many devices with a hostname `sender` first described.
    pub fn described_by(&self, sender: &IpAddr) -> usize {
        let hash = hash_addr(&self.hasher, sender);
        let first = |id: &Id| {
            let entry = self.table.get(*id);
            entry.from == *sender && entry.device.hostname.is_some()
        };
        self.by_from.under(hash).filter(first).count()
    }

    /// The soonest anything of a device is due: when something of one runs
    /// out, or one is to be asked again. Never if none is.
    pub fn next_due(&self) -> Option<Instant> {
        let soonest = self.by_soonest.first().map(|&(at, _)| at);
        let refresh = self.by_refresh.first().map(|&(at, _)| at);
        soonest.into_iter().chain(refresh).min()
    }

    /// The devices of which something has run out as of `now`.
    pub fn running_out(&self, now: Instant) -> Vec<Id> {
        self.by_soonest.range(..=(now, Id::LAST)).map(|&(_, id)| id).collect()
    }

    /// The devices that run out after `now`, and no later than `before`
    /// after it: those to ask to answer again.
    pub fn about_to_run_out(&self, now: Instant, before: Duration) -> Vec<Id> {
        let to = now.checked_add(before).map_or(Bound::Unbounded, |limit| Bound::Included((limit, Id::LAST)));
        self.by_soonest.range((Bound::Excluded((now, Id::LAST)), to)).map(|&(_, id)| id).collect()
    }

    /// Whether the tables hold what the devices have, and nothing else: for
    /// tests, which change things without the segment's own care.
    #[cfg(test)]
    pub fn check(&self) {
        self.table.check();
        let (mut addrs, mut names, mut unresolved, mut froms, mut refreshed) = (0, 0, 0, 0, 0);
        for id in self.table.ids() {
            let entry = self.table.get(id);
            let indexed = self.indexed(entry);
            addrs += indexed.addrs.len();
            names += indexed.names.len();
            assert!(indexed.addrs.iter().all(|&h| self.by_addr.holds(h, id)), "an address is indexed: {entry:?}");
            assert!(indexed.names.iter().all(|&h| self.by_name.holds(h, id)), "a name is indexed: {entry:?}");
            let unresolved_here = entry.device.services.iter().any(|s| s.target.is_none());
            assert_eq!(self.unresolved.contains(&id), unresolved_here, "unresolved: {entry:?}");
            unresolved += usize::from(unresolved_here);
            for addr in entry.device.addrs() {
                assert!(self.ids_with_addr(&addr).any(|found| found == id), "{addr} finds it");
            }
            froms += 1;
            assert!(self.by_from.holds(hash_addr(&self.hasher, &entry.from), id), "by where from: {entry:?}");
            match entry.device.hostname.as_deref() {
                Some(host) => assert_eq!(self.find_host(host), Some(id), "a hostname is had once: {entry:?}"),
                None => assert_eq!(self.find_nameless(&entry.from), Some(id), "one with no hostname per address: {entry:?}"),
            }
            assert!(self.by_soonest.contains(&(entry.soonest(), id)), "by when it runs out: {entry:?}");
            if let Some(at) = self.refresh_at(entry) {
                refreshed += 1;
                assert!(self.by_refresh.contains(&(at, id)), "by when it is asked again: {entry:?}");
            }
        }
        assert_eq!((self.by_addr.pairs, self.by_name.pairs, self.unresolved.len()), (addrs, names, unresolved));
        assert_eq!((self.by_from.pairs, self.by_soonest.len(), self.by_refresh.len()), (froms, self.len(), refreshed));
    }

    /// How many (address, device) pairs the tables hold.
    #[cfg(test)]
    pub fn addrs_held(&self) -> usize {
        self.by_addr.pairs
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::string::String;
    use std::collections::HashMap;

    use super::*;
    use crate::device::Service;
    use crate::time::Instant;

    fn named(host: &str, from: &str) -> Entry {
        Entry::new(Instant::now(), from.parse().unwrap(), Some(host))
    }

    #[test]
    fn a_device_is_found_by_its_hostname_whatever_the_case_and_by_address_until_it_has_one() {
        let mut devices = Devices::default();
        let tv = devices.create(named("TV.local", "10.0.0.1"));
        devices.reindex(tv, &Indexed::default());
        let from: IpAddr = "10.0.0.9".parse().unwrap();
        let bare = devices.create(Entry::new(Instant::now(), from, None));
        devices.reindex(bare, &Indexed::default());
        devices.check();

        assert_eq!(devices.len(), 2);
        assert_eq!((devices.find_host("tv.LOCAL"), devices.find_nameless(&from)), (Some(tv), Some(bare)));
        assert_eq!(devices.get(tv).device.hostname.as_deref(), Some("TV.local"), "spelt as it was announced");
        assert!(!devices.contains_host("other.local"));
        assert_eq!(devices.find_nameless(&"10.0.0.8".parse().unwrap()), None);
        assert_eq!(devices.find_nameless(&"10.0.0.1".parse().unwrap()), None, "it has a name");
        assert_eq!(devices.described_by(&"10.0.0.1".parse().unwrap()), 1);
        assert_eq!(devices.described_by(&from), 0, "it has none");

        // Given a hostname, it is found by it, and no longer by where from.
        let was = devices.indexed_of(bare);
        devices.edit(bare, |entry| entry.device.hostname = Some("Bare.local".into()));
        devices.reindex(bare, &was);
        assert_eq!((devices.find_host("bare.local"), devices.find_nameless(&from)), (Some(bare), None));
        devices.check();

        assert!(devices.remove(tv).is_some() && devices.remove(tv).is_none());
        assert_eq!((devices.len(), devices.iter().count(), devices.find_host("tv.local")), (1, 1, None));
        // The slot is another device's now, which the old id does not find.
        let other = devices.create(named("other.local", "10.0.0.2"));
        assert_ne!(tv, other);
        assert!(devices.try_get(tv).is_none());
        devices.reindex(other, &Indexed::default());
        devices.check();
    }

    /// Whatever is put in and taken out, in any order, and changed in what it
    /// has, with the slots of those taken out used again, the tables find what
    /// a scan of the devices does.
    #[test]
    fn the_tables_find_what_a_scan_of_the_devices_does_through_any_mix_of_changes() {
        let mut devices = Devices::default();
        devices.set_refresh(Some(Duration::from_secs(30)));
        let mut model: HashMap<String, Id> = HashMap::new();
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        // Not the clock's now: on a machine that has only just started the clock
        // is no later than the refresh time, and the time to ask again is its start.
        let start = Instant::START + Duration::from_secs(30);
        for step in 0..20_000u64 {
            let (n, pick) = (next() % 300, next());
            // A name of mixed case, as announced, spelt differently each time.
            let spelt = |step: u64| -> String {
                format!("Host{n}.local").chars().enumerate().map(|(i, c)| if (i as u64 + step) % 3 == 0 { c.to_ascii_uppercase() } else { c.to_ascii_lowercase() }).collect()
            };
            let key = format!("host{n}.local");
            match pick % 4 {
                0 | 1 => {
                    let id = match devices.find_host(&spelt(step)) {
                        Some(id) => id,
                        None => {
                            let id = devices.create(Entry::new(start, format!("10.9.{}.{}", n % 7, n % 5).parse().unwrap(), Some(&spelt(step))));
                            devices.reindex(id, &Indexed::default());
                            id
                        }
                    };
                    assert_eq!(*model.entry(key).or_insert(id), id, "found as it was made");
                    let was = devices.indexed_of(id);
                    devices.edit(id, |entry| {
                        entry.expires = start + Duration::from_secs(pick >> 8 & 255);
                        // What it has changes: an address more or fewer, a service more
                        // (its host known or not) or fewer, asked again or not.
                        let addr: IpAddr = format!("10.5.{}.{}", pick >> 16 & 7, pick >> 24 & 7).parse().unwrap();
                        match pick >> 32 & 7 {
                            0 | 1 => entry.device.add_addrs(&[addr]),
                            2 => entry.device.addresses.retain(|a| a.ip != addr),
                            3 | 4 => {
                                let instance = format!("S{}._x{}._tcp.local", pick >> 40 & 3, pick >> 44 & 1);
                                let kind = format!("_x{}._tcp.local", pick >> 44 & 1);
                                let target = (pick >> 48 & 1 == 0).then(|| "somewhere.local".to_string());
                                if !entry.device.services.iter().any(|s| s.instance == instance) {
                                    entry.device.services.push(Service { instance, kind, target, ..Default::default() });
                                }
                            }
                            5 => entry.device.services.clear(),
                            6 => entry.refreshed = Some(start + Duration::from_secs(pick >> 8 & 63)),
                            _ => entry.device.services.retain(|s| s.target.is_none()),
                        }
                    });
                    devices.reindex(id, &was);
                }
                _ => {
                    let gone = devices.find_host(&key).map(|id| devices.remove(id).is_some());
                    assert_eq!(gone, model.remove(&key).map(|_| true));
                }
            }
            assert_eq!(devices.len(), model.len());
            if step % 500 == 0 {
                devices.check();
            }
        }
        devices.check();

        // The tables find what a scan of the devices does.
        let same = |found: Vec<*const Entry>, scan: Vec<*const Entry>| {
            let (mut found, mut scan) = (found, scan);
            (found.sort(), scan.sort());
            assert_eq!(found, scan);
        };
        let ptrs = |entries: Vec<&Entry>| entries.into_iter().map(|e| e as *const Entry).collect::<Vec<_>>();
        for a in 0..8 {
            for b in 0..8 {
                let addr: IpAddr = format!("10.5.{a}.{b}").parse().unwrap();
                let found = devices.ids_with_addr(&addr).map(|id| devices.get(id)).collect();
                same(ptrs(found), ptrs(devices.iter().filter(|e| e.device.has_addr(&addr)).collect()));
            }
        }
        for name in ["_x0._tcp.local", "_X1._tcp.LOCAL", "S1._x0._tcp.local", "host7.local", "HOST12.local", "_services._dns-sd._udp.local", "none"] {
            same(ptrs(devices.with_name(name).collect()), ptrs(devices.iter().filter(|e| e.device.has_name(name)).collect()));
        }
        same(
            ptrs(devices.with_unresolved().map(|(_, e)| e).collect()),
            ptrs(devices.iter().filter(|e| e.device.services.iter().any(|s| s.target.is_none())).collect()),
        );
        assert!(devices.with_name("_services._dns-sd._udp.local").count() > 0, "the test finds some");
        assert!(devices.with_unresolved().count() > 0 && devices.ids_with_addr(&"10.5.1.1".parse().unwrap()).count() > 0);
        assert_eq!(devices.iter().count(), model.len());

        // And the times: what runs out first, and what is due to be asked again.
        let soonest = devices.iter().map(|e| e.soonest());
        let asked_again = devices.iter().filter_map(|e| devices.indexed(e).refresh_at);
        assert_eq!(devices.next_due(), soonest.chain(asked_again).min());
        let running: Vec<Id> = devices.running_out(start + Duration::from_secs(100));
        assert_eq!(running.len(), devices.iter().filter(|e| e.soonest() <= start + Duration::from_secs(100)).count());
        let before = Duration::from_secs(50);
        let about = devices.about_to_run_out(start + Duration::from_secs(100), before);
        let scan = devices.iter().filter(|e| e.soonest() > start + Duration::from_secs(100) && e.soonest() <= start + Duration::from_secs(150)).count();
        assert_eq!(about.len(), scan);
        assert!(devices.next_due().is_some());
    }
}

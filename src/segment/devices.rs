//! The discovered devices of a segment, each held in one place, and how they
//! are found.
//!
//! A device lives in a slot of a list and is called by the slot's number, an
//! [`Id`]. The tables that find a device quickly hold nothing but ids: they
//! are given the hash of what is looked for, and tell the ids they hold apart
//! by looking into the device itself. So nothing is kept twice, and a table
//! can be made again from the devices alone.
//!
//! What a device is told apart by, its identity, is its hostname (without
//! regard to case) or, until it has one, the address it was first heard from.
//! It must not change while the device is here.
//!
//! Devices are found by other things too: the addresses they have, the names
//! they answer for, and whether they have a service whose host is not known.
//! The tables for those hold a hash and an id, and confirm by looking into
//! the device, as the one for identity does, so they too can be made again
//! from the devices alone ([`Devices::check`] does, and compares). A table
//! follows a device when it is told that it changed ([`Devices::reindex`]),
//! given what the tables held of it before ([`Indexed`]), and when it goes.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::hash::{BuildHasher, Hash, Hasher};
use core::net::IpAddr;
use core::ops::Index;

use hashbrown::{hash_map::Entry as Slot2, DefaultHashBuilder, HashMap, HashSet, HashTable};

use super::{Entry, Key};
use crate::device::Device;

/// Where a device is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Id(u32);

/// What the tables hold of a device: the hashes of its addresses and of the
/// names it answers for, each once, in order.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub(super) struct Indexed {
    addrs: Vec<u64>,
    names: Vec<u64>,
}

enum Slot {
    Taken(Entry),
    /// Empty, and the next empty one.
    Free(Option<u32>),
}

/// What tells a device apart, as lent by the device or by a [`Key`].
enum Ident<'a> {
    Host(&'a str),
    Source(IpAddr),
}

impl Ident<'_> {
    fn same(&self, other: &Ident<'_>) -> bool {
        match (self, other) {
            (Ident::Host(a), Ident::Host(b)) => a.eq_ignore_ascii_case(b),
            (Ident::Source(a), Ident::Source(b)) => a == b,
            _ => false,
        }
    }
}

impl Entry {
    fn ident(&self) -> Ident<'_> {
        match &self.device.hostname {
            Some(host) => Ident::Host(host),
            None => Ident::Source(self.from),
        }
    }
}

impl Key {
    fn ident(&self) -> Ident<'_> {
        match self {
            Key::Host(host) => Ident::Host(host),
            Key::Source(addr) => Ident::Source(*addr),
        }
    }
}

/// The hash of `ident`: a name hashes as it does in lowercase, whatever its
/// case, and without being copied whole.
fn hash_of(hasher: &DefaultHashBuilder, ident: &Ident<'_>) -> u64 {
    let mut h = hasher.build_hasher();
    match ident {
        Ident::Host(name) => hash_name(&mut h, name),
        Ident::Source(addr) => {
            h.write_u8(1);
            addr.hash(&mut h);
        }
    }
    h.finish()
}

/// Feed `name` to `h` as it is in lowercase, and not copied whole.
fn hash_name(h: &mut impl Hasher, name: &str) {
    let mut lower = [0u8; 64];
    for chunk in name.as_bytes().chunks(lower.len()) {
        let part = &mut lower[..chunk.len()];
        part.copy_from_slice(chunk);
        part.make_ascii_lowercase();
        h.write(part);
    }
    h.write_u8(0);
}

fn hash_of_name(hasher: &DefaultHashBuilder, name: &str) -> u64 {
    let mut h = hasher.build_hasher();
    hash_name(&mut h, name);
    h.finish()
}

fn hash_of_addr(hasher: &DefaultHashBuilder, addr: &IpAddr) -> u64 {
    hasher.hash_one(addr)
}

/// The devices under one hash: usually one, but a name that many devices
/// answer for (a service type, the type enumeration) has them all under one,
/// and a device is taken from among them without looking at the others.
enum Holders {
    One(Id),
    Many(Box<HashSet<Id>>),
}

/// Devices by hash, each under every hash it has, as many as have it.
#[derive(Default)]
struct Multi {
    by_hash: HashMap<u64, Holders>,
    /// How many (hash, device) pairs it holds.
    pairs: usize,
}

impl Multi {
    fn add(&mut self, hash: u64, id: Id) {
        match self.by_hash.entry(hash) {
            Slot2::Vacant(vacant) => {
                vacant.insert(Holders::One(id));
            }
            Slot2::Occupied(mut occupied) => match occupied.get_mut() {
                Holders::One(first) if *first == id => return,
                Holders::One(first) => {
                    let both = HashSet::from_iter([*first, id]);
                    *occupied.get_mut() = Holders::Many(Box::new(both));
                }
                Holders::Many(set) => {
                    if !set.insert(id) {
                        return;
                    }
                }
            },
        }
        self.pairs += 1;
    }

    fn remove(&mut self, hash: u64, id: Id) {
        let Slot2::Occupied(mut occupied) = self.by_hash.entry(hash) else { return };
        match occupied.get_mut() {
            Holders::One(only) if *only == id => {
                occupied.remove();
            }
            Holders::One(_) => return,
            Holders::Many(set) => {
                if !set.remove(&id) {
                    return;
                }
                if let Some(&last) = set.iter().next().filter(|_| set.len() == 1) {
                    *occupied.get_mut() = Holders::One(last);
                }
            }
        }
        self.pairs -= 1;
    }

    /// The devices under `hash`: those that have what hashes to it, and any
    /// that has something else that does.
    fn under(&self, hash: u64) -> impl Iterator<Item = Id> + '_ {
        let (one, many) = match self.by_hash.get(&hash) {
            None => (None, None),
            Some(Holders::One(id)) => (Some(*id), None),
            Some(Holders::Many(set)) => (None, Some(set.iter().copied())),
        };
        one.into_iter().chain(many.into_iter().flatten())
    }

    #[cfg(test)]
    fn holds(&self, hash: u64, id: Id) -> bool {
        self.under(hash).any(|held| held == id)
    }

    /// Put `id` under each hash in `new` that is not in `was`, and take it
    /// from under each in `was` that is not in `new`. Both are in order.
    fn move_between(&mut self, id: Id, was: &[u64], new: &[u64]) {
        for &hash in was.iter().filter(|h| new.binary_search(h).is_err()) {
            self.remove(hash, id);
        }
        for &hash in new.iter().filter(|h| was.binary_search(h).is_err()) {
            self.add(hash, id);
        }
    }
}

fn entry_at(slots: &[Slot], id: Id) -> &Entry {
    match &slots[id.0 as usize] {
        Slot::Taken(entry) => entry,
        Slot::Free(_) => unreachable!("a table holds an id whose device is gone"),
    }
}

#[derive(Default)]
pub(super) struct Devices {
    slots: Vec<Slot>,
    /// The first empty slot.
    free: Option<u32>,
    len: usize,
    /// The devices by identity: ids only, found by what the devices say.
    by_ident: HashTable<Id>,
    /// Each address a device has, and the device, by the hash of the address.
    by_addr: Multi,
    /// Each name a device answers for, and the device, by the hash of the name.
    by_name: Multi,
    /// The devices with a service whose host is not known yet (a bare browse
    /// answer): the ones to look at when it is, rather than all of them.
    unresolved: HashSet<Id>,
    hasher: DefaultHashBuilder,
}

impl Devices {
    pub fn len(&self) -> usize {
        self.len
    }

    fn find(&self, key: &Key) -> Option<Id> {
        let want = key.ident();
        let hash = hash_of(&self.hasher, &want);
        self.by_ident.find(hash, |&id| entry_at(&self.slots, id).ident().same(&want)).copied()
    }

    pub fn contains_key(&self, key: &Key) -> bool {
        self.find(key).is_some()
    }

    pub fn get(&self, key: &Key) -> Option<&Entry> {
        self.find(key).map(|id| entry_at(&self.slots, id))
    }

    /// The device, to be changed but not in what tells it apart.
    pub fn get_mut(&mut self, key: &Key) -> Option<&mut Entry> {
        let id = self.find(key)?;
        match &mut self.slots[id.0 as usize] {
            Slot::Taken(entry) => Some(entry),
            Slot::Free(_) => unreachable!("found a device that is gone"),
        }
    }

    /// The device for `key`, made by `make` and kept if it is not here. It
    /// must be told apart as `key` says.
    pub fn get_or_insert_with(&mut self, key: &Key, make: impl FnOnce() -> Entry) -> &mut Entry {
        let id = match self.find(key) {
            Some(id) => id,
            None => {
                let entry = make();
                debug_assert!(entry.ident().same(&key.ident()), "a device is made as it is looked up");
                self.insert(entry)
            }
        };
        match &mut self.slots[id.0 as usize] {
            Slot::Taken(entry) => entry,
            Slot::Free(_) => unreachable!("an id that was just found or made"),
        }
    }

    /// Keep a device that is not here yet.
    fn insert(&mut self, entry: Entry) -> Id {
        let hash = hash_of(&self.hasher, &entry.ident());
        let id = match self.free {
            Some(at) => {
                let Slot::Free(next) = self.slots[at as usize] else { unreachable!("the list of empty slots") };
                self.free = next;
                self.slots[at as usize] = Slot::Taken(entry);
                Id(at)
            }
            None => {
                self.slots.push(Slot::Taken(entry));
                Id(u32::try_from(self.slots.len() - 1).expect("fewer than 2^32 devices"))
            }
        };
        let (slots, hasher) = (&self.slots, &self.hasher);
        self.by_ident.insert_unique(hash, id, |&id| hash_of(hasher, &entry_at(slots, id).ident()));
        self.len += 1;
        id
    }

    pub fn remove(&mut self, key: &Key) -> Option<Entry> {
        let want = key.ident();
        let hash = hash_of(&self.hasher, &want);
        let slots = &self.slots;
        let found = self.by_ident.find_entry(hash, |&id| entry_at(slots, id).ident().same(&want)).ok()?;
        let (id, _) = found.remove();
        let Slot::Taken(entry) = core::mem::replace(&mut self.slots[id.0 as usize], Slot::Free(self.free)) else {
            unreachable!("removed a device that is gone")
        };
        // From the other tables, by what it was given to them as: what the
        // tables hold is what it was when it was last indexed, the device
        // as it is now, unless it was changed and not reindexed.
        let held = self.indexed(&entry.device);
        self.by_addr.move_between(id, &held.addrs, &[]);
        self.by_name.move_between(id, &held.names, &[]);
        self.unresolved.remove(&id);
        self.free = Some(id.0);
        self.len -= 1;
        Some(entry)
    }

    /// What the tables would hold of `device`.
    pub fn indexed(&self, device: &Device) -> Indexed {
        let mut addrs: Vec<u64> = device.addrs().map(|addr| hash_of_addr(&self.hasher, &addr)).collect();
        let mut names = Vec::new();
        device.for_each_name(|name| names.push(hash_of_name(&self.hasher, name)));
        for hashes in [&mut addrs, &mut names] {
            hashes.sort_unstable();
            hashes.dedup();
        }
        Indexed { addrs, names }
    }

    /// What the tables hold of the device for `key`, as of now, if it is here.
    pub fn indexed_of(&self, key: &Key) -> Option<Indexed> {
        self.get(key).map(|entry| self.indexed(&entry.device))
    }

    /// The device for `key` was changed from what the tables held of it,
    /// `was`: have them follow. Returns what they hold now, which is what to
    /// give the next time. Nothing if it is not here: they were told when it
    /// went.
    pub fn reindex(&mut self, key: &Key, was: &Indexed) -> Indexed {
        let Some(id) = self.find(key) else { return Indexed::default() };
        let device = &entry_at(&self.slots, id).device;
        let now = self.indexed(device);
        self.by_addr.move_between(id, &was.addrs, &now.addrs);
        self.by_name.move_between(id, &was.names, &now.names);
        if device.services.iter().any(|s| s.target.is_none()) {
            self.unresolved.insert(id);
        } else {
            self.unresolved.remove(&id);
        }
        now
    }

    /// The devices that have `addr`.
    pub fn with_addr<'a>(&'a self, addr: &'a IpAddr) -> impl Iterator<Item = &'a Entry> + 'a {
        let hash = hash_of_addr(&self.hasher, addr);
        self.by_addr
            .under(hash)
            .map(|id| entry_at(&self.slots, id))
            .filter(move |entry| entry.device.has_addr(addr))
    }

    /// The device that has `addr` and was heard of last, if any does.
    pub fn holder_of<'a>(&'a self, addr: &'a IpAddr) -> Option<&'a Entry> {
        self.with_addr(addr).max_by_key(|entry| entry.expires)
    }

    /// The devices that answer for `name`, ignoring case.
    pub fn with_name<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Entry> + 'a {
        let hash = hash_of_name(&self.hasher, name);
        self.by_name
            .under(hash)
            .map(|id| entry_at(&self.slots, id))
            .filter(move |entry| entry.device.has_name(name))
    }

    /// The devices with a service whose host is not known yet.
    pub fn with_unresolved(&self) -> impl Iterator<Item = &Entry> {
        self.unresolved.iter().map(|&id| entry_at(&self.slots, id))
    }

    pub fn iter(&self) -> impl Iterator<Item = &Entry> {
        self.slots.iter().filter_map(|slot| match slot {
            Slot::Taken(entry) => Some(entry),
            Slot::Free(_) => None,
        })
    }

    /// The devices, to be changed but not in what tells them apart.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Entry> {
        self.slots.iter_mut().filter_map(|slot| match slot {
            Slot::Taken(entry) => Some(entry),
            Slot::Free(_) => None,
        })
    }

    /// Whether the tables find each device by what it says, and only the
    /// devices that are here: for tests, which change things without the
    /// segment's own care.
    #[cfg(test)]
    pub fn check(&self) {
        let taken = self.slots.iter().filter(|s| matches!(s, Slot::Taken(_))).count();
        assert_eq!((self.len, self.by_ident.len()), (taken, taken));
        for entry in self.iter() {
            let found = self.get(&entry.key());
            assert!(found.is_some_and(|f| core::ptr::eq(f, entry)), "a device is found by what it says");
        }
        let mut free = self.free;
        let mut empty = 0;
        while let Some(at) = free {
            let Slot::Free(next) = self.slots[at as usize] else { panic!("a taken slot is listed as empty") };
            (free, empty) = (next, empty + 1);
        }
        assert_eq!(empty, self.slots.len() - taken);

        // What the other tables hold is what the devices have.
        let (mut addrs, mut names) = (0, 0);
        let mut unresolved = 0;
        for entry in self.iter() {
            let id = self.find(&entry.key()).expect("found above");
            let indexed = self.indexed(&entry.device);
            addrs += indexed.addrs.len();
            names += indexed.names.len();
            assert!(indexed.addrs.iter().all(|&h| self.by_addr.holds(h, id)), "an address is indexed: {entry:?}");
            assert!(indexed.names.iter().all(|&h| self.by_name.holds(h, id)), "a name is indexed: {entry:?}");
            let unresolved_here = entry.device.services.iter().any(|s| s.target.is_none());
            assert_eq!(self.unresolved.contains(&id), unresolved_here, "unresolved: {entry:?}");
            unresolved += usize::from(unresolved_here);
            for addr in entry.device.addrs() {
                assert!(self.with_addr(&addr).any(|e| core::ptr::eq(e, entry)), "{addr} finds it");
            }
        }
        assert_eq!((self.by_addr.pairs, self.by_name.pairs, self.unresolved.len()), (addrs, names, unresolved));
    }

    /// How many (address, device) pairs the tables hold.
    #[cfg(test)]
    pub fn addrs_held(&self) -> usize {
        self.by_addr.pairs
    }
}

impl Index<&Key> for Devices {
    type Output = Entry;

    fn index(&self, key: &Key) -> &Entry {
        self.get(key).expect("no such device")
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::string::String;
    use std::collections::HashMap;

    use super::*;
    use crate::time::Instant;

    /// A device told apart as `key` says.
    fn made(key: &Key) -> Entry {
        let from = match key {
            Key::Source(addr) => *addr,
            Key::Host(_) => "10.0.0.1".parse().unwrap(),
        };
        Entry::of(key, Instant::now(), from)
    }

    fn host(name: &str) -> Key {
        Key::Host(name.to_ascii_lowercase())
    }

    #[test]
    fn a_device_is_found_by_its_hostname_whatever_the_case_and_by_address_until_it_has_one() {
        let mut devices = Devices::default();
        let named = host("tv.local");
        devices.get_or_insert_with(&named, || made(&named)).device.hostname = Some("TV.local".into());
        devices.reindex(&named, &Indexed::default());
        let by_address = Key::Source("10.0.0.9".parse().unwrap());
        devices.get_or_insert_with(&by_address, || made(&by_address));
        devices.reindex(&by_address, &Indexed::default());
        devices.check();

        assert_eq!(devices.len(), 2);
        assert!(devices.contains_key(&named) && devices.contains_key(&by_address));
        assert_eq!(devices[&named].device.hostname.as_deref(), Some("TV.local"), "spelt as it was announced");
        assert!(!devices.contains_key(&host("other.local")));
        assert!(!devices.contains_key(&Key::Source("10.0.0.8".parse().unwrap())));

        // Told apart the same way a second time: it is the one that is here.
        devices.get_or_insert_with(&named, || unreachable!("it is here")).expires = Instant::now();
        assert_eq!(devices.len(), 2);

        assert!(devices.remove(&named).is_some() && devices.remove(&named).is_none());
        assert_eq!((devices.len(), devices.iter().count()), (1, 1));
        devices.check();
    }

    /// Whatever is put in and taken out, in any order, with the slots of those
    /// taken out used again, it holds what a map holds.
    #[test]
    fn it_holds_what_a_map_holds_through_any_mix_of_inserting_and_removing() {
        let mut devices = Devices::default();
        let mut model: HashMap<String, u64> = HashMap::new();
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        // Names of mixed case, and addresses, from a small set, so that the same come again.
        let key = |n: u64| -> (Key, String) {
            if n % 5 == 0 {
                let addr: IpAddr = format!("10.9.{}.{}", n % 7, n % 11).parse().unwrap();
                (Key::Source(addr), format!("source {addr}"))
            } else {
                let name = format!("Host{}.local", n % 300);
                (host(&name), name.to_ascii_lowercase())
            }
        };
        for step in 0..20_000u64 {
            let (key, id) = key(next() % 1000);
            let pick = next();
            match pick % 4 {
                0 | 1 => {
                    let was = devices.indexed_of(&key).unwrap_or_default();
                    let entry = devices.get_or_insert_with(&key, || made(&key));
                    entry.expires = Instant::now();
                    if let Key::Host(name) = &key {
                        // Spelt as announced, in no particular case.
                        let spelt: String = name.chars().enumerate().map(|(i, c)| if (i + step as usize) % 3 == 0 { c.to_ascii_uppercase() } else { c }).collect();
                        entry.device.hostname = Some(spelt);
                    }
                    // What it has changes: an address more or fewer, a service
                    // more (its host known or not) or fewer.
                    let addr: IpAddr = format!("10.5.{}.{}", pick >> 8 & 7, pick >> 16 & 7).parse().unwrap();
                    match pick >> 24 & 7 {
                        0 | 1 => entry.device.add_addrs(&[addr]),
                        2 => entry.device.addresses.retain(|a| a.ip != addr),
                        3 | 4 => {
                            let instance = format!("S{}._x{}._tcp.local", pick >> 32 & 3, pick >> 40 & 1);
                            let kind = format!("_x{}._tcp.local", pick >> 40 & 1);
                            let target = (pick >> 48 & 1 == 0).then(|| "somewhere.local".to_string());
                            if !entry.device.services.iter().any(|s| s.instance == instance) {
                                entry.device.services.push(crate::device::Service { instance, kind, target, ..Default::default() });
                            }
                        }
                        5 => entry.device.services.clear(),
                        6 => entry.device.services.retain(|s| s.target.is_none()),
                        _ => {}
                    }
                    devices.reindex(&key, &was);
                    model.entry(id.clone()).or_insert(step);
                }
                _ => assert_eq!(devices.remove(&key).is_some(), model.remove(&id).is_some()),
            }
            assert_eq!(devices.len(), model.len());
            assert_eq!(devices.contains_key(&key), model.contains_key(&id));
            if step % 500 == 0 {
                devices.check();
            }
        }
        devices.check();
        // The tables find what a scan of the devices does.
        let same = |found: Vec<&Entry>, scan: Vec<&Entry>| {
            let mut found: Vec<*const Entry> = found.into_iter().map(|e| e as *const Entry).collect();
            let mut scan: Vec<*const Entry> = scan.into_iter().map(|e| e as *const Entry).collect();
            (found.sort(), scan.sort());
            assert_eq!(found, scan);
        };
        for a in 0..8 {
            for b in 0..8 {
                let addr: IpAddr = format!("10.5.{a}.{b}").parse().unwrap();
                same(devices.with_addr(&addr).collect(), devices.iter().filter(|e| e.device.has_addr(&addr)).collect());
            }
        }
        for name in ["_x0._tcp.local", "_X1._tcp.LOCAL", "S1._x0._tcp.local", "host7.local", "HOST12.local", "_services._dns-sd._udp.local", "none"] {
            same(devices.with_name(name).collect(), devices.iter().filter(|e| e.device.has_name(name)).collect());
        }
        same(
            devices.with_unresolved().collect(),
            devices.iter().filter(|e| e.device.services.iter().any(|s| s.target.is_none())).collect(),
        );
        assert!(devices.with_name("_services._dns-sd._udp.local").count() > 0, "the test finds some");
        assert!(devices.with_unresolved().count() > 0 && devices.with_addr(&"10.5.1.1".parse().unwrap()).count() > 0);
        assert_eq!(devices.iter().count(), model.len());
        for entry in devices.iter() {
            let key = entry.key();
            assert!(model.contains_key(&match &key {
                Key::Host(name) => name.clone(),
                Key::Source(addr) => format!("source {addr}"),
            }));
        }
    }
}

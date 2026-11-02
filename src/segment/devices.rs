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

use alloc::vec::Vec;
use core::hash::{BuildHasher, Hash, Hasher};
use core::net::IpAddr;
use core::ops::Index;

use hashbrown::{DefaultHashBuilder, HashTable};

use super::{Entry, Key};

/// Where a device is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Id(u32);

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
        Ident::Host(name) => {
            let mut lower = [0u8; 64];
            for chunk in name.as_bytes().chunks(lower.len()) {
                let part = &mut lower[..chunk.len()];
                part.copy_from_slice(chunk);
                part.make_ascii_lowercase();
                h.write(part);
            }
            h.write_u8(0);
        }
        Ident::Source(addr) => {
            h.write_u8(1);
            addr.hash(&mut h);
        }
    }
    h.finish()
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
        self.free = Some(id.0);
        self.len -= 1;
        Some(entry)
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
        let by_address = Key::Source("10.0.0.9".parse().unwrap());
        devices.get_or_insert_with(&by_address, || made(&by_address));
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
            match next() % 3 {
                0 | 1 => {
                    let entry = devices.get_or_insert_with(&key, || made(&key));
                    entry.expires = Instant::now();
                    if let Key::Host(name) = &key {
                        // Spelt as announced, in no particular case.
                        let spelt: String = name.chars().enumerate().map(|(i, c)| if (i + step as usize) % 3 == 0 { c.to_ascii_uppercase() } else { c }).collect();
                        entry.device.hostname = Some(spelt);
                    }
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

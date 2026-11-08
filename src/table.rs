//! Things held in one place each, and the tables that find them.
//!
//! A thing lives in a slot of a list and is called by an [`Id`]: the slot's
//! number, and which thing it has held, so that an id outlives its thing
//! without ever being taken for the next one in the slot. Nothing about a thing
//! tells it apart from another: the tables that find things by what they
//! say, a hostname, an address, a name, a time, hold ids and hashes, are given
//! the hash of what is looked for, and tell the ids they hold apart by looking
//! into the things themselves. So nothing is kept twice, and a table can be
//! made again from the things alone.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::hash::{BuildHasher, Hash, Hasher};
use core::net::IpAddr;

use hashbrown::{hash_map::Entry as MapEntry, DefaultHashBuilder, HashMap, HashSet};

/// Which thing, and where it is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct Id {
    slot: u32,
    /// How many things the slot has held before this one.
    generation: u32,
}

impl Id {
    /// After every other, for the end of a range.
    pub const LAST: Id = Id { slot: u32::MAX, generation: u32::MAX };
}

/// The hash of `name` as it is in lowercase, whatever its case, and without
/// copying it whole.
pub(crate) fn hash_name(hasher: &DefaultHashBuilder, name: &str) -> u64 {
    let mut h = hasher.build_hasher();
    let mut lower = [0u8; 64];
    for chunk in name.as_bytes().chunks(lower.len()) {
        let part = &mut lower[..chunk.len()];
        part.copy_from_slice(chunk);
        part.make_ascii_lowercase();
        h.write(part);
    }
    h.write_u8(0);
    h.finish()
}

pub(crate) fn hash_addr(hasher: &DefaultHashBuilder, addr: &IpAddr) -> u64 {
    hasher.hash_one(addr)
}

enum Slot<T> {
    Taken(T),
    /// Empty, and the next empty one.
    Free(Option<u32>),
}

pub(crate) struct Table<T> {
    slots: Vec<Slot<T>>,
    /// How many things each slot has held.
    generations: Vec<u32>,
    /// The first empty slot.
    free: Option<u32>,
    len: usize,
}

impl<T> Default for Table<T> {
    fn default() -> Self {
        Table { slots: Vec::new(), generations: Vec::new(), free: None, len: 0 }
    }
}

impl<T> Table<T> {
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether `id` is of a thing that is still here.
    pub fn has(&self, id: Id) -> bool {
        self.generations.get(id.slot as usize) == Some(&id.generation)
            && matches!(self.slots[id.slot as usize], Slot::Taken(_))
    }

    /// The thing, if it is still here.
    pub fn try_get(&self, id: Id) -> Option<&T> {
        match self.slots.get(id.slot as usize) {
            Some(Slot::Taken(thing)) if self.generations[id.slot as usize] == id.generation => Some(thing),
            _ => None,
        }
    }

    pub fn get(&self, id: Id) -> &T {
        self.try_get(id).expect("an id of a thing that is gone")
    }

    pub fn get_mut(&mut self, id: Id) -> &mut T {
        match self.slots.get_mut(id.slot as usize) {
            Some(Slot::Taken(thing)) if self.generations[id.slot as usize] == id.generation => thing,
            _ => panic!("an id of a thing that is gone"),
        }
    }

    pub fn insert(&mut self, thing: T) -> Id {
        let slot = match self.free {
            Some(at) => {
                let Slot::Free(next) = self.slots[at as usize] else { unreachable!("the list of empty slots") };
                self.free = next;
                self.slots[at as usize] = Slot::Taken(thing);
                at
            }
            None => {
                self.slots.push(Slot::Taken(thing));
                self.generations.push(0);
                u32::try_from(self.slots.len() - 1).expect("fewer than 2^32 things")
            }
        };
        self.len += 1;
        Id { slot, generation: self.generations[slot as usize] }
    }

    pub fn remove(&mut self, id: Id) -> T {
        assert!(self.has(id), "an id of a thing that is gone");
        let Slot::Taken(thing) = core::mem::replace(&mut self.slots[id.slot as usize], Slot::Free(self.free)) else {
            unreachable!("checked above")
        };
        self.generations[id.slot as usize] = id.generation.wrapping_add(1);
        self.free = Some(id.slot);
        self.len -= 1;
        thing
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.slots.iter().filter_map(|slot| match slot {
            Slot::Taken(thing) => Some(thing),
            Slot::Free(_) => None,
        })
    }

    pub fn ids(&self) -> impl Iterator<Item = Id> + '_ {
        let taken = |(at, slot): (usize, &Slot<T>)| {
            matches!(slot, Slot::Taken(_)).then(|| Id { slot: at as u32, generation: self.generations[at] })
        };
        self.slots.iter().enumerate().filter_map(taken)
    }

    /// Whether the list of empty slots is what the slots say.
    #[cfg(test)]
    pub fn check(&self) {
        let taken = self.slots.iter().filter(|s| matches!(s, Slot::Taken(_))).count();
        assert_eq!(self.len, taken);
        assert_eq!(self.generations.len(), self.slots.len());
        let mut free = self.free;
        let mut empty = 0;
        while let Some(at) = free {
            let Slot::Free(next) = self.slots[at as usize] else { panic!("a taken slot is listed as empty") };
            (free, empty) = (next, empty + 1);
        }
        assert_eq!(empty, self.slots.len() - taken);
    }
}

/// The things under one hash: usually one, but a name that many answer for
/// (a service type, the type enumeration) has them all under one, and one is
/// taken from among them without looking at the others.
enum Holders {
    One(Id),
    Many(Box<HashSet<Id>>),
}

/// Things by hash, each under every hash it has, as many as have it.
#[derive(Default)]
pub(crate) struct Multi {
    by_hash: HashMap<u64, Holders>,
    /// How many (hash, thing) pairs it holds.
    pub pairs: usize,
}

impl Multi {
    pub fn add(&mut self, hash: u64, id: Id) {
        match self.by_hash.entry(hash) {
            MapEntry::Vacant(vacant) => {
                vacant.insert(Holders::One(id));
            }
            MapEntry::Occupied(mut occupied) => match occupied.get_mut() {
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

    pub fn remove(&mut self, hash: u64, id: Id) {
        let MapEntry::Occupied(mut occupied) = self.by_hash.entry(hash) else { return };
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

    /// The things under `hash`: those that have what hashes to it, and any
    /// that has something else that does.
    pub fn under(&self, hash: u64) -> impl Iterator<Item = Id> + '_ {
        let (one, many) = match self.by_hash.get(&hash) {
            None => (None, None),
            Some(Holders::One(id)) => (Some(*id), None),
            Some(Holders::Many(set)) => (None, Some(set.iter().copied())),
        };
        one.into_iter().chain(many.into_iter().flatten())
    }

    #[cfg(test)]
    pub fn holds(&self, hash: u64, id: Id) -> bool {
        self.under(hash).any(|held| held == id)
    }

    /// Put `id` under each hash in `new` that is not in `was`, and take it
    /// from under each in `was` that is not in `new`. Both are in order.
    pub fn move_between(&mut self, id: Id, was: &[u64], new: &[u64]) {
        for &hash in was.iter().filter(|h| new.binary_search(h).is_err()) {
            self.remove(hash, id);
        }
        for &hash in new.iter().filter(|h| was.binary_search(h).is_err()) {
            self.add(hash, id);
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/table.rs"]
mod tests;

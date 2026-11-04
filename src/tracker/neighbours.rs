//! The kernel's neighbour table for an interface, and what finds addresses by
//! their link-layer address.
//!
//! The table of addresses by link-layer address holds the addresses, as ids,
//! and confirms by looking each up in the table itself: it is made of the
//! table and nothing else.

use alloc::vec::Vec;
use core::hash::{BuildHasher, Hasher};
use core::net::IpAddr;

use hashbrown::{DefaultHashBuilder, HashMap, HashTable};

#[derive(Default)]
pub(crate) struct NeighbourTable {
    /// Each address it has a link-layer address for, and that address.
    macs: HashMap<IpAddr, Vec<u8>>,
    /// The addresses, by the hash of their link-layer address.
    by_mac: HashTable<IpAddr>,
    hasher: DefaultHashBuilder,
}

fn hash_of(hasher: &DefaultHashBuilder, mac: &[u8]) -> u64 {
    let mut h = hasher.build_hasher();
    h.write(mac);
    h.finish()
}

impl NeighbourTable {
    pub fn get(&self, ip: &IpAddr) -> Option<&Vec<u8>> {
        self.macs.get(ip)
    }

    pub fn contains_key(&self, ip: &IpAddr) -> bool {
        self.macs.contains_key(ip)
    }

    /// Set the link-layer address of `ip`. Returns the one it had.
    pub fn insert(&mut self, ip: IpAddr, mac: Vec<u8>) -> Option<Vec<u8>> {
        let hash = hash_of(&self.hasher, &mac);
        let was = self.macs.insert(ip, mac);
        if let Some(was) = &was {
            self.unlink(ip, hash_of(&self.hasher, was));
        }
        let (macs, hasher) = (&self.macs, &self.hasher);
        self.by_mac.insert_unique(hash, ip, |ip| hash_of(hasher, &macs[ip]));
        was
    }

    /// Forget `ip`. Returns the link-layer address it had.
    pub fn remove(&mut self, ip: &IpAddr) -> Option<Vec<u8>> {
        let was = self.macs.remove(ip)?;
        self.unlink(*ip, hash_of(&self.hasher, &was));
        Some(was)
    }

    fn unlink(&mut self, ip: IpAddr, hash: u64) {
        if let Ok(found) = self.by_mac.find_entry(hash, |other| *other == ip) {
            found.remove();
        }
    }

    /// The addresses that have the link-layer address `mac`.
    pub fn with_mac<'a>(&'a self, mac: &'a [u8]) -> impl Iterator<Item = IpAddr> + 'a {
        self.by_mac
            .iter_hash(hash_of(&self.hasher, mac))
            .copied()
            .filter(move |ip| self.macs.get(ip).is_some_and(|own| own == mac))
    }

    /// Whether the table by link-layer address is what the table says.
    #[cfg(test)]
    pub fn check(&self) {
        assert_eq!(self.by_mac.len(), self.macs.len());
        for (ip, mac) in &self.macs {
            assert!(self.with_mac(mac).any(|found| found == *ip), "{ip} is found by {mac:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn addresses_are_found_by_their_link_layer_address_as_they_change() {
        let mut table = NeighbourTable::default();
        let (a, b, c) = (vec![1; 6], vec![2; 6], vec![3; 6]);
        assert_eq!(table.insert(ip("10.0.0.1"), a.clone()), None);
        table.insert(ip("fd00::1"), a.clone());
        table.insert(ip("10.0.0.2"), b.clone());
        table.check();
        let mut with_a: Vec<IpAddr> = table.with_mac(&a).collect();
        with_a.sort();
        assert_eq!(with_a, [ip("10.0.0.1"), ip("fd00::1")]);

        // One that moves to another link-layer address is no longer found under the first.
        assert_eq!(table.insert(ip("10.0.0.1"), b.clone()), Some(a.clone()));
        assert_eq!(table.insert(ip("10.0.0.2"), b.clone()), Some(b.clone()), "set again to what it is");
        table.check();
        assert_eq!(table.with_mac(&a).collect::<Vec<_>>(), [ip("fd00::1")]);
        assert_eq!(table.with_mac(&b).count(), 2);

        assert_eq!(table.remove(&ip("fd00::1")), Some(a.clone()));
        assert_eq!(table.remove(&ip("fd00::1")), None);
        table.check();
        assert_eq!(table.with_mac(&a).count(), 0);
        assert_eq!(table.with_mac(&c).count(), 0);
        assert!(table.contains_key(&ip("10.0.0.2")) && !table.contains_key(&ip("fd00::1")));
    }
}

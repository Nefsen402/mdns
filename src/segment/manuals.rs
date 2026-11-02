//! The devices a segment announces on behalf of somewhere else, each held in
//! one place, and how they are found.
//!
//! A device is [kept](Table) and called by its [`Id`]. It is found by its
//! hostname, which is among the names it, or anyone who wants it announced,
//! has records under, and by when it is next due to be announced again. Like
//! those of the discovered devices ([`Devices`](super::devices::Devices)) the
//! tables hold hashes, times and ids, and follow a device when it is changed
//! by [`Manuals::edit`], or goes. A device that nobody wants announced and
//! that is not shown is gone, as it has nothing to be found by.

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use hashbrown::DefaultHashBuilder;

use super::table::{hash_name, Id, Multi, Table};
use super::Manual;
use crate::time::Instant;

impl Manual {
    /// Its hostname, as announced or as wanted.
    fn host(&self) -> Option<&str> {
        let shown = self.shown.as_ref();
        let wanted = self.claims.values().map(|claim| &claim.device);
        shown.into_iter().chain(wanted).find_map(|device| device.hostname.as_deref())
    }

    /// Whether nothing of it is wanted or shown.
    fn gone(&self) -> bool {
        self.claims.is_empty() && self.shown.is_none()
    }
}

/// What the tables hold of one: the hashes of the names it, or any claim on
/// it, has records under, and when it is held as due.
#[derive(Default, Debug, PartialEq, Eq)]
struct Held {
    names: Vec<u64>,
    due: Option<Instant>,
}

#[derive(Default)]
pub(super) struct Manuals {
    table: Table<Manual>,
    /// Each name an announced device, or a claim on it, has records under,
    /// and the device, by the hash of the name.
    by_name: Multi,
    /// The devices by when they are next due to be announced again.
    by_due: BTreeSet<(Instant, Id)>,
    /// Whether devices that have not changed are announced again, which is
    /// what when they are due goes by.
    unchanged: bool,
    hasher: DefaultHashBuilder,
}

impl Manuals {
    fn find(&self, host: &str) -> Option<Id> {
        let hash = hash_name(&self.hasher, host);
        let named = |id: &Id| self.table.get(*id).host().is_some_and(|own| own.eq_ignore_ascii_case(host));
        self.by_name.under(hash).find(named)
    }

    /// The device announced as `host`, ignoring case.
    pub fn get(&self, host: &str) -> Option<&Manual> {
        self.find(host).map(|id| self.table.get(id))
    }

    pub fn contains_key(&self, host: &str) -> bool {
        self.find(host).is_some()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Manual> {
        self.table.iter()
    }

    fn held(&self, manual: &Manual) -> Held {
        let mut names = Vec::new();
        let shown = manual.shown.iter();
        for device in shown.chain(manual.claims.values().map(|claim| &claim.device)) {
            device.for_each_name(|name| names.push(hash_name(&self.hasher, name)));
        }
        names.sort_unstable();
        names.dedup();
        Held { names, due: manual.reannounce_at(self.unchanged) }
    }

    fn follow(&mut self, id: Id, was: &Held) {
        let now = self.held(self.table.get(id));
        self.by_name.move_between(id, &was.names, &now.names);
        if was.due != now.due {
            if let Some(at) = was.due {
                self.by_due.remove(&(at, id));
            }
            if let Some(at) = now.due {
                self.by_due.insert((at, id));
            }
        }
    }

    /// Keep a device that is not announced yet, and wanted by someone. Not if
    /// one is announced as its hostname.
    pub fn insert(&mut self, manual: Manual) {
        debug_assert!(manual.host().is_some_and(|host| !self.contains_key(host)), "a hostname is announced once");
        debug_assert!(!manual.gone(), "a device is wanted");
        let id = self.table.insert(manual);
        self.follow(id, &Held::default());
    }

    /// Change the device announced as `host` with `f`, and have the tables
    /// follow. It is gone when nothing of it is wanted or shown any more.
    pub fn edit<R>(&mut self, host: &str, f: impl FnOnce(&mut Manual) -> R) -> Option<R> {
        let id = self.find(host)?;
        let was = self.held(self.table.get(id));
        let out = f(self.table.get_mut(id));
        if self.table.get(id).gone() {
            self.drop(id, &was);
        } else {
            self.follow(id, &was);
        }
        Some(out)
    }

    /// Let go of a device, which the tables hold as `held`.
    fn drop(&mut self, id: Id, held: &Held) -> Manual {
        self.by_name.move_between(id, &held.names, &[]);
        if let Some(at) = held.due {
            self.by_due.remove(&(at, id));
        }
        self.table.remove(id)
    }

    /// The devices that have, or that someone wants to have, records under
    /// `name`, ignoring case.
    pub fn with_claimed_name<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Manual> + 'a {
        let hash = hash_name(&self.hasher, name);
        self.by_name.under(hash).map(|id| self.table.get(id)).filter(move |manual| {
            manual.claims.values().any(|claim| claim.device.has_name(name))
                || manual.shown.as_ref().is_some_and(|shown| shown.has_name(name))
        })
    }

    /// The devices that are announced with records under `name`, ignoring case.
    pub fn with_shown_name<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Manual> + 'a {
        let hash = hash_name(&self.hasher, name);
        self.by_name
            .under(hash)
            .map(|id| self.table.get(id))
            .filter(move |manual| manual.shown.as_ref().is_some_and(|shown| shown.has_name(name)))
    }

    /// The hostnames, in lowercase, of all the devices.
    pub fn hosts_all(&self) -> Vec<String> {
        self.hosts(self.iter())
    }

    /// The hostnames, in lowercase, of the devices that someone wants to have
    /// records under `name`, ignoring case, each once.
    pub fn hosts_claiming(&self, name: &str) -> Vec<String> {
        self.hosts(self.with_claimed_name(name))
    }

    /// The hostnames, in lowercase, of the devices announced with records
    /// under `name`, ignoring case, each once.
    pub fn hosts_showing(&self, name: &str) -> Vec<String> {
        self.hosts(self.with_shown_name(name))
    }

    fn hosts<'a>(&self, manuals: impl Iterator<Item = &'a Manual>) -> Vec<String> {
        let mut hosts: Vec<String> = manuals.filter_map(|m| m.host().map(str::to_ascii_lowercase)).collect();
        hosts.sort_unstable();
        hosts.dedup();
        hosts
    }

    /// Set whether devices that have not changed are announced again. It is
    /// what when they are due goes by, so those times are made again.
    pub fn set_unchanged(&mut self, unchanged: bool) {
        if self.unchanged == unchanged {
            return;
        }
        self.unchanged = unchanged;
        self.by_due.clear();
        for id in self.table.ids().collect::<Vec<_>>() {
            if let Some(at) = self.table.get(id).reannounce_at(unchanged) {
                self.by_due.insert((at, id));
            }
        }
    }

    /// When a device is next due to be announced again.
    pub fn next_due(&self) -> Option<Instant> {
        self.by_due.first().map(|&(at, _)| at)
    }

    /// The hostnames, in lowercase, of the devices due to be announced again
    /// as of `now`.
    pub fn due(&self, now: Instant) -> Vec<String> {
        let host = |id: Id| self.table.get(id).host().map(str::to_ascii_lowercase);
        self.by_due.range(..=(now, Id::LAST)).filter_map(|&(_, id)| host(id)).collect()
    }

    /// Whether the tables find each device by what it says and hold what it
    /// has, and nothing else.
    #[cfg(test)]
    pub fn check(&self) {
        self.table.check();
        let (mut names, mut due) = (0, 0);
        for id in self.table.ids() {
            let manual = self.table.get(id);
            let host = manual.host().expect("a device that is kept has a hostname");
            assert!(!manual.gone(), "a device is wanted or shown: {host}");
            assert_eq!(self.find(host), Some(id), "a hostname is announced once: {host}");
            let held = self.held(manual);
            names += held.names.len();
            assert!(held.names.iter().all(|&h| self.by_name.holds(h, id)), "a name is held: {host}");
            if let Some(at) = held.due {
                due += 1;
                assert!(self.by_due.contains(&(at, id)), "it is held as due: {host}");
            }
        }
        assert_eq!((self.by_name.pairs, self.by_due.len()), (names, due));
    }
}

#[cfg(test)]
impl Manuals {
    pub fn is_empty(&self) -> bool {
        self.table.len() == 0
    }
}

#[cfg(test)]
impl core::ops::Index<&str> for Manuals {
    type Output = Manual;

    fn index(&self, host: &str) -> &Manual {
        self.get(host).expect("no such device")
    }
}

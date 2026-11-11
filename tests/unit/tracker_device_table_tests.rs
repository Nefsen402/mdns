use alloc::format;
use alloc::string::String;
use std::collections::HashMap;

use super::*;
use crate::device::ServiceParts;
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
                        2 => edit(&mut entry.device.addresses).retain(|a| a.ip != addr),
                        3 | 4 => {
                            let instance = format!("S{}._x{}._tcp.local", pick >> 40 & 3, pick >> 44 & 1);
                            let kind = format!("_x{}._tcp.local", pick >> 44 & 1);
                            let target = (pick >> 48 & 1 == 0).then(|| "somewhere.local".to_string());
                            if !entry.device.services.iter().any(|s| s.instance() == instance) {
                                edit(&mut entry.device.services).push(ServiceParts { instance, kind, target, ..Default::default() }.into());
                            }
                        }
                        5 => edit(&mut entry.device.services).clear(),
                        6 => entry.refreshed = Some(start + Duration::from_secs(pick >> 8 & 63)),
                        _ => edit(&mut entry.device.services).retain(|s| s.target().is_none()),
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
        same(ptrs(devices.with_name(name).collect()), ptrs(devices.iter().filter(|e| e.device.has_name(&Advertise::ALL, name)).collect()));
    }
    same(
        ptrs(devices.with_unresolved().map(|(_, e)| e).collect()),
        ptrs(devices.iter().filter(|e| e.device.services.iter().any(|s| s.target().is_none())).collect()),
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

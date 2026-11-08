use alloc::string::String;
use alloc::vec::Vec;

use super::*;

#[test]
fn an_id_outlives_its_thing_without_being_taken_for_the_next_in_its_slot() {
    let mut table: Table<String> = Table::default();
    let (a, b) = (table.insert("a".into()), table.insert("b".into()));
    assert_eq!((table.get(a).as_str(), table.get(b).as_str(), table.len()), ("a", "b", 2));

    assert_eq!(table.remove(a), "a");
    assert!(!table.has(a) && table.try_get(a).is_none());
    // The slot is used again, by a thing that is not the one the old id was of.
    let c = table.insert("c".into());
    assert_ne!(a, c);
    assert!(!table.has(a) && table.has(c));
    assert_eq!(table.get(c), "c");
    table.check();

    assert_eq!(table.ids().collect::<Vec<_>>().len(), 2);
    assert_eq!(table.iter().map(String::as_str).collect::<Vec<_>>().len(), 2);
}

#[test]
fn a_hash_holds_one_thing_or_many_and_gives_one_up_without_looking_at_the_others() {
    let mut table: Table<u8> = Table::default();
    let ids: Vec<Id> = (0..50).map(|n| table.insert(n)).collect();
    let mut multi = Multi::default();
    for &id in &ids {
        multi.add(7, id);
        multi.add(7, id); // once
    }
    multi.add(8, ids[0]);
    assert_eq!((multi.pairs, multi.under(7).count(), multi.under(8).count(), multi.under(9).count()), (51, 50, 1, 0));

    for &id in &ids[1..49] {
        multi.remove(7, id);
        multi.remove(7, id); // gone
    }
    let mut left: Vec<Id> = multi.under(7).collect();
    left.sort();
    assert_eq!(left, [ids[0], ids[49]]);
    multi.remove(7, ids[0]);
    assert_eq!(multi.under(7).collect::<Vec<_>>(), [ids[49]], "one again");
    multi.remove(7, ids[49]);
    multi.remove(8, ids[0]);
    assert_eq!(multi.pairs, 0);
    assert!(!multi.holds(7, ids[49]));

    // Moved from the hashes it was under to those it is under.
    multi.move_between(ids[3], &[], &[1, 2, 3]);
    multi.move_between(ids[3], &[1, 2, 3], &[2, 3, 4]);
    assert_eq!((multi.holds(1, ids[3]), multi.holds(2, ids[3]), multi.holds(4, ids[3])), (false, true, true));
    assert_eq!(multi.pairs, 3);
}

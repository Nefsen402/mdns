use super::*;

#[test]
fn behaves_as_std_does() {
    let a = Instant::now();
    let b = Instant::now();
    assert!(b >= a);
    assert_eq!(a - b, Duration::ZERO, "earlier minus later is nothing");
    let later = a + Duration::from_secs(5);
    assert_eq!(later - a, Duration::from_secs(5));
    assert_eq!(later.saturating_duration_since(a), Duration::from_secs(5));
    assert_eq!(later - Duration::from_secs(5), a);
    assert_eq!(a.checked_add(Duration::MAX), None, "too far for the clock");
    assert_eq!(a.checked_sub(Duration::MAX), None);
    assert!(later.elapsed() == Duration::ZERO && a.elapsed() < Duration::from_secs(1));
}

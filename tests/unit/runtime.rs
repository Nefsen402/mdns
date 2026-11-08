use super::*;

#[test]
fn words_an_error_as_the_system_does() {
    assert_eq!(Why(Errno::NOENT).to_string(), "No such file or directory (os error 2)");
    assert_eq!(alloc::format!("{:?}", Why(Errno::NOENT)), "No such file or directory (os error 2)");
}

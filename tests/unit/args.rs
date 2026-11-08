use super::*;

fn parser(args: &[&str]) -> Parser {
    Parser::new(args.iter().map(|a| a.to_string()))
}

/// Everything the command line holds, the value of each option named in
/// `valued` taken with it.
fn all(args: &[&str], valued: &[&str]) -> Result<Vec<String>, Error> {
    let mut p = parser(args);
    let mut out = Vec::new();
    while let Some(arg) = p.next()? {
        let (name, takes) = match arg {
            Arg::Short(c) => (format!("-{c}"), valued.contains(&c.to_string().as_str())),
            Arg::Long(name) => (format!("--{name}"), valued.contains(&name)),
            Arg::Value(word) => (word, false),
        };
        out.push(if takes { format!("{name}={}", p.value()?) } else { name });
    }
    Ok(out)
}

#[test]
fn tells_options_from_words() {
    assert_eq!(all(&["devices", "-v", "IoT", "--json"], &[]), Ok(vec!["devices".into(), "-v".into(), "IoT".into(), "--json".into()]));
    assert_eq!(all(&["-", "x"], &[]).unwrap(), ["-", "x"], "a lone dash is a word");
    assert_eq!(all(&[], &[]).unwrap(), Vec::<String>::new());
}

#[test]
fn options_take_their_values_every_way() {
    let got = all(&["--socket", "/a", "--socket=/b", "-s", "/c", "-s/d", "--socket=", "--query=a=b"], &["socket", "s", "query"]);
    assert_eq!(got.unwrap(), ["--socket=/a", "--socket=/b", "-s=/c", "-s=/d", "--socket=", "--query=a=b"]);
    // A value may look like an option.
    assert_eq!(all(&["--log", "--json"], &["log"]).unwrap(), ["--log=--json"]);
}

#[test]
fn short_options_bundle() {
    assert_eq!(all(&["-vh"], &[]).unwrap(), ["-v", "-h"]);
    assert_eq!(all(&["-vs", "/a", "x"], &["s"]).unwrap(), ["-v", "-s=/a", "x"]);
    assert_eq!(all(&["-vs/a"], &["s"]).unwrap(), ["-v", "-s=/a"]);
    assert_eq!(all(&["-é"], &[]).unwrap(), ["-é"], "a letter, not a byte");
}

#[test]
fn after_two_dashes_all_are_words() {
    assert_eq!(all(&["sub", "--", "-x", "--y", "--"], &[]).unwrap(), ["sub", "-x", "--y", "--"]);
}

#[test]
fn says_what_is_wrong() {
    assert_eq!(all(&["--socket"], &["socket"]).unwrap_err().to_string(), "missing argument for option '--socket'");
    assert_eq!(all(&["-s"], &["s"]).unwrap_err().to_string(), "missing argument for option '-s'");
    assert_eq!(all(&["-vs"], &["s"]).unwrap_err().to_string(), "missing argument for option '-s'");
    assert_eq!(all(&["--verbose=yes"], &[]).unwrap_err().to_string(), r#"unexpected argument for option '--verbose': "yes""#);
    assert_eq!(Arg::Long("bogus").unexpected().to_string(), "invalid option '--bogus'");
    assert_eq!(Arg::Short('x').unexpected().to_string(), "invalid option '-x'");
    assert_eq!(Arg::Value("extra".into()).unexpected().to_string(), "unexpected argument 'extra' found");
}

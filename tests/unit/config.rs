use super::*;

const EXAMPLE: &str = r#"
[segment]
name=media_stuff
interfaces=br0,media

[segment]
name="IoT"
interfaces=wifi

[segment]
name="IoT to br0"
interfaces=br0,wifi
"#;

fn seg(name: &str, interfaces: &[&str]) -> SegmentConfig {
    SegmentConfig {
        name: name.into(),
        interfaces: interfaces.iter().map(|s| s.to_string()).collect(),
        ..SegmentConfig::default()
    }
}

#[test]
fn untrusted_interfaces_are_listed_and_checked() {
    let parse = |extra: &str| Config::parse(&format!("[Segment]\nName=s\nInterfaces=br0,media,wifi\n{extra}"));
    assert!(parse("").unwrap().segments[0].untrusted.is_empty());
    assert_eq!(parse("Untrusted=media").unwrap().segments[0].untrusted, ["media"]);
    // The same kind of list as Interfaces=, with the key in any case.
    assert_eq!(parse("untrusted=media, wifi").unwrap().segments[0].untrusted, ["media", "wifi"]);
    assert_eq!(parse("UNTRUSTED=media\nUntrusted=wifi").unwrap().segments[0].untrusted, ["media", "wifi"]);
    assert!(parse("Untrusted=media\nUntrusted=").unwrap().segments[0].untrusted.is_empty(), "empty resets");

    // Only interfaces of the segment, each once.
    assert!(parse("Untrusted=eth9").unwrap_err().to_string().contains("not in its Interfaces"));
    assert!(parse("Untrusted=media,media").is_err());
    // Someone has to be told about the others.
    assert!(parse("Untrusted=br0,media,wifi").unwrap_err().to_string().contains("no trusted interface"));
    assert!(parse("Untrusted=media,wifi").is_ok());
    // A segment of one interface reflects nothing anyway.
    assert!(Config::parse("[Segment]\nName=s\nInterfaces=wifi\nUntrusted=wifi\n").is_ok());
}

#[test]
fn a_pattern_matches_what_it_says() {
    assert!(glob("enp*", "enp3s0") && glob("enp*", "enp") && glob("*", "eth0") && glob("*", ""));
    assert!(glob("eth?", "eth0") && !glob("eth?", "eth") && !glob("eth?", "eth10"));
    assert!(glob("en*s?", "enp3s0") && glob("*0", "enp3s0") && glob("*p*s*", "enp3s0"));
    assert!(!glob("enp*", "wlan0") && !glob("*0", "enp3s1") && !glob("eth0", "eth01"));
    assert!(glob("eth0", "eth0") && !glob("", "x") && glob("", ""));
    assert!(is_pattern("enp*") && is_pattern("eth?") && !is_pattern("eth0"));
}

#[test]
fn interfaces_may_be_patterns() {
    let c = Config::parse(
        "[Segment]\nName=s\nInterfaces=enp*,wlan0\nUntrusted=enp3s0,wlan0\n\
         [Interface]\nName=enp*\nMinimumLifetime=30s\nMaxDevices=9\n\
         [Interface]\nName=enp3s0\nMinimumLifetime=90s\n\
         [Interface]\nName=en*\nMinimumLifetime=45s\nMaxDevices=7\nMaxServices=5\n\
         [Advertise]\nHostname=pc\nInterface=enp*\n",
    )
    .unwrap();
    assert!(c.wants("enp3s0") && c.wants("wlan0") && !c.wants("eth0"));
    assert!(c.segments[0].has("enp7s0") && !c.segments[0].has("wlan1"));
    // Only the names are of interfaces to be there; a pattern is of those that are.
    assert_eq!(c.interfaces().iter().map(|i| i.name.as_str()).collect::<Vec<_>>(), ["wlan0"]);
    // A name of its own, then the first pattern that sets it, then the one for all.
    let enp = c.interface("enp3s0");
    assert_eq!((enp.min_lifetime.as_secs(), enp.max_devices, enp.max_services), (90, 9, 5));
    assert_eq!(c.interface("enp5s0").min_lifetime.as_secs(), 30);
    assert_eq!(c.interface("enx1").min_lifetime.as_secs(), 45);
    assert_eq!(c.interface("wlan0").min_lifetime, DEFAULT_MIN_LIFETIME);
}

#[test]
fn what_names_interfaces_is_in_a_segment_by_name_or_pattern() {
    let err = |text: &str| Config::parse(text).unwrap_err().to_string();
    let seg = "[Segment]\nName=s\nInterfaces=enp*,wlan0\n";
    // A name or a pattern of the segment, or a name a pattern of it matches.
    assert!(Config::parse(&format!("{seg}Untrusted=enp*\n")).is_ok());
    assert!(Config::parse(&format!("{seg}Untrusted=enp3s0\n")).is_ok());
    assert!(err(&format!("{seg}Untrusted=eth*\n")).contains("not in its Interfaces"));
    assert!(err(&format!("{seg}Untrusted=enp*,enp*\n")).contains("twice"));
    assert!(err("[Segment]\nName=s\nInterfaces=enp*,wlan*\nUntrusted=enp*,wlan*\n").contains("no trusted interface"));
    assert!(Config::parse(&format!("{seg}[Interface]\nName=enp3s0\n")).is_ok());
    assert!(Config::parse(&format!("{seg}[Interface]\nName=enp*\n")).is_ok());
    assert!(err(&format!("{seg}[Interface]\nName=eth0\n")).contains("not in the Interfaces"));
    assert!(Config::parse(&format!("{seg}[Interface]\nName=eth*\n")).is_ok(), "a pattern may match none");
    assert!(Config::parse(&format!("{seg}[Advertise]\nHostname=pc\nInterface=enp1\n")).is_ok());
    assert!(err(&format!("{seg}[Advertise]\nHostname=pc\nInterface=eth0\n")).contains("not in any segment"));
    // The same hostname on interfaces a pattern and a name both have is the same interface.
    assert!(err(&format!("{seg}[Advertise]\nHostname=pc\nInterface=enp*\n[Advertise]\nHostname=pc\nInterface=enp*\n"))
        .contains("same interface"));
    assert!(Config::parse(&format!("{seg}[Advertise]\nHostname=pc\nInterface=enp*\n[Advertise]\nHostname=pc\nInterface=wlan0\n")).is_ok());
}

#[test]
fn interfaces_may_be_kept_out_and_that_wins() {
    let seg = |interfaces: &str| format!("[Segment]\nName=s\nInterfaces={interfaces}\n");
    let c = Config::parse(&seg("*,!br*,!veth?")).unwrap();
    let has = |name: &str| c.segments[0].has(name);
    assert!(has("enp3s0") && has("wlan0") && has("veth10") && !has("br0") && !has("br-lan") && !has("veth1"));
    // However it is ordered.
    let c = Config::parse(&seg("!br*,*")).unwrap();
    assert!(c.segments[0].has("enp3s0") && !c.segments[0].has("br0"));
    assert!(c.wants("enp3s0") && !c.wants("br0"));
    // Only what is included is of interfaces to be there.
    let c = Config::parse(&seg("wlan0,*,!enp*")).unwrap();
    assert_eq!(c.interfaces().iter().map(|i| i.name.as_str()).collect::<Vec<_>>(), ["wlan0"]);
    assert!(c.interface("enp3s0").probe_interval.is_none());

    let err = |text: &str| Config::parse(text).unwrap_err().to_string();
    assert!(err(&seg("!br*")).contains("only interfaces kept out"));
    assert!(err(&seg("*,!")).contains("keeps nothing out"));
    assert!(err(&seg("br0,!br*")).contains("also keeps out"));
    // The segment's interfaces are those that are not kept out, for what is said of them.
    let with = |extra: &str| format!("{}{extra}", seg("*,!br0"));
    assert!(err(&with("Untrusted=br0\n")).contains("not in its Interfaces"));
    assert!(Config::parse(&with("Untrusted=enp3s0\n")).is_ok());
    assert!(err(&with("[Interface]\nName=br0\n")).contains("not in the Interfaces"));
    assert!(err(&with("[Advertise]\nHostname=pc\nInterface=br0\n")).contains("not in any segment"));
    assert!(Config::parse(&with("[Advertise]\nHostname=pc\nInterface=eth0\n")).is_ok());
    // Another segment may have one that this keeps out.
    assert!(Config::parse(&format!("{}{}", seg("*,!br0"), "[Segment]\nName=t\nInterfaces=br0,x\n")).is_ok());
}

#[test]
fn the_avahi_socket_is_off_unless_set() {
    assert_eq!(Config::parse(EXAMPLE).unwrap().avahi_socket, None);
    let with = |value: &str| Config::parse(&format!("[Ipc]\nAvahiSocket={value}\n{EXAMPLE}")).unwrap().avahi_socket;
    assert_eq!(with("/run/avahi-daemon/socket").as_deref(), Some("/run/avahi-daemon/socket"));
    assert_eq!(with("\"/tmp/a b\"").as_deref(), Some("/tmp/a b"));
    assert_eq!(with(""), None, "empty is off");
}

#[test]
fn advertise_is_optional_and_validated() {
    let names = |c: Config| c.advertise.into_iter().map(|a| a.name).collect::<Vec<_>>();
    assert!(Config::parse(EXAMPLE).unwrap().advertise.is_empty());

    let with = |value: &str| Config::parse(&format!("[Advertise]\nHostname={value}\n{EXAMPLE}"));
    assert_eq!(names(with("router.local").unwrap()), ["router.local"]);
    assert_eq!(names(with("\"My-Router.LOCAL\"").unwrap()), ["My-Router.LOCAL"]);
    // A bare label means that label under .local.
    assert_eq!(names(with("router").unwrap()), ["router.local"]);

    for bad in ["", "router.lan", "router.example.com", "bad name.local", "a..local", ".local", "ro_uter.local"] {
        assert!(with(bad).is_err(), "should reject {bad:?}");
    }
    assert!(with(&format!("{}.local", "x".repeat(64))).is_err());
    assert!(with(&format!("{}.local", "x".repeat(63))).is_ok());
}

/// Any number of them, each with its own name, services, interfaces and TTL.
#[test]
fn there_may_be_any_number_of_advertise_sections() {
    let c = Config::parse(&format!(
        "[Advertise]\nHostname=pc\nServices=_ssh._tcp:22\nInterface=br0\nTTL=1h\n\
         [Advertise]\nHostname=files\nServices=_smb._tcp:445\nInterface=media\n\
         [Advertise]\nHostname=other\n\
         [Segment]\nName=a\nInterfaces=br0,media\n"
    ))
    .unwrap();
    assert_eq!(c.advertise.len(), 3);
    assert_eq!((c.advertise[0].name.as_str(), c.advertise[0].ttl), ("pc.local", Duration::from_secs(3600)));
    assert_eq!(c.advertise[1].services, [("_smb._tcp".to_string(), 445)]);
    assert_eq!((c.advertise[2].interfaces.len(), c.advertise[2].ttl), (0, Duration::from_secs(120)));

    let err = |text: &str| Config::parse(&format!("{text}\n[Segment]\nName=a\nInterfaces=br0,media\n")).unwrap_err().to_string();
    // Each has a name.
    let e = err("[Advertise]\nHostname=pc\n[Advertise]\nServices=_ssh._tcp:22");
    assert!(e.contains("line 3") && e.contains("no Hostname="), "{e}");
    // One name is not on an interface twice; on different ones, or in
    // different case on none shared, it may be.
    let e = err("[Advertise]\nHostname=pc\n[Advertise]\nHostname=PC");
    assert!(e.contains("line 3") && e.contains("same interface"), "{e}");
    let e = err("[Advertise]\nHostname=pc\nInterface=br0\n[Advertise]\nHostname=pc");
    assert!(e.contains("same interface"), "{e}");
    let ok = Config::parse("[Advertise]\nHostname=pc\nInterface=br0\n[Advertise]\nHostname=pc\nInterface=media\n[Segment]\nName=a\nInterfaces=br0,media\n");
    assert!(ok.is_ok());
}

#[test]
fn advertised_services_are_a_type_and_a_port() {
    let ok = |value: &str| Config::parse(&format!("[Advertise]\nHostname=pc\nServices={value}\n{EXAMPLE}")).map(|c| c.advertise[0].services.clone());
    assert_eq!(ok("_ssh._tcp:22").unwrap(), [("_ssh._tcp".to_string(), 22)]);
    // Lists as elsewhere: spaces or commas, more than one line, none repeated.
    let c = Config::parse(&format!("[Advertise]\nHostname=pc\nServices=_ssh._tcp:22, _http._tcp:8080\nServices=_SSH._tcp:22 _x._udp:9\n{EXAMPLE}")).unwrap();
    assert_eq!(c.advertise[0].services.len(), 3);
    assert_eq!(c.advertise[0].services[2], ("_x._udp".to_string(), 9));
    // Empty clears.
    let c = Config::parse(&format!("[Advertise]\nHostname=pc\nServices=_ssh._tcp:22\nServices=\n{EXAMPLE}")).unwrap();
    assert!(c.advertise[0].services.is_empty());
    for bad in ["ssh", "_ssh._tcp", "_ssh._tcp:0", "_ssh._tcp:70000", "ssh._tcp:22", "_ssh._sctp:22", "_ssh:22", "_ssh._tcp.local:22"] {
        let e = ok(bad).unwrap_err().to_string();
        assert!(e.contains("line 3") && e.contains("a type and a port"), "{bad}: {e}");
    }
}

#[test]
fn advertising_can_be_limited_to_interfaces_that_are_listened_to() {
    let with = |lines: &str| Config::parse(&format!("[Advertise]\nHostname=pc\n{lines}\n[Segment]\nName=a\nInterfaces=br0,media\n"));
    let on = |lines: &str| with(lines).unwrap().advertise[0].interfaces.clone();
    assert!(on("").is_empty());
    assert_eq!(on("Interface=br0"), ["br0"]);
    assert_eq!(on("Interface=br0, media\nInterface=br0"), ["br0", "media"]);
    assert!(on("Interface=br0\nInterface=").is_empty());
    let e = with("Interface=eth9").unwrap_err().to_string();
    assert!(e.contains("eth9") && e.contains("not in any segment"), "{e}");
}

#[test]
fn advertise_ttl_defaults_to_two_minutes_and_is_bounded() {
    let ttl = |value: &str| Config::parse(&format!("[Advertise]\nHostname=pc\nTTL={value}\n{EXAMPLE}")).map(|c| c.advertise[0].ttl);
    assert_eq!(Config::parse(&format!("[Advertise]\nHostname=pc\n{EXAMPLE}")).unwrap().advertise[0].ttl, Duration::from_secs(120));
    assert_eq!(ttl("2min").unwrap(), Duration::from_secs(120));
    assert_eq!(ttl("1h").unwrap(), Duration::from_secs(3600));
    assert_eq!(ttl("10").unwrap(), Duration::from_secs(10));
    assert_eq!(ttl("24h").unwrap(), Duration::from_secs(86400));
    for bad in ["9s", "0", "", "off", "infinity", "25h", "soon", "99999999999999s"] {
        assert!(ttl(bad).is_err(), "should reject {bad:?}");
    }
}

#[test]
fn reflect_ttl_follows_the_device_unless_set_and_is_bounded() {
    let segments = |extra: &str| {
        let c = Config::parse(&format!("[Segment]\nName=a\nInterfaces=x,y\n{extra}\n[Segment]\nName=b\nInterfaces=y,z"));
        c.map(|c| (c.segments[0].reflect_ttl, c.segments[1].reflect_ttl))
    };
    let ttl = |value: &str| segments(&format!("ReflectTTL={value}")).map(|(a, _)| a);
    assert_eq!(segments("").unwrap(), (None, None));
    assert_eq!(ttl("auto").unwrap(), None);
    assert_eq!(ttl("AUTO").unwrap(), None);
    assert_eq!(ttl("2min").unwrap(), Some(Duration::from_secs(120)));
    assert_eq!(ttl("30min").unwrap(), Some(Duration::from_secs(1800)));
    assert_eq!(ttl("10").unwrap(), Some(Duration::from_secs(10)));
    assert_eq!(segments("ReflectTTL=5min\nReflectTTL=").unwrap(), (None, None), "empty resets");
    assert_eq!(segments("ReflectTTL=5min").unwrap(), (Some(Duration::from_secs(300)), None), "each its own");
    for bad in ["9s", "0", "off", "infinity", "25h", "soon", "99999999999999s"] {
        assert!(ttl(bad).is_err(), "should reject {bad:?}");
    }
    // It is independent of the advertised name's, and no longer a device setting.
    let c = Config::parse("[Advertise]\nHostname=pc\nTTL=1h\n[Segment]\nName=a\nInterfaces=x\nReflectTTL=5min").unwrap();
    assert_eq!((c.segments[0].reflect_ttl, c.advertise[0].ttl), (Some(Duration::from_secs(300)), Duration::from_secs(3600)));
    assert!(error_of(&format!("[Devices]\nReflectTTL=5min\n{EXAMPLE}")).contains("unknown setting"));
}

/// What a name or a service may be in the configuration is what the codec
/// can write: a label of 63 bytes and a name of 253, and a service type of
/// 15 characters after the underscore. A byte more is refused when it is
/// read, not when it is announced.
#[test]
fn what_the_configuration_takes_as_a_name_is_what_can_be_written() {
    let advertise = |host: &str, service: &str| {
        Config::parse(&format!("[Advertise]\nHostname={host}\nServices={service}:22\n{EXAMPLE}")).map(|c| c.advertise[0].clone())
    };
    let label = |n: usize| "a".repeat(n);
    // Four labels and `.local`: 63 + 63 + 63 + 55 + 3 dots + 6 = 253.
    let longest = format!("{}.{}.{}.{}.local", label(63), label(63), label(63), label(55));
    assert_eq!(longest.len(), 253);
    let kind = format!("_{}._tcp", label(15));
    let advertised = advertise(&longest, &kind).unwrap();
    assert_eq!((advertised.name.len(), advertised.services[0].0.len()), (253, kind.len()));

    let too_long = format!("{}.{}.{}.{}.local", label(63), label(63), label(63), label(56));
    for (host, service, why) in [
        (too_long.as_str(), kind.as_str(), "a name of 254"),
        (format!("{}.local", label(64)).as_str(), "_ssh._tcp", "a label of 64"),
        ("pc", format!("_{}._tcp", label(16)).as_str(), "a service type of 16 after the underscore"),
        ("p\0c", "_ssh._tcp", "a NUL in a name"),
        ("pc", "_s\0h._tcp", "a NUL in a type"),
    ] {
        assert!(advertise(host, service).is_err(), "{why}");
    }
}

/// The man page must document every key and a config that really parses.
#[test]
fn man_page_documents_every_key_and_its_example_parses() {
    let man = include_str!("../../man/mdnsd.conf.5");
    for key in [
        "IPv4=", "IPv6=", "Peer=", "PeerPort=", "Socket=", "MinimumLifetime=", "ProbeInterval=", "RefreshBefore=", "Hostname=", "TTL=",
        "ReflectTTL=", "MaxAddresses=", "MaxDevices=", "MaxServices=", "Name=", "Interfaces=", "Untrusted=", "ForwardQuestions=", "NeighbourAddresses=",
        "Reannounce=", "ReflectedWhen=", "ReflectedServices=",
    ] {
        assert!(man.contains(&format!(".B {key}")), "{key}");
    }
    assert!(man.contains(DEFAULT_SOCKET));

    let start = man.find("[Ipc]\nSocket=/run").expect("example in the man page");
    let example = &man[start..start + man[start..].find("\n.fi").unwrap()];
    let c = Config::parse(example).unwrap();
    assert_eq!(c.segments.len(), 3);
}

#[test]
fn parses_segments() {
    let c = Config::parse(EXAMPLE).unwrap();
    assert_eq!(
        c.segments,
        [
            seg("media_stuff", &["br0", "media"]),
            seg("IoT", &["wifi"]),
            seg("IoT to br0", &["br0", "wifi"]),
        ]
    );
    assert_eq!(c.interfaces().iter().map(|i| i.name.as_str()).collect::<Vec<_>>(), ["br0", "media", "wifi"]);
    let br0 = c.interface("br0");
    assert_eq!((br0.ipv4, br0.ipv6), (Listen::On, Listen::On));
}

#[test]
fn keys_are_case_insensitive_and_lists_flexible() {
    let c = Config::parse(
        "# c\n[Interface]\nIPv6=off\n[SEGMENT]\nNAME = 'a b'\nInterfaces=x y, z\nInterfaces=w\n",
    )
    .unwrap();
    assert_eq!(c.segments, [seg("a b", &["x", "y", "z", "w"])]);
    let x = c.interface("x");
    assert_eq!((x.ipv4, x.ipv6), (Listen::On, Listen::Off), "what is set for every interface is set for each");
}

#[test]
fn the_control_socket_is_open_to_all_unless_a_mode_says_otherwise() {
    let mode = |value: &str| Config::parse(&format!("[Ipc]\nMode={value}\n{EXAMPLE}")).map(|c| c.socket_mode);
    assert_eq!(Config::parse(EXAMPLE).unwrap().socket_mode, 0o666);
    assert_eq!(mode("0660").unwrap(), 0o660);
    assert_eq!(mode("660").unwrap(), 0o660);
    assert_eq!(mode("0o600").unwrap(), 0o600);
    for bad in ["", "rw", "0668", "1777", "0o"] {
        assert!(mode(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn ipc_socket_defaults_and_overrides() {
    let c = Config::parse(EXAMPLE).unwrap();
    assert_eq!(c.socket, DEFAULT_SOCKET);
    let c = Config::parse(&format!("[Ipc]\nSocket=\"/tmp/x.sock\"\n{EXAMPLE}")).unwrap();
    assert_eq!(c.socket, "/tmp/x.sock");
    assert!(Config::parse(&format!("[Ipc]\nSocket=\n{EXAMPLE}")).is_err());
}

#[test]
fn empty_assignment_resets_interfaces() {
    let c = Config::parse("[Segment]\nName=a\nInterfaces=x\nInterfaces=\nInterfaces=y\n").unwrap();
    assert_eq!(c.segments[0].interfaces, ["y"]);
}

#[test]
fn overlap_of_a_single_interface_is_fine() {
    assert!(Config::parse("[Segment]\nName=a\nInterfaces=x,y\n[Segment]\nName=b\nInterfaces=x,z\n").is_ok());
}

fn error_of(text: &str) -> String {
    format!("{:#}", Config::parse(text).unwrap_err())
}

#[test]
fn syntax_errors_name_their_line() {
    assert!(error_of("[Segment]\nName=a\nInterfaces\n").contains("line 3"), "no '='");
    assert!(error_of("# c\n\nInterfaces=a\n").contains("line 3"), "outside a section");
    assert!(error_of("# c\n\nInterfaces=a\n").contains("assignment outside of a section"));
    assert!(error_of("[Segment\nName=a\n").contains("line 1"), "unterminated header");
}

#[test]
fn semantic_errors_name_their_line() {
    let with = |body: &str| error_of(&format!("\n# comment\n{body}"));
    assert!(with("[Segment]\nName=a\nInterfaces=x\nBogus=1\n").contains("line 6"), "unknown key");
    assert!(with("[Interface]\nIPv4=maybe\n[Segment]\nName=a\nInterfaces=x\n").contains("line 4"), "bad value");
    assert!(with("[Segment]\nInterfaces=x\n").contains("line 3"), "segment without a name, at its header");
    assert!(with("[Advertise]\nHostname=router.lan\n").contains("line 4"), "hostname outside .local");
}

#[test]
fn a_family_is_listened_to_off_multicast_or_on_and_nothing_else() {
    let parse = |v: &str| Config::parse(&format!("[Interface]\nIPv4={v}\nIPv6=multicast\n[Segment]\nName=a\nInterfaces=x\n"));
    for (value, listen) in [("off", Listen::Off), ("multicast", Listen::Multicast), ("on", Listen::On), ("ON", Listen::On), ("\"Multicast\"", Listen::Multicast)] {
        assert_eq!(parse(value).unwrap().interface("x").ipv4, listen, "{value}");
    }
    assert!((Listen::Multicast.enabled(), Listen::Off.enabled()) == (true, false));
    assert_eq!((Listen::On.unicast(), Listen::Multicast.unicast(), Listen::Off.unicast()), (true, false, false));
    // Unset, it is on.
    let c = Config::parse("[Segment]\nName=a\nInterfaces=x\n").unwrap();
    let x = c.interface("x");
    assert_eq!((x.ipv4, x.ipv6), (Listen::On, Listen::On));
    // Both off is nothing to listen to, for an interface that is named.
    let both_off = error_of("[Interface]\nIPv4=off\nIPv6=off\n[Segment]\nName=a\nInterfaces=x\n");
    assert!(both_off.contains("both off"), "{both_off}");
    // Nothing else is one of them, and the error says which line and what was written.
    for other in ["yes", "no", "true", "1", "0", "enabled", ""] {
        let err = parse(other).unwrap_err().to_string();
        assert!(err.contains("line 2") && err.contains("IPv4= must be off, multicast or on"), "{other:?}: {err}");
    }
}

/// What is set in the section for every interface is what each has, unless its
/// own section, or one named for a pattern it matches, says otherwise, a setting
/// at a time.
#[test]
fn the_section_for_every_interface_is_what_the_others_start_from() {
    let c = Config::parse(
        "[Interface]\nIPv6=off\nMaxDevices=10\n[Interface]\nName=x\nIPv4=multicast\nIPv6=on\n[Interface]\nName=w*\nMaxDevices=20\n[Segment]\nName=a\nInterfaces=x,wlan0,y\n",
    )
    .unwrap();
    let listens = |name: &str| (c.interface(name).ipv4, c.interface(name).ipv6);
    assert_eq!(listens("x"), (Listen::Multicast, Listen::On), "its own, setting by setting");
    assert_eq!(listens("y"), (Listen::On, Listen::Off), "what is set for every one, and the default of what is not");
    assert_eq!((c.interface("y").max_devices, c.interface("wlan0").max_devices, c.interface("x").max_devices), (10, 20, 10));
    // An interface only named has nothing on if that is what it comes to.
    let off = error_of("[Interface]\nIPv6=off\n[Interface]\nName=x\nIPv4=off\n[Segment]\nName=a\nInterfaces=x\n");
    assert!(off.contains("interface x") && off.contains("both off"), "{off}");
    // Whichever is for every interface, a pattern may match one that has nothing on.
    assert!(Config::parse("[Interface]\nIPv4=off\nIPv6=off\n[Interface]\nName=x\nIPv6=on\n[Segment]\nName=a\nInterfaces=x,y*\n").is_ok());
}

/// An interface can talk to hosts alone instead of to the groups, at a port
/// that is the mDNS one unless said: the hosts of one interface, more than one
/// of them, in the families that are on.
#[test]
fn an_interface_talks_to_its_peers_alone() {
    let ip = |s: &str| -> IpAddr { s.parse().unwrap() };
    let peers = |extra: &str| {
        Config::parse(&format!("[Interface]\nName=wg0\n{extra}\n[Segment]\nName=a\nInterfaces=wg0,br0\n")).map(|c| {
            let i = c.interface("wg0");
            (i.peers, i.peer_port)
        })
    };
    assert_eq!(peers("").unwrap(), (vec![], MDNS_PORT));
    assert_eq!(peers("Peer=10.8.0.2").unwrap(), (vec![ip("10.8.0.2")], MDNS_PORT));
    assert_eq!(peers("Peer=10.8.0.2, fd00::2\nPeer=10.8.0.3\nPeerPort=5354").unwrap(), (vec![ip("10.8.0.2"), ip("fd00::2"), ip("10.8.0.3")], 5354));
    assert_eq!(peers("Peer=10.8.0.2\nPeer=").unwrap().0, Vec::<IpAddr>::new(), "empty resets");
    for (bad, says) in [
        ("Peer=host.example", "must be addresses"),
        ("Peer=224.0.0.251", "must be the address of a host"),
        ("Peer=0.0.0.0", "must be the address of a host"),
        ("Peer=10.8.0.2 10.8.0.2", "twice"),
        ("Peer=10.8.0.2:5353", "must be addresses"),
        ("PeerPort=0", "must be a port"),
        ("PeerPort=http", "must be a port"),
        ("Peer=10.8.0.2\nIPv4=off", "family it has off"),
        ("Peer=fd00::2\nIPv6=off", "family it has off"),
    ] {
        let err = peers(bad).unwrap_err().to_string();
        assert!(err.contains(says), "{bad:?}: {err}");
    }
    // With a peer, the groups are not used: both families off is no matter, if the peer's is on.
    assert!(peers("Peer=10.8.0.2\nIPv6=off").is_ok());
    // The peers are of one interface.
    let every = error_of("[Interface]\nPeer=10.8.0.2\n[Segment]\nName=a\nInterfaces=x\n");
    assert!(every.contains("no Name="), "{every}");
    let pattern = error_of("[Interface]\nName=wg*\nPeer=10.8.0.2\n[Segment]\nName=a\nInterfaces=wg0\n");
    assert!(pattern.contains("not a pattern"), "{pattern}");
    // The port can be set for all.
    let c = Config::parse("[Interface]\nPeerPort=5354\n[Segment]\nName=a\nInterfaces=x\n").unwrap();
    assert_eq!(c.interface("x").peer_port, 5354);
}

#[test]
fn comments_blank_lines_crlf_and_continuations_are_fine() {
    // Comments and blank lines inside a section, and Windows line endings.
    let c = Config::parse("[Segment]\r\n# c\r\nName=a\r\n\r\n; d\r\nInterfaces=x,y\r\n").unwrap();
    assert_eq!(c.segments, [seg("a", &["x", "y"])]);
    // A line ending in a backslash continues on the next, as in unit files.
    let c = Config::parse("[Segment]\nName=a\nInterfaces=x \\\n    y,z\n").unwrap();
    assert_eq!(c.segments[0].interfaces, ["x", "y", "z"]);
    // A value may contain an equals sign.
    let c = Config::parse("[Segment]\nName=a=b\nInterfaces=x\n").unwrap();
    assert_eq!(c.segments[0].name, "a=b");
}

/// Each segment forwards every question unless it says otherwise.
#[test]
fn forwarding_questions_is_set_per_segment_and_always_by_default() {
    let forward = |extra: &str| {
        let c = Config::parse(&format!("[Segment]\nName=a\nInterfaces=x,y\n{extra}\n[Segment]\nName=b\nInterfaces=z")).unwrap();
        (c.segments[0].forward, c.segments[1].forward)
    };
    assert_eq!(forward(""), (Forward::Always, Forward::Always));
    assert_eq!(forward("ForwardQuestions=Unknown"), (Forward::Unknown, Forward::Always));
    assert_eq!(forward("ForwardQuestions=never"), (Forward::Never, Forward::Always));
    assert_eq!(forward("ForwardQuestions=never\nForwardQuestions="), (Forward::Always, Forward::Always));
    let bad = error_of("[Segment]\nName=a\nInterfaces=x\nForwardQuestions=sometimes");
    assert!(bad.contains("line 4") && bad.contains("ForwardQuestions"), "{bad}");
}

/// A config is read from its file, and an error says which file, and,
/// for what is in it, which line.
#[test]
fn a_config_is_loaded_from_its_file() {
    std::fs::create_dir_all("target").unwrap();
    let path = format!("target/config-test-{}.conf", std::process::id());
    std::fs::write(&path, "[Segment]\nName=lan\nInterfaces=eth0\n").unwrap();
    assert_eq!(Config::load(&path).unwrap().segments[0].interfaces, ["eth0"]);

    std::fs::write(&path, "[Segment]\nName=lan\nInterfaces=eth0\nBogus=1\n").unwrap();
    let err = format!("{:#}", Config::load(&path).unwrap_err());
    assert!(err.contains(&format!("parsing {path}")) && err.contains("line 4"), "{err}");
    std::fs::remove_file(&path).unwrap();

    let err = format!("{:#}", Config::load(&path).unwrap_err());
    assert!(err.contains(&format!("reading {path}")), "{err}");
}

/// A hostname to advertise is at most 253 bytes, as a DNS name is, even
/// with every label short enough.
#[test]
fn an_advertised_hostname_is_not_too_long() {
    let label = "a".repeat(63);
    let long = format!("{label}.{label}.{label}.{label}.local");
    let err = error_of(&format!("[Advertise]\nHostname={long}\n{EXAMPLE}"));
    assert!(err.contains("line 2") && err.contains("is too long"), "{err}");
    let fits = format!("{label}.{label}.{label}.{}.local", "a".repeat(52));
    assert_eq!(fits.len(), 250);
    assert!(Config::parse(&format!("[Advertise]\nHostname={fits}\n{EXAMPLE}")).is_ok());
}

/// Each segment says what a device must have to be reflected: all of an
/// address, a hostname and a service unless it names fewer.
#[test]
fn segments_choose_what_a_device_needs_to_be_reflected() {
    let when = |extra: &str| {
        let c = Config::parse(&format!("[Segment]\nName=a\nInterfaces=x,y\n{extra}\n[Segment]\nName=b\nInterfaces=z")).unwrap();
        (c.segments[0].reflected_when.clone(), c.segments[1].reflected_when.clone())
    };
    let all = ReflectedWhen::default();
    assert_eq!(when(""), (all.clone(), all.clone()));
    assert_eq!(when("ReflectedWhen=address,hostname,service"), (all.clone(), all.clone()));
    let named = ReflectedWhen { service: false, ..all.clone() };
    assert_eq!(when("ReflectedWhen=address, Hostname"), (named.clone(), all.clone()));
    let nameless = ReflectedWhen { address: false, ..all.clone() };
    assert_eq!(when("ReflectedWhen=hostname,service"), (nameless.clone(), all.clone()));
    assert_eq!(when("reflectedwhen=address hostname"), (named.clone(), all.clone()));
    assert_eq!(when("ReflectedWhen=hostname\nReflectedWhen="), (all.clone(), all.clone()));
    for (bad, message) in [("name", "address, hostname or service"), ("address,service", "must include hostname")] {
        let err = error_of(&format!("[Segment]\nName=a\nInterfaces=x\nReflectedWhen={bad}"));
        assert!(err.contains("line 4") && err.contains(message), "{err}");
    }
}

/// `ReflectedServices=` names the service types to reflect, or to keep out
/// (which wins), whatever the case and whether or not `.local` is there.
#[test]
fn segments_choose_which_service_types_are_reflected() {
    let kinds = |extra: &str| {
        Config::parse(&format!("[Segment]\nName=a\nInterfaces=x,y\n{extra}")).unwrap().segments[0].advertise.clone()
    };
    assert!(kinds("").is_all());
    let only = kinds("ReflectedServices=_IPP._tcp, _airplay._tcp.local.");
    assert!(only.allows("_ipp._tcp.local") && only.allows("_airplay._tcp.local") && !only.allows("_ssh._tcp.local"));
    let not = kinds("ReflectedServices=!_ssh._tcp");
    assert!(not.allows("_ipp._tcp.local") && !not.allows("_SSH._tcp.local"));
    let both = kinds("ReflectedServices=_ssh._tcp,_ipp._tcp,!_ssh._tcp");
    assert!(both.allows("_ipp._tcp.local") && !both.allows("_ssh._tcp.local"));
    assert_eq!(both.words(), ["_ipp._tcp", "_ssh._tcp", "!_ssh._tcp"]);
    // Repeated, it adds to what is named; empty, it resets; ReflectedWhen= leaves it.
    assert!(kinds("ReflectedServices=_ipp._tcp\nReflectedServices=").is_all());
    assert!(!kinds("ReflectedServices=_ipp._tcp\nReflectedWhen=hostname,service").allows("_ssh._tcp.local"));
    assert!(!kinds("ReflectedWhen=hostname,service\nReflectedServices=_ipp._tcp").allows("_ssh._tcp.local"));
    let err = error_of("[Segment]\nName=a\nInterfaces=x\nReflectedWhen=hostname,address\nReflectedServices=_ipp._tcp");
    assert!(err.contains("without enabling service filtering"), "{err}");
    assert!(Config::parse("[Segment]\nName=a\nInterfaces=x\nReflectedWhen=hostname,address").is_ok());
    for bad in ["_ipp", "ipp._tcp", "_ipp._sctp", "_*._tcp", "!", "_a.b._tcp"] {
        let err = error_of(&format!("[Segment]\nName=a\nInterfaces=x\nReflectedServices={bad}"));
        assert!(err.contains("line 4") && err.contains("a service type"), "{bad}: {err}");
    }
}

/// Each segment says which addresses from the neighbour table it
/// reflects; of families a device announced a link-local address of,
/// unless it says otherwise.
#[test]
fn segments_choose_which_neighbour_addresses_to_reflect() {
    let segments = |extra: &str| {
        let c = Config::parse(&format!("[Segment]\nName=a\nInterfaces=x,y\n{extra}\n[Segment]\nName=b\nInterfaces=z")).unwrap();
        (c.segments[0].advertise.neighbours, c.segments[1].advertise.neighbours)
    };
    assert_eq!(segments(""), (Neighbours::LinkLocal, Neighbours::LinkLocal));
    assert_eq!(segments("NeighbourAddresses=always"), (Neighbours::Always, Neighbours::LinkLocal));
    assert_eq!(segments("NeighbourAddresses=Never"), (Neighbours::Never, Neighbours::LinkLocal));
    assert_eq!(segments("neighbouraddresses=never\nNeighbourAddresses="), (Neighbours::LinkLocal, Neighbours::LinkLocal));
    for bad in ["sometimes", "yes", "no"] {
        let err = error_of(&format!("[Segment]\nName=a\nInterfaces=x\nNeighbourAddresses={bad}"));
        assert!(err.contains("line 4") && err.contains("always, link-local or never"), "{err}");
    }
}

/// Unchanged devices are not announced again unless a segment says so,
/// and then on each of its interfaces, shared or not.
#[test]
fn a_segment_can_reannounce_unchanged_devices() {
    let config = |extra: &str| {
        Config::parse(&format!("[Segment]\nName=a\nInterfaces=x,y\n{extra}\n[Segment]\nName=b\nInterfaces=y,z")).unwrap()
    };
    let on = |c: &Config| ["x", "y", "z"].map(|i| c.interface(i).reannounce);
    assert_eq!(on(&config("")), [false, false, false]);
    assert_eq!(on(&config("Reannounce=yes")), [true, true, false]);
    assert_eq!(on(&config("reannounce=TRUE")), [true, true, false]);
    assert_eq!(on(&config("Reannounce=no")), [false, false, false]);
    assert_eq!(on(&config("Reannounce=yes\nReannounce=")), [false, false, false], "empty resets");
    let err = error_of("[Segment]\nName=a\nInterfaces=x\nReannounce=sometimes");
    assert!(err.contains("line 4"), "{err}");
}

#[test]
fn the_probe_interval_is_off_by_default_and_takes_systemd_time_spans() {
    assert_eq!(Config::parse(EXAMPLE).unwrap().interface("br0").probe_interval, None);

    let with = |v: &str| Config::parse(&format!("[Interface]\nProbeInterval={v}\n{EXAMPLE}"));
    let secs = |v: &str| with(v).unwrap().interface("br0").probe_interval.map(|d| d.as_secs());
    assert_eq!(secs("4min"), Some(240));
    assert_eq!(secs("30s"), Some(30));
    assert_eq!(secs("1h"), Some(3600));
    assert_eq!(secs("1h 30min"), Some(5400));
    assert_eq!(secs("90"), Some(90), "a bare number is seconds");
    assert_eq!(secs("\"10min\""), Some(600));
    for never in ["0", "0s", "0min", "off", "OFF", "infinity"] {
        assert_eq!(secs(never), None, "{never}");
    }
}

#[test]
fn bad_probe_intervals_are_rejected_with_their_line() {
    let with = |v: &str| error_of(&format!("[Interface]\nProbeInterval={v}\n{EXAMPLE}"));
    assert!(with("soon").contains("line 2") && with("soon").contains("invalid ProbeInterval"));
    assert!(with("5s").contains("at least 10 seconds"));
    assert!(with("").contains("line 2"), "an empty value is not a time span");
    assert!(with("3 fortnights").contains("invalid"));
}

#[test]
fn the_probe_settings_are_said_to_be_of_interface_now() {
    for (setting, key) in [("ProbeInterval=4min", "ProbeInterval="), ("Interval=4min", "ProbeInterval="), ("RefreshBefore=30s", "RefreshBefore=")] {
        let err = error_of(&format!("[Probe]\n{setting}\n{EXAMPLE}"));
        assert!(err.contains("line 2") && err.contains(key) && err.contains("[Interface]"), "{setting}: {err}");
    }
}

#[test]
fn each_interface_is_settled_once_with_its_defaults_filled_in() {
    let c = Config::parse(EXAMPLE).unwrap();
    assert_eq!(c.interfaces().iter().map(|i| i.name.as_str()).collect::<Vec<_>>(), ["br0", "media", "wifi"]);
    assert_eq!(
        c.interfaces()[0],
        Interface {
            name: "br0".into(),
            min_lifetime: DEFAULT_MIN_LIFETIME,
            refresh_before: Some(DEFAULT_REFRESH_BEFORE),
            probe_interval: None,
            max_addrs: DEFAULT_MAX_ADDRS,
            max_devices: DEFAULT_MAX_DEVICES,
            max_services: DEFAULT_MAX_SERVICES,
            ipv4: Listen::On,
            ipv6: Listen::On,
            peers: Vec::new(),
            peer_port: MDNS_PORT,
            reannounce: false,
        }
    );
}

#[test]
fn an_interface_probes_and_refreshes_as_its_own_section_says_or_else_the_one_for_all() {
    let c = Config::parse(&format!(
        "{EXAMPLE}\n[Interface]\nProbeInterval=4min\nRefreshBefore=1min\n[Interface]\nName=wifi\nProbeInterval=off\nRefreshBefore=off\n[Interface]\nName=media\nProbeInterval=1min"
    ))
    .unwrap();
    let probe = |i: &str| c.interface(i).probe_interval.map(|d| d.as_secs());
    let refresh = |i: &str| c.interface(i).refresh_before.map(|d| d.as_secs());
    assert_eq!((probe("br0"), probe("media"), probe("wifi")), (Some(240), Some(60), None));
    assert_eq!((refresh("br0"), refresh("media"), refresh("wifi")), (Some(60), Some(60), None));
    assert_eq!(refresh("br0"), Some(60), "an interface with no section of its own has the one for all");
    let elsewhere = c.interface("elsewhere");
    assert_eq!((elsewhere.name.as_str(), elsewhere.refresh_before, elsewhere.probe_interval), ("elsewhere", Some(Duration::from_secs(60)), None), "one that no segment has is settled all the same");
}

/// Three segments over br0: one that follows its interfaces', one with its
/// own interval, and one that turns probing off for itself.
fn probing(probe: &str) -> Config {
    Config::parse(&format!(
        "{probe}
[Segment]
Name=default
Interfaces=br0,lan
[Segment]
Name=often
Interfaces=br0,media
ProbeInterval=1min
[Segment]
Name=quiet
Interfaces=wifi,guest
ProbeInterval=off
"
    ))
    .unwrap()
}

#[test]
fn a_segment_probes_as_often_as_it_says_or_else_as_its_interfaces_say() {
    let c = probing("[Interface]\nProbeInterval=4min");
    let secs = |iface: &str| c.interface(iface).probe_interval.map(|d| d.as_secs());
    assert_eq!(c.segments.iter().map(|s| s.probe_interval).collect::<Vec<_>>(), [
        None,
        Some(Some(Duration::from_secs(60))),
        Some(None)
    ]);
    assert_eq!(secs("lan"), Some(240), "from [Interface]");
    assert_eq!(secs("media"), Some(60));
    assert_eq!(secs("br0"), Some(60), "in two segments: the more frequent one");
    assert_eq!(secs("wifi"), None, "off for its only segment, whatever [Interface] says");
    assert_eq!(secs("nonesuch"), None);

    // Without a setting of the interface, only the segment that asks is probed.
    let c = probing("");
    assert_eq!(c.interface("lan").probe_interval, None);
    assert_eq!(c.interface("br0").probe_interval, Some(Duration::from_secs(60)));
}

#[test]
fn a_segment_probe_interval_is_checked_like_the_global_one() {
    let with = |v: &str| error_of(&format!("[Segment]\nName=x\nInterfaces=a\nProbeInterval={v}\n"));
    assert!(with("5s").contains("line 4") && with("5s").contains("ProbeInterval= must be at least 10 seconds"));
    assert!(with("soon").contains("invalid ProbeInterval"));
    // The last one counts, and 0 is off.
    let c = Config::parse("[Segment]\nName=x\nInterfaces=a\nProbeInterval=1min\nProbeInterval=0\n").unwrap();
    assert_eq!(c.segments[0].probe_interval, Some(None));
}

#[test]
fn refreshing_before_expiry_defaults_on_and_takes_systemd_time_spans() {
    assert_eq!(Config::parse(EXAMPLE).unwrap().interface("br0").refresh_before, Some(DEFAULT_REFRESH_BEFORE));

    let with = |v: &str| Config::parse(&format!("[Interface]\nRefreshBefore={v}\n{EXAMPLE}"));
    let secs = |v: &str| with(v).unwrap().interface("br0").refresh_before.map(|d| d.as_secs());
    assert_eq!(secs("1min"), Some(60));
    assert_eq!(secs("30s"), Some(30), "the minimum is allowed");
    assert_eq!(secs("45s"), Some(45));
    assert_eq!(secs("10min"), Some(600), "longer than the idle floor is allowed");
    for never in ["0", "off", "infinity"] {
        assert_eq!(secs(never), None, "{never}");
    }
    // It is independent of the periodic probe, in both directions.
    let both = Config::parse(&format!("[Interface]\nProbeInterval=off\nRefreshBefore=2min\n{EXAMPLE}")).unwrap();
    assert_eq!((both.interface("br0").probe_interval, both.interface("br0").refresh_before), (None, Some(Duration::from_secs(120))));

    let err = |v: &str| error_of(&format!("[Interface]\nRefreshBefore={v}\n{EXAMPLE}"));
    assert!(err("20s").contains("RefreshBefore= must be at least 30 seconds"), "{}", err("20s"));
    assert!(err("soon").contains("line 2") && err("soon").contains("invalid RefreshBefore"));
}

#[test]
fn max_addresses_defaults_to_eight_and_has_no_upper_bound() {
    assert_eq!(Config::parse(EXAMPLE).unwrap().interface("br0").max_addrs, DEFAULT_MAX_ADDRS);
    let with = |v: &str| Config::parse(&format!("{EXAMPLE}\n[Interface]\nMaxAddresses={v}"));
    let max = |v: &str| with(v).unwrap().interface("br0").max_addrs;
    assert_eq!(max("2"), 2);
    assert_eq!(max("100000"), 100_000);
    assert_eq!(max("infinity"), usize::MAX, "no limit at all");
    assert_eq!(max("Infinity"), usize::MAX);
    for bad in ["0", "-1", "many", ""] {
        let err = error_of(&format!("{EXAMPLE}\n[Interface]\nMaxAddresses={bad}"));
        assert!(err.contains("MaxAddresses="), "{bad:?}: {err}");
    }
}

#[test]
fn max_devices_and_services_default_and_are_an_interfaces_setting_like_max_addresses() {
    assert_eq!(Config::parse(EXAMPLE).unwrap().interface("br0").max_devices, DEFAULT_MAX_DEVICES);
    assert_eq!(Config::parse(EXAMPLE).unwrap().interface("br0").max_services, DEFAULT_MAX_SERVICES);
    let c = Config::parse(&format!("{EXAMPLE}\n[Interface]\nMaxServices=200\n[Interface]\nName=wifi\nMaxServices=infinity")).unwrap();
    assert_eq!((c.interface("br0").max_services, c.interface("wifi").max_services), (200, usize::MAX));
    for bad in ["0", "many", ""] {
        let err = error_of(&format!("{EXAMPLE}\n[Interface]\nMaxServices={bad}"));
        assert!(err.contains("MaxServices="), "{bad:?}: {err}");
    }
    let c = Config::parse(&format!("{EXAMPLE}\n[Interface]\nMaxDevices=5000\n[Interface]\nName=wifi\nMaxDevices=infinity")).unwrap();
    assert_eq!((c.interface("br0").max_devices, c.interface("wifi").max_devices), (5000, usize::MAX));
    for bad in ["0", "-1", "many", ""] {
        let err = error_of(&format!("{EXAMPLE}\n[Interface]\nMaxDevices={bad}"));
        assert!(err.contains("MaxDevices="), "{bad:?}: {err}");
    }
}

#[test]
fn an_interface_is_set_its_own_minimum_lifetime_whatever_segments_it_is_in() {
    let c = Config::parse(&format!("{EXAMPLE}\n[Interface]\nName=wifi\nMinimumLifetime=1h\n[Interface]\nName=media\nMinimumLifetime=0"))
        .unwrap();
    let secs = |i: &str| c.interface(i).min_lifetime.as_secs();
    assert_eq!((secs("wifi"), secs("media")), (3600, 0), "wifi is in two segments");
    assert_eq!(secs("br0"), 60, "an interface with no section has the default");
    assert_eq!(secs("elsewhere"), 60, "and one that no segment has");
}

#[test]
fn an_interface_section_without_a_name_is_for_every_interface_that_has_none_of_its_own() {
    let c = Config::parse(&format!(
        "{EXAMPLE}\n[Interface]\nMinimumLifetime=1h\nMaxAddresses=4\n[Interface]\nName=wifi\nMinimumLifetime=30s"
    ))
    .unwrap();
    let (secs, max) = (|i: &str| c.interface(i).min_lifetime.as_secs(), |i: &str| c.interface(i).max_addrs);
    assert_eq!((secs("br0"), secs("media"), secs("wifi")), (3600, 3600, 30));
    // A setting the interface's own section leaves out comes from the one for all.
    assert_eq!((max("br0"), max("wifi")), (4, 4));
    // Whichever comes first.
    let c = Config::parse(&format!("{EXAMPLE}\n[Interface]\nName=wifi\nMaxAddresses=2\n[Interface]\nMaxAddresses=4")).unwrap();
    assert_eq!((c.interface("wifi").max_addrs, c.interface("br0").max_addrs), (2, 4));
    // An empty Name= names nothing, so the section is for every interface.
    assert!(Config::parse(&format!("{EXAMPLE}\n[Interface]\nName=\nMaxAddresses=3")).is_ok(), "an empty Name= is no name");
}

#[test]
fn an_interface_section_names_an_interface_of_a_segment_once() {
    let err = |text: &str| error_of(&format!("{EXAMPLE}\n{text}"));
    assert!(err("[Interface]\nMaxAddresses=2\n[Interface]\nMinimumLifetime=1h").contains("only one can be for every interface"));
    assert!(err("[Interface]\nName=eth9\nMinimumLifetime=1h").contains("not in the Interfaces= of any segment"));
    assert!(err("[Interface]\nName=br0\n[Interface]\nName=br0").contains("two [Interface] sections are named br0"));
    assert!(err("[Interface]\nName=br0\nBogus=1").contains("unknown setting"));
}

#[test]
fn the_settings_that_were_a_devices_are_now_an_interfaces() {
    for key in ["MinimumLifetime=5min", "MaxAddresses=4"] {
        let err = error_of(&format!("[Devices]\n{key}\n{EXAMPLE}"));
        assert!(err.contains("line 2") && err.contains("now a setting of [Interface]"), "{err}");
    }
}

#[test]
fn the_minimum_lifetime_defaults_to_a_minute_and_takes_systemd_time_spans() {
    assert_eq!(Config::parse(EXAMPLE).unwrap().interface("br0").min_lifetime, Duration::from_secs(60));

    let with = |v: &str| Config::parse(&format!("{EXAMPLE}\n[Interface]\nName=br0\nMinimumLifetime={v}"));
    let secs = |v: &str| with(v).unwrap().interface("br0").min_lifetime.as_secs();
    assert_eq!(secs("5min"), 300);
    assert_eq!(secs("90s"), 90);
    assert_eq!(secs("1h"), 3600);
    assert_eq!(secs("1d"), 86400, "the longest allowed");
    assert_eq!(secs("0"), 0, "zero means no minimum: a device lives for exactly its TTL");
    assert_eq!(secs("0s"), 0);

    let err = |v: &str| error_of(&format!("{EXAMPLE}\n[Interface]\nName=br0\nMinimumLifetime={v}"));
    assert!(err("2d").contains("at most 24 hours"));
    // A value that parses but would overflow the clock when added to "now".
    assert!(err("99999999999999s").contains("at most 24 hours"), "{}", err("99999999999999s"));
    assert!(err("18446744073709551615s").contains("at most 24 hours"));
    assert!(err("99999999999y").contains("at most 24 hours"), "{}", err("99999999999y"));
    assert!(err("5fortnights").contains("invalid MinimumLifetime"), "an unknown unit is just invalid");
    assert_eq!(secs("1.5h"), 5400, "a fraction, as systemd takes it");
    assert!(err("soon").contains("invalid MinimumLifetime"));
    assert!(err("").contains("MinimumLifetime"), "an empty value is not a time span");
    // Unlike the probe settings, `off` and `infinity` are not "never": a device must be able to expire.
    assert!(err("off").contains("invalid MinimumLifetime"));
    assert!(err("infinity").contains("invalid MinimumLifetime"));
}

#[test]
fn rejects_bad_input() {
    let bad = [
        ("", "no segments"),
        ("[Segment]\nInterfaces=a\n", "missing name"),
        ("[Segment]\nName=a\n", "missing interfaces"),
        ("[Segment]\nName=a\nInterfaces=x\n[Segment]\nName=a\nInterfaces=y\n", "duplicate name"),
        ("[Segment]\nName=a\nInterfaces=x,x\n", "duplicate interface"),
        (
            "[Segment]\nName=a\nInterfaces=x,y\n[Segment]\nName=b\nInterfaces=y,x,z\n",
            "two segments reflect the same pair",
        ),
        ("[Interface]\nIPv4=off\nIPv6=off\n[Segment]\nName=a\nInterfaces=x\n", "no families"),
        ("[Segment]\nName=a\nInterfaces=x\nBogus=1\n", "unknown key"),
        ("[Other]\nName=a\n", "unknown section"),
        ("Name=a\n", "outside a section"),
        ("[Segment]\nName a\n", "not an assignment"),
    ];
    for (text, why) in bad {
        assert!(Config::parse(text).is_err(), "should reject: {why}");
    }
}

fn entries(text: &str) -> Vec<(String, String, String, usize)> {
    let unit = parse_unit(text).unwrap();
    unit.sections.iter().flat_map(|s| s.entries.iter().map(|e| (s.name.clone(), e.key.clone(), e.value.clone(), e.line))).collect()
}

#[test]
fn takes_sections_and_assignments_apart() {
    let text = "# about\n\n[Listen]\nIPv4 = yes\n; no\n[Segment]\r\nName=a=b\r\nInterfaces=\n";
    let unit = parse_unit(text).unwrap();
    assert_eq!(unit.sections.iter().map(|s| (s.name.as_str(), s.line)).collect::<Vec<_>>(), [("Listen", 3), ("Segment", 6)]);
    assert_eq!(
        entries(text),
        [
            ("Listen".into(), "IPv4".into(), "yes".into(), 4),
            ("Segment".into(), "Name".into(), "a=b".into(), 7),
            ("Segment".into(), "Interfaces".into(), "".into(), 8),
        ]
    );
    assert_eq!(parse_unit("").unwrap(), Unit::default());
}

#[test]
fn a_backslash_continues_a_line() {
    assert_eq!(entries("[S]\nK=x \\\n    y,z\nL=1\n")[0].2, "x     y,z");
    assert_eq!(entries("[S]\nK=x\\\ny\n")[0].2, "x y", "a space in its place");
    assert_eq!(entries("[S]\nK=x\\\ny\nL=1\n")[1].3, 4, "lines still counted");
    assert_eq!(entries("[S]\nK=x\\")[0].2, "x", "at the very end");
}

#[test]
fn values_may_be_quoted_and_booleans_are_systemds() {
    let entry = |value: &str| Entry { key: "K".into(), value: value.into(), line: 1 };
    assert_eq!(entry(" \"/tmp/x y\" ").unquoted(), "/tmp/x y");
    assert_eq!(entry("'a'").unquoted(), "a");
    assert_eq!(entry("\"a'").unquoted(), "\"a'", "not a matching pair");
    assert_eq!(entry("\"").unquoted(), "\"");
    for yes in ["1", "yes", "TRUE", "On", "\"on\""] {
        assert_eq!(entry(yes).as_bool(), Some(true), "{yes}");
    }
    for no in ["0", "no", "False", "OFF"] {
        assert_eq!(entry(no).as_bool(), Some(false), "{no}");
    }
    assert_eq!(entry("enabled").as_bool(), None);
    assert_eq!(entry("").as_bool(), None);
}

#[test]
fn says_what_is_wrong_and_where() {
    let error = |text: &str| parse_unit(text).unwrap_err().to_string();
    assert_eq!(error("# c\n\nName=a\n"), "line 3: assignment outside of a section");
    assert_eq!(error("[Segment]\nName a\n"), "line 2: not an assignment (Key=Value)");
    assert_eq!(error("[Segment\nName=a\n"), "line 1: a section header without its closing ]");
    assert_eq!(error("[S]\n=a\n"), "line 2: an assignment without a key");
}

fn ms(s: &str) -> u128 {
    parse_timespan(s).unwrap_or_else(|e| panic!("{s:?}: {e}")).as_millis()
}

#[test]
fn whole_numbers_with_and_without_units_add_up() {
    assert_eq!(ms("30"), 30_000);
    assert_eq!(ms("2min"), 120_000);
    assert_eq!(ms("1h 30min"), 5_400_000);
    assert_eq!(ms("2min30s"), 150_000);
    assert_eq!(ms(" 5 min  10 "), 310_000);
    assert_eq!(ms("1d"), 86_400_000);
    assert_eq!(ms("1w"), 604_800_000);
    assert_eq!(ms("1m"), 60_000, "minutes");
    assert_eq!(ms("1M"), 2_629_800_000, "months");
    assert_eq!(ms("1y"), 31_557_600_000);
    assert_eq!(parse_timespan("250us"), Ok(Duration::from_micros(250)));
    assert_eq!(parse_timespan("3µs 7ns"), Ok(Duration::from_nanos(3_007)));
}

#[test]
fn numbers_may_have_a_fraction() {
    assert_eq!(ms("1.5s"), 1_500);
    assert_eq!(ms("10.5"), 10_500);
    assert_eq!(ms("1.5h"), 5_400_000);
    assert_eq!(ms("0.25min"), 15_000);
    assert_eq!(ms(".5s"), 500);
    assert_eq!(ms("5."), 5_000);
    assert_eq!(ms("1.5min 30.25s"), 120_250);
    assert_eq!(parse_timespan("1.5us"), Ok(Duration::from_nanos(1_500)));
    // Finer than a nanosecond is dropped.
    assert_eq!(parse_timespan("1.123456789123s"), Ok(Duration::from_nanos(1_123_456_789)));
}

#[test]
fn nothing_adds_up_to_zero() {
    assert_eq!(parse_timespan("0"), Ok(Duration::ZERO));
    assert_eq!(parse_timespan("0s 0.0min"), Ok(Duration::ZERO));
}

#[test]
fn what_is_not_a_time_span_is_refused() {
    assert_eq!(parse_timespan(""), Err(TimespanError::Empty));
    assert_eq!(parse_timespan("  "), Err(TimespanError::Empty));
    assert_eq!(parse_timespan("soon"), Err(TimespanError::Number("soon".into())));
    assert_eq!(parse_timespan("-5s"), Err(TimespanError::Number("-5s".into())));
    assert_eq!(parse_timespan("."), Err(TimespanError::Number(".".into())));
    assert_eq!(parse_timespan("5 s s"), Err(TimespanError::Number("s".into())));
    assert_eq!(parse_timespan("5fortnights"), Err(TimespanError::Unit("fortnights".into())));
    assert_eq!(parse_timespan("5MIN"), Err(TimespanError::Unit("MIN".into())));
    assert_eq!(parse_timespan("5s$"), Err(TimespanError::Unit("s$".into())));
    assert_eq!(parse_timespan("1.2.3s"), Err(TimespanError::Number(".3s".into())));
    assert_eq!(parse_timespan("99999999999999999999999999999999999999999"), Err(TimespanError::TooLong));
    assert_eq!(parse_timespan("999999999999999999999y"), Err(TimespanError::TooLong));
}

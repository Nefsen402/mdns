"""The scenarios. See e2e.py for how to run them."""
import os
import subprocess
import time
import unittest

from lab import A, AAAA, PTR, SRV, Lab, announcement, a, aaaa, query, response, sh, ptr, srv, until

BINARY = os.environ["E2E_DAEMON"]
CTL = os.environ.get("E2E_CTL")
SLOW = bool(os.environ.get("E2E_SLOW"))
LOGS = os.environ.get("E2E_LOGS")

PROBE = ("_services._dns-sd._udp.local", PTR)


def conf(body, ipv6=False):
    """A config, with IPv6 left out unless wanted: most scenarios are of IPv4."""
    return ("" if ipv6 else "[Listen]\nIPv6=off\n") + body


def alive(owner, rtype=None, data=None):
    """A condition on what is heard: it has such a record, not a goodbye."""
    return lambda h: h.message.response and h.message.has(owner, rtype, data, alive=True)


def goodbye(owner, rtype=None, data=None):
    return lambda h: h.message.response and h.message.has(owner, rtype, data, goodbye=True)


def asks(owner, rtype=None, src=None):
    return lambda h: not h.message.response and h.message.asks(owner, rtype) and (src is None or h.src == src)


class Case(unittest.TestCase):
    def setUp(self):
        self.lab = Lab(BINARY, CTL)

    def tearDown(self):
        if LOGS:
            path = os.path.join(LOGS, self.id().split(".", 1)[1] + ".log")
            with open(path, "w") as f:
                for i, d in enumerate(self.lab.daemons):
                    f.write(f"== daemon {i}\n" + "\n".join(d.log()) + "\n")
        self.lab.close()

    def two_links(self):
        return self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24"), self.lab.link("rb", "10.9.2.1/24", "10.9.2.2/24")

    def logs(self, d):
        return "\n".join(d.log())


class Reflecting(Case):
    def test_a_device_is_reflected_to_the_other_interface_and_withdrawn_when_the_daemon_stops(self):
        la, lb = self.two_links()
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=ra,rb\n"))
        ha, hb = la.hearer(), lb.hearer()
        # It asks what is there when it starts.
        self.assertTrue(ha.wait(asks(*PROBE)), self.logs(d))

        tv = la.device("10.9.1.50")
        tv.multicast(announcement("tv", "10.9.1.50", "TV"))
        self.assertTrue(hb.wait(alive("tv.local", A, "10.9.1.50")), self.logs(d))
        self.assertTrue(hb.wait(alive("_http._tcp.local", PTR, "TV._http._tcp.local")), "its service goes with it")
        self.assertTrue(hb.wait(alive("TV._http._tcp.local", SRV, "80 tv.local")))
        # Not back to where it is.
        self.assertTrue(ha.none(lambda h: h.src == la.router_addr and h.message.has("tv.local", A)), "reflected back")

        listed = d.host("s", "tv.local")
        self.assertEqual([x["addresses"] for x in listed], [["10.9.1.50"]], listed)
        self.assertEqual(listed[0]["interface"], "ra")

        self.assertEqual(d.stop(), 0, self.logs(d))
        self.assertTrue(hb.wait(goodbye("tv.local", A, "10.9.1.50")), "withdrawn from the other interface on shutdown")

    def test_a_device_that_says_goodbye_is_forgotten_and_withdrawn(self):
        la, lb = self.two_links()
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=ra,rb\n"))
        hb = lb.hearer()
        tv = la.device("10.9.1.50")
        tv.multicast(announcement("tv", "10.9.1.50", "TV"))
        self.assertTrue(hb.wait(alive("tv.local", A)))
        tv.multicast(response(a("tv.local", "10.9.1.50", ttl=0)))
        self.assertTrue(hb.wait(goodbye("tv.local", A, "10.9.1.50")), self.logs(d))
        self.assertTrue(until(lambda: not d.host("s", "tv.local"), 3), d.devices("s"))

    def test_an_untrusted_interface_is_told_nothing_but_is_heard(self):
        la, lb = self.two_links()
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=ra,rb\nUntrusted=rb\n"))
        ha, hb = la.hearer(), lb.hearer()
        lan, iot = la.device("10.9.1.50"), lb.device("10.9.2.50")
        lan.multicast(announcement("laptop", "10.9.1.50", "Laptop"))
        iot.multicast(announcement("plug", "10.9.2.50", "Plug"))
        self.assertTrue(ha.wait(alive("plug.local", A, "10.9.2.50")), "what the untrusted one has is reflected out of it\n" + self.logs(d))
        self.assertTrue(until(lambda: d.host("s", "laptop.local"), 3))
        self.assertTrue(hb.none(lambda h: h.message.has("laptop.local", A), wait=2), "and it is told of nothing")

    def test_a_question_is_forwarded_to_the_other_interfaces_when_the_segment_says_so(self):
        la, lb = self.two_links()
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=ra,rb\nForwardQuestions=always\n"))
        hb = lb.hearer()
        asker = la.device("10.9.1.50")
        asker.multicast(query(("_ipp._tcp.local", PTR)))
        got = hb.wait(asks("_ipp._tcp.local", PTR, src=lb.router_addr), 5)
        self.assertTrue(got, self.logs(d))

    def test_a_question_is_not_forwarded_when_the_segment_says_never(self):
        la, lb = self.two_links()
        self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=ra,rb\nForwardQuestions=never\n"))
        hb = lb.hearer()
        la.device("10.9.1.50").multicast(query(("_ipp._tcp.local", PTR)))
        self.assertTrue(hb.none(asks("_ipp._tcp.local", PTR), wait=2))


class Interfaces(Case):
    def test_an_interface_that_is_not_there_yet_is_waited_for_and_followed_as_it_comes_and_goes(self):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=ra,late\n"))
        self.assertTrue(d.wait_log(r"late: not there yet; waiting for it", 1), self.logs(d))
        tv = la.device("10.9.1.50")
        tv.multicast(announcement("tv", "10.9.1.50", "TV"))
        self.assertTrue(until(lambda: d.host("s", "tv.local"), 3))

        # It appears: it is listened to, and what is known is announced on it.
        mark = d.mark()
        late = self.lab.link("late", "10.9.3.1/24", "10.9.3.2/24")
        hl = late.hearer()
        self.assertTrue(d.wait_log(r"late: here \(index \d+\), listening", 5, mark), self.logs(d))
        self.assertTrue(hl.wait(alive("tv.local", A, "10.9.1.50"), 5), "what is known is announced on it\n" + self.logs(d))

        # It goes, and comes back, in another form.
        mark = d.mark()
        self.lab.router("ip", "link", "del", "late")
        self.assertTrue(d.wait_log(r"late: gone; waiting for it to come back", 5, mark), self.logs(d))
        mark = d.mark()
        late = self.lab.link("late", "10.9.3.1/24", "10.9.3.2/24")
        hl = late.hearer()
        self.assertTrue(d.wait_log(r"late: back \(index \d+\), listening", 5, mark), self.logs(d))
        self.assertTrue(hl.wait(alive("tv.local", A, "10.9.1.50"), 5), "and again\n" + self.logs(d))

        # What it learned of the one that was there is not kept for it.
        late_dev = late.device("10.9.3.50")
        late_dev.multicast(announcement("cam", "10.9.3.50", "Cam"))
        self.assertTrue(until(lambda: d.host("s", "cam.local"), 3), self.logs(d))
        self.lab.router("ip", "link", "del", "late")
        self.assertTrue(until(lambda: not d.host("s", "cam.local"), 5), "what was heard there is forgotten\n" + self.logs(d))
        self.assertEqual(d.stop(), 0)

    def test_an_interface_that_goes_down_and_comes_up_is_announced_on_again(self):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        d = self.lab.daemon(conf("[Advertise]\nHostname=pc\n[Segment]\nName=s\nInterfaces=ra\n"))
        ha = la.hearer()
        self.assertTrue(ha.wait(alive("pc.local", A, "10.9.1.1")), self.logs(d))
        self.lab.router("ip", "link", "set", "ra", "down")
        time.sleep(0.5)
        mark, heard = d.mark(), ha.count()
        self.lab.router("ip", "link", "set", "ra", "up")
        self.assertTrue(d.wait_log(r"ra: up$", 5, mark), self.logs(d))
        self.assertTrue(ha.wait(alive("pc.local", A, "10.9.1.1"), 5, since=heard), "announced again\n" + self.logs(d))
        self.assertTrue(ha.wait(asks(*PROBE), 5, since=heard), "and asked on again")

    def test_a_change_of_mtu_is_taken(self):
        self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=ra\n"))
        self.assertTrue(d.wait_log(r"ra: MTU is 1500", 2), self.logs(d))
        mark = d.mark()
        self.lab.router("ip", "link", "set", "ra", "mtu", "1400")
        self.assertTrue(d.wait_log(r"ra: MTU now 1400", 5, mark), self.logs(d))

    def test_a_daemon_with_no_interface_there_still_starts_and_stops(self):
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=nothere\n"))
        self.assertTrue(d.wait_log(r"nothere: not there yet", 2), self.logs(d))
        self.assertEqual(d.request("segments")["ok"], True)
        self.assertEqual(d.stop(), 0)


class Advertising(Case):
    def test_the_advertised_name_and_services_are_announced_and_answered_for(self):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        d = self.lab.daemon(conf("[Advertise]\nHostname=pc\nServices=_ssh._tcp:22 _http._tcp:8080\n[Segment]\nName=s\nInterfaces=ra\n"))
        ha = la.hearer()
        self.assertTrue(ha.wait(alive("pc.local", A, "10.9.1.1")), self.logs(d))
        self.assertTrue(ha.wait(alive("_ssh._tcp.local", PTR, "pc._ssh._tcp.local")))
        self.assertTrue(ha.wait(alive("pc._ssh._tcp.local", SRV, "22 pc.local")))
        self.assertTrue(ha.wait(alive("pc._http._tcp.local", SRV, "8080 pc.local")))

        # Asked for, it answers: not within a second of saying it, which a
        # responder does not do twice (RFC 6762 section 6).
        time.sleep(1.5)
        heard = ha.count()
        la.device("10.9.1.50").multicast(query(("pc._ssh._tcp.local", SRV)))
        self.assertTrue(ha.wait(alive("pc._ssh._tcp.local", SRV, "22 pc.local"), 5, since=heard), self.logs(d))
        # And it is among the devices, as itself.
        own = d.host("s", "pc.local")
        self.assertTrue(own and own[0].get("own"), own)
        self.assertEqual({s["type"] for s in own[0]["services"]}, {"_ssh._tcp.local", "_http._tcp.local"})
        self.assertEqual(d.stop(), 0)
        self.assertTrue(ha.wait(goodbye("pc.local", A, "10.9.1.1")), "withdrawn on shutdown")

    def test_the_advertised_name_follows_the_interfaces_addresses(self):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        d = self.lab.daemon(conf("[Advertise]\nHostname=pc\n[Segment]\nName=s\nInterfaces=ra\n"))
        ha = la.hearer()
        self.assertTrue(ha.wait(alive("pc.local", A, "10.9.1.1")))
        # A second address is announced.
        self.lab.router("ip", "addr", "add", "10.9.1.9/24", "dev", "ra")
        self.assertTrue(ha.wait(alive("pc.local", A, "10.9.1.9"), 5), self.logs(d))
        # The one that goes is retracted, with a goodbye.
        self.lab.router("ip", "addr", "del", "10.9.1.9/24", "dev", "ra")
        self.assertTrue(ha.wait(goodbye("pc.local", A, "10.9.1.9"), 5), self.logs(d))
        self.assertTrue(d.wait_log(r"ra: advertising pc.local as 10.9.1.1 ", 2))
        # One asked for now is not told of it.
        heard = ha.count()
        la.device("10.9.1.50").multicast(query(("pc.local", A)))
        got = ha.wait(alive("pc.local", A), 5, since=heard)
        self.assertTrue(got and not got.message.has("pc.local", A, "10.9.1.9"), got)

    def test_a_name_with_an_interface_is_only_advertised_and_answered_for_there(self):
        la, lb = self.two_links()
        d = self.lab.daemon(conf("[Advertise]\nHostname=pc\nInterface=ra\nServices=_ssh._tcp:22\n[Segment]\nName=s\nInterfaces=ra,rb\n"))
        ha, hb = la.hearer(), lb.hearer()
        self.assertTrue(ha.wait(alive("pc.local", A, "10.9.1.1")), self.logs(d))
        la.device("10.9.1.50").multicast(query(("pc.local", A)))
        lb.device("10.9.2.50").multicast(query(("pc.local", A)))
        self.assertTrue(ha.wait(alive("pc.local", A, "10.9.1.1")))
        self.assertTrue(hb.none(lambda h: h.message.has("pc.local"), wait=2), "nothing of it on the other")

    def test_there_may_be_several_names_each_where_it_says(self):
        la, lb = self.two_links()
        d = self.lab.daemon(conf(
            "[Advertise]\nHostname=pc\nInterface=ra\nServices=_ssh._tcp:22\n"
            "[Advertise]\nHostname=files\nInterface=rb\nServices=_smb._tcp:445\n"
            "[Segment]\nName=s\nInterfaces=ra,rb\n"
        ))
        ha, hb = la.hearer(), lb.hearer()
        self.assertTrue(ha.wait(alive("pc.local", A, "10.9.1.1")), self.logs(d))
        self.assertTrue(hb.wait(alive("files.local", A, "10.9.2.1")), self.logs(d))
        self.assertTrue(hb.wait(alive("files._smb._tcp.local", SRV, "445 files.local")))
        self.assertTrue(ha.none(lambda h: h.message.has("files.local"), wait=1))
        self.assertTrue(hb.none(lambda h: h.message.has("pc.local"), wait=0.5))


class Unicast(Case):
    """What is sent to the daemon itself, and not to the group."""

    def world(self, listen, source="10.9.1.50"):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        # A packet from an address that is not on the link is not for the kernel to drop.
        self.lab.router("sh", "-c", "for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > $f; done")
        d = self.lab.daemon(f"[Listen]\nIPv4={listen}\nIPv6=off\n[Segment]\nName=s\nInterfaces=ra\n")
        dev = la.device(source)
        dev.unicast(announcement("tv", source, "TV"), "10.9.1.1")
        return d

    def test_it_is_heard_from_the_link_where_listening_is_on(self):
        d = self.world("on")
        self.assertTrue(until(lambda: d.host("s", "tv.local"), 3), self.logs(d))

    def test_it_is_not_heard_where_listening_is_to_the_group_only(self):
        d = self.world("multicast")
        time.sleep(1.5)
        self.assertEqual(d.host("s", "tv.local"), [])

    def test_it_is_not_heard_from_a_host_that_is_not_on_the_link(self):
        d = self.world("on", source="192.168.77.5")
        time.sleep(1.5)
        self.assertEqual(d.host("s", "tv.local"), [], "a host routed in is not believed")


class Questions(Case):
    def test_a_device_with_a_host_and_no_address_is_asked_for_its_address(self):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=ra\n"))
        ha = la.hearer()
        dev = la.device("10.9.1.50")
        # It says where its service is, and not where it is: the daemon asks.
        dev.multicast(response(ptr("_http._tcp.local", "TV._http._tcp.local"), srv("TV._http._tcp.local", 80, "tv.local")))
        self.assertTrue(until(lambda: d.host("s", "tv.local"), 3), self.logs(d))
        self.assertEqual(d.host("s", "tv.local")[0]["addresses"], [], "not the address it sent from")
        self.assertTrue(ha.wait(asks("tv.local", A), 10), "asked for it\n" + self.logs(d))
        dev.multicast(response(a("tv.local", "10.9.1.50")))
        self.assertTrue(until(lambda: d.host("s", "tv.local") and d.host("s", "tv.local")[0]["addresses"] == ["10.9.1.50"], 3))

    def test_what_a_router_says_of_the_devices_behind_it_is_not_taken_for_its_own(self):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=ra\n"))
        router = la.device("10.9.1.77")
        router.multicast(response(
            ptr("_raop._tcp.local", "Speakers._raop._tcp.local"), srv("Speakers._raop._tcp.local", 7000, "speakers.local"),
            ptr("_ssh._tcp.local", "router._ssh._tcp.local"),
        ))
        router.multicast(response(a("speakers.local", "10.9.8.73"), srv("Speakers._raop._tcp.local", 7000, "speakers.local")))
        self.assertTrue(until(lambda: d.host("s", "speakers.local") and d.host("s", "speakers.local")[0]["addresses"], 3), self.logs(d))
        speakers = d.host("s", "speakers.local")[0]
        self.assertEqual(speakers["addresses"], ["10.9.8.73"], speakers)
        self.assertEqual([s["type"] for s in speakers["services"]], ["_raop._tcp.local"], "no service of the router's")


class Avahi(Case):
    def test_names_are_resolved_as_avahi_does(self):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        path = os.path.join(self.lab.dir, "avahi.sock")
        d = self.lab.daemon(conf(
            f"[Ipc]\nSocket={self.lab.dir}/mdnsd.sock\nAvahiSocket={path}\n"
            "[Advertise]\nHostname=pc\n[Segment]\nName=s\nInterfaces=ra\n"
        ))
        ha = la.hearer()
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o666", "for anyone to use")
        la.device("10.9.1.50").multicast(announcement("tv", "10.9.1.50", "TV"))
        self.assertTrue(until(lambda: d.host("s", "tv.local"), 3))

        self.assertRegex(d.avahi(path, "RESOLVE-HOSTNAME-IPV4 tv.local"), r"^\+ \d+ 0 tv\.local 10\.9\.1\.50$")
        self.assertRegex(d.avahi(path, "RESOLVE-HOSTNAME-IPV4 TV.local."), r"^\+ \d+ 0 tv\.local 10\.9\.1\.50$")
        self.assertRegex(d.avahi(path, "RESOLVE-HOSTNAME-IPV4 pc.local"), r"^\+ \d+ 0 pc\.local 10\.9\.1\.1$", "itself")
        self.assertRegex(d.avahi(path, "RESOLVE-ADDRESS 10.9.1.1"), r"^\+ \d+ 0 pc\.local$")
        self.assertTrue(d.avahi(path, "RESOLVE-ADDRESS 10.9.1.222").startswith("-30"))
        self.assertTrue(d.avahi(path, "RESOLVE-HOSTNAME-IPV4 example.com").startswith("-3 "))
        self.assertTrue(d.avahi(path, "NONSENSE").startswith("-21"))

        # A name that is known has no address of the other family: not waited for long.
        started = time.time()
        self.assertTrue(d.avahi(path, "RESOLVE-HOSTNAME-IPV6 tv.local").startswith("-15"))
        self.assertLess(time.time() - started, 1.5)

        # One that is not known is asked for, and waited for.
        heard = ha.count()
        started = time.time()
        self.assertTrue(d.avahi(path, "RESOLVE-HOSTNAME-IPV4 nobody.local").startswith("-15"))
        self.assertGreater(time.time() - started, 1.5)
        self.assertTrue(ha.wait(asks("nobody.local", A), 1, since=heard), "it was asked for")

    def test_a_name_that_answers_late_is_told_when_it_does(self):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        path = os.path.join(self.lab.dir, "avahi.sock")
        d = self.lab.daemon(conf(f"[Ipc]\nSocket={self.lab.dir}/mdnsd.sock\nAvahiSocket={path}\n[Segment]\nName=s\nInterfaces=ra\n"))
        ha = la.hearer()
        sleepy = la.device("10.9.1.60")
        import threading
        out = []
        t = threading.Thread(target=lambda: out.append(d.avahi(path, "RESOLVE-HOSTNAME-IPV4 sleepy.local")))
        t.start()
        # It answers when it is asked, not before.
        self.assertTrue(ha.wait(asks("sleepy.local", A), 5), self.logs(d))
        sleepy.multicast(response(a("sleepy.local", "10.9.1.60")))
        t.join(5)
        self.assertEqual(len(out), 1)
        self.assertRegex(out[0], r"^\+ \d+ 0 sleepy\.local 10\.9\.1\.60$")


@unittest.skipUnless(CTL, "needs --ctl")
class Ctl(Case):
    def test_mdnsctl_lists_and_asks(self):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        d = self.lab.daemon(conf("[Advertise]\nHostname=pc\nServices=_ssh._tcp:22\n[Segment]\nName=lan\nInterfaces=ra\n"))
        ha = la.hearer()
        la.device("10.9.1.50").multicast(announcement("tv", "10.9.1.50", "TV"))
        self.assertTrue(until(lambda: d.host("lan", "tv.local"), 3))

        out = d.ctl("segments")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("lan", out.stdout)
        out = d.ctl("devices", "lan")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("tv.local", out.stdout)
        self.assertIn("pc.local", out.stdout, "the host itself")
        self.assertIn("10.9.1.50", out.stdout)

        # A query is a watch for the type, for as long as it is told to wait.
        out = d.ctl("devices", "--query", "_ssh._tcp", "--wait", "2s", "lan")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("pc.local", out.stdout)
        self.assertNotIn("tv.local", out.stdout, "it has no such service")
        self.assertTrue(ha.wait(asks("_ssh._tcp.local", PTR), 3), "and the type was asked for")

        heard = ha.count()
        out = d.ctl("probe", "lan", timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertTrue(ha.wait(asks(*PROBE), 3, since=heard))
        out = d.ctl("timers")
        self.assertEqual(out.returncode, 0, out.stderr)
        out = d.ctl("devices", "nosuchsegment")
        self.assertNotEqual(out.returncode, 0)

    def test_mdnsctl_without_the_daemon_says_so(self):
        d = self.lab.daemon(conf("[Segment]\nName=lan\nInterfaces=nothere\n"))
        d.stop()
        out = d.ctl("segments")
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("cannot talk to", out.stderr)


class Startup(Case):
    def test_a_config_that_is_wrong_is_said_so_and_is_not_run(self):
        cases = [
            ("[Segment]\nName=s\nInterfaces=ra\nBogus=1\n", r'line 4: unknown setting "bogus"'),
            ("[Segment]\nName=s\n", r"has no Interfaces="),
            ("[Listen]\nIPv4=off\nIPv6=off\n[Segment]\nName=s\nInterfaces=ra\n", r"both off"),
            ("[Listen]\nIPv4=yes\n[Segment]\nName=s\nInterfaces=ra\n", r"must be off, multicast or on"),
            ("[Advertise]\nServices=_ssh._tcp:22\n[Segment]\nName=s\nInterfaces=ra\n", r"no Hostname="),
            ("[Advertise]\nHostname=pc\nInterface=other\n[Segment]\nName=s\nInterfaces=ra\n", r"not in any segment"),
            ("[Advertise]\nHostname=pc\n[Advertise]\nHostname=pc\n[Segment]\nName=s\nInterfaces=ra\n", r"same interface"),
            ("[Advertise]\nHostname=router.lan\n[Segment]\nName=s\nInterfaces=ra\n", r"not under \.local"),
            ("", r"no \[Segment\]"),
        ]
        for text, pattern in cases:
            with self.subTest(pattern=pattern):
                path = os.path.join(self.lab.dir, "bad.conf")
                with open(path, "w") as f:
                    f.write(text)
                r = subprocess.run([BINARY, path], capture_output=True, text=True, timeout=10)
                self.assertNotEqual(r.returncode, 0, r.stderr)
                self.assertRegex(r.stderr, pattern)

    def test_a_missing_config_is_said_so(self):
        r = subprocess.run([BINARY, os.path.join(self.lab.dir, "nothere.conf")], capture_output=True, text=True, timeout=10)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("nothere.conf", r.stderr)

    def test_a_second_instance_is_refused_and_the_first_is_not_disturbed(self):
        self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        body = "[Segment]\nName=s\nInterfaces=ra\n"
        first = self.lab.daemon(conf(body))
        second = self.lab.daemon(conf(f"[Ipc]\nSocket={first.socket_path}\n" + body), wait=False)
        self.assertNotEqual(second.exited(10), None, "it did not stop")
        self.assertNotEqual(second.proc.returncode, 0)
        self.assertTrue(second.wait_log(r"in use by a running instance", 1), self.logs(second))
        self.assertTrue(first.request("segments")["ok"])

    def test_the_signals_stop_it_cleanly(self):
        import signal
        for sig in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(sig=sig.name):
                lab = Lab(BINARY, CTL)
                try:
                    lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
                    d = lab.daemon(conf("[Segment]\nName=s\nInterfaces=ra\n"))
                    self.assertEqual(d.stop(sig), 0, "\n".join(d.log()))
                    self.assertTrue(d.wait_log(rf"received {sig.name}", 1), "\n".join(d.log()))
                finally:
                    lab.close()


class Neighbours(Case):
    def test_addresses_the_neighbour_table_has_for_a_device_are_learned(self):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        self.lab.router("ip", "addr", "add", "fd00:9::1/64", "dev", "ra", "nodad")
        sh("ip", "addr", "add", "fd00:9::2/64", "dev", la.peer, "nodad")
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=ra\n", ipv6=True))
        mac = "02:00:00:00:00:50"
        # The device announces an IPv4 address and a link-local IPv6 one, and
        # is known to the router's neighbour table at a routable one too.
        self.lab.router("ip", "-6", "neigh", "replace", "fd00:9::50", "lladdr", mac, "dev", "ra", "nud", "permanent")
        self.lab.router("ip", "-4", "neigh", "replace", "10.9.1.50", "lladdr", mac, "dev", "ra", "nud", "permanent")
        dev = la.device("10.9.1.50")
        dev.multicast(response(a("tv.local", "10.9.1.50"), aaaa("tv.local", "fe80::50"), srv("TV._http._tcp.local", 80, "tv.local"),
                               ptr("_http._tcp.local", "TV._http._tcp.local")))
        learned = until(lambda: (d.host("s", "tv.local") or [{}])[0].get("neighbour_addresses"), 5)
        self.assertEqual(learned, ["fd00:9::50"], self.logs(d))
        # The entry goes, and so does what was learned of it.
        self.lab.router("ip", "-6", "neigh", "del", "fd00:9::50", "dev", "ra")
        self.assertTrue(until(lambda: not d.host("s", "tv.local")[0]["neighbour_addresses"], 5), d.host("s", "tv.local"))


@unittest.skipUnless(SLOW, "takes a minute: --slow")
class Timers(Case):
    def test_a_device_about_to_expire_is_asked_at_its_own_address_and_then_on_the_group(self):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        d = self.lab.daemon(conf("[Probe]\nRefreshBefore=30s\n[Interface]\nMinimumLifetime=60s\n[Segment]\nName=s\nInterfaces=ra\n"))
        ha = la.hearer()
        dev = la.device("10.9.1.50")
        dev.multicast(announcement("dev", "10.9.1.50", ttl=60))
        self.assertTrue(until(lambda: d.host("s", "dev.local"), 3))
        started = time.time()
        # It lives a minute, and is asked half a minute in: of itself, not of the group.
        got = dev.hearer.wait(asks("dev.local", A), 45)
        self.assertTrue(got, self.logs(d))
        self.assertFalse(got.to_group)
        self.assertGreater(time.time() - started, 25)
        # It does not answer: the next try is to the group.
        again = ha.wait(asks("dev.local", A), 20)
        self.assertTrue(again, "tried the group\n" + self.logs(d))
        # It answers that, and is kept.
        dev.multicast(announcement("dev", "10.9.1.50", ttl=60))
        time.sleep(1)
        self.assertTrue(d.host("s", "dev.local"))


if __name__ == "__main__":
    unittest.main()

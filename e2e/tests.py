"""The scenarios. See e2e.py for how to run them."""
import os
import subprocess
import unittest

from lab import A, AAAA, PTR, SRV, Lab, announcement, a, aaaa, query, response, sh, ptr, srv, until

BINARY = os.environ["E2E_DAEMON"]
CTL = os.environ.get("E2E_CTL")
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
        ha, hb = la.hearer(), lb.hearer()
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=ra,rb\n"))
        # It asks what is there when it starts.
        self.assertTrue(ha.wait(asks(*PROBE)), self.logs(d))

        tv = la.device("10.9.1.50")
        tv.multicast(announcement("tv", "10.9.1.50", "TV"))
        self.assertTrue(hb.wait(alive("tv.local", A, "10.9.1.50")), self.logs(d))
        self.assertTrue(hb.wait(alive("_http._tcp.local", PTR, "TV._http._tcp.local")), "its service goes with it")
        self.assertTrue(hb.wait(alive("TV._http._tcp.local", SRV, "80 tv.local")))
        # Not back to where it is.
        d.settle()
        self.assertTrue(ha.none(lambda h: h.src == la.router_addr and h.message.has("tv.local", A)), "reflected back")

        listed = d.host("s", "tv.local")
        self.assertEqual([x["addresses"] for x in listed], [["10.9.1.50"]], listed)
        self.assertEqual(listed[0]["interface"], "ra")

        self.assertEqual(d.stop(), 0, self.logs(d))
        self.assertTrue(hb.wait(goodbye("tv.local", A, "10.9.1.50")), "withdrawn from the other interface on shutdown")

    def test_a_device_that_says_goodbye_is_forgotten_and_withdrawn(self):
        la, lb = self.two_links()
        hb = lb.hearer()
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=ra,rb\n"))
        tv = la.device("10.9.1.50")
        tv.multicast(announcement("tv", "10.9.1.50", "TV"))
        self.assertTrue(hb.wait(alive("tv.local", A)))
        tv.multicast(response(a("tv.local", "10.9.1.50", ttl=0)))
        self.assertTrue(hb.wait(goodbye("tv.local", A, "10.9.1.50")), self.logs(d))
        d.settle()
        self.assertTrue(not d.host("s", "tv.local"), d.devices("s"))

    def test_an_untrusted_interface_is_told_nothing_but_is_heard(self):
        la, lb = self.two_links()
        ha, hb = la.hearer(), lb.hearer()
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=ra,rb\nUntrusted=rb\n"))
        lan, iot = la.device("10.9.1.50"), lb.device("10.9.2.50")
        lan.multicast(announcement("laptop", "10.9.1.50", "Laptop"))
        iot.multicast(announcement("plug", "10.9.2.50", "Plug"))
        self.assertTrue(ha.wait(alive("plug.local", A, "10.9.2.50")), "what the untrusted one has is reflected out of it\n" + self.logs(d))
        d.settle()
        self.assertTrue(d.host("s", "laptop.local"))
        d.settle()
        self.assertTrue(hb.none(lambda h: h.message.has("laptop.local", A)), "and it is told of nothing")

    def test_a_question_is_forwarded_to_the_other_interfaces_when_the_segment_says_so(self):
        la, lb = self.two_links()
        hb = lb.hearer()
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=ra,rb\nForwardQuestions=always\n"))
        asker = la.device("10.9.1.50")
        asker.multicast(query(("_ipp._tcp.local", PTR)))
        got = hb.wait(asks("_ipp._tcp.local", PTR, src=lb.router_addr), 5)
        self.assertTrue(got, self.logs(d))

    def test_a_question_is_not_forwarded_when_the_segment_says_never(self):
        la, lb = self.two_links()
        hb = lb.hearer()
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=ra,rb\nForwardQuestions=never\n"))
        la.device("10.9.1.50").multicast(query(("_ipp._tcp.local", PTR)))
        d.settle()
        self.assertTrue(hb.none(asks("_ipp._tcp.local", PTR)))


class Interfaces(Case):
    def test_an_interface_that_is_not_there_yet_is_waited_for_and_followed_as_it_comes_and_goes(self):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=ra,late\n"))
        self.assertTrue(d.wait_log(r"late: not there yet; waiting for it", 1), self.logs(d))
        tv = la.device("10.9.1.50")
        tv.multicast(announcement("tv", "10.9.1.50", "TV"))
        d.settle()
        self.assertTrue(d.host("s", "tv.local"))

        # It appears: it is listened to, and what is known is announced on it.
        mark = d.mark()
        late = self.lab.link("late", "10.9.3.1/24", "10.9.3.2/24")
        hl = late.hearer()
        self.assertTrue(d.wait_log(r"late: here \(index \d+\), listening", 5, mark), self.logs(d))
        self.assertTrue(d.advance_until(lambda: hl.seen(alive("tv.local", A, "10.9.1.50"))), "what is known is announced on it\n" + self.logs(d))

        # It goes, and comes back, in another form.
        mark = d.mark()
        self.lab.router("ip", "link", "del", "late")
        self.assertTrue(d.wait_log(r"late: gone; waiting for it to come back", 5, mark), self.logs(d))
        mark = d.mark()
        late = self.lab.link("late", "10.9.3.1/24", "10.9.3.2/24")
        hl = late.hearer()
        self.assertTrue(d.wait_log(r"late: back \(index \d+\), listening", 5, mark), self.logs(d))
        self.assertTrue(d.advance_until(lambda: hl.seen(alive("tv.local", A, "10.9.1.50"))), "and again\n" + self.logs(d))

        # What it learned of the one that was there is not kept for it.
        late_dev = late.device("10.9.3.50")
        late_dev.multicast(announcement("cam", "10.9.3.50", "Cam"))
        d.settle()
        self.assertTrue(d.host("s", "cam.local"), self.logs(d))
        self.lab.router("ip", "link", "del", "late")
        d.settle()
        self.assertTrue(not d.host("s", "cam.local"), "what was heard there is forgotten\n" + self.logs(d))
        self.assertEqual(d.stop(), 0)

    def test_an_interface_that_goes_down_and_comes_up_is_announced_on_again(self):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        ha = la.hearer()
        d = self.lab.daemon(conf("[Advertise]\nHostname=pc\n[Segment]\nName=s\nInterfaces=ra\n"))
        self.assertTrue(ha.wait(alive("pc.local", A, "10.9.1.1")), self.logs(d))
        self.lab.router("ip", "link", "set", "ra", "down")
        d.settle()
        mark, heard = d.mark(), ha.count()
        self.lab.router("ip", "link", "set", "ra", "up")
        self.assertTrue(d.wait_log(r"ra: up$", 5, mark), self.logs(d))
        self.assertTrue(ha.wait(alive("pc.local", A, "10.9.1.1"), 5, since=heard), "announced again\n" + self.logs(d))
        self.assertTrue(d.advance_until(lambda: ha.seen(asks(*PROBE), heard)), "and asked on again")

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
        ha = la.hearer()
        d = self.lab.daemon(conf("[Advertise]\nHostname=pc\nServices=_ssh._tcp:22 _http._tcp:8080\n[Segment]\nName=s\nInterfaces=ra\n"))
        self.assertTrue(ha.wait(alive("pc.local", A, "10.9.1.1")), self.logs(d))
        self.assertTrue(ha.wait(alive("_ssh._tcp.local", PTR, "pc._ssh._tcp.local")))
        self.assertTrue(ha.wait(alive("pc._ssh._tcp.local", SRV, "22 pc.local")))
        self.assertTrue(ha.wait(alive("pc._http._tcp.local", SRV, "8080 pc.local")))

        # Asked for, it answers: not within a second of saying it, which a
        # responder does not do twice (RFC 6762 section 6). It says it again a
        # second after it starts, so that is waited out, and a second more.
        d.advance(1)
        d.advance(1.5)
        heard = ha.count()
        la.device("10.9.1.50").multicast(query(("pc._ssh._tcp.local", SRV)))
        self.assertTrue(d.advance_until(lambda: ha.seen(alive("pc._ssh._tcp.local", SRV, "22 pc.local"), heard)), self.logs(d))
        # And it is among the devices, as itself.
        own = d.host("s", "pc.local")
        self.assertTrue(own and own[0].get("own"), own)
        self.assertEqual({s["type"] for s in own[0]["services"]}, {"_ssh._tcp.local", "_http._tcp.local"})
        self.assertEqual(d.stop(), 0)
        self.assertTrue(ha.wait(goodbye("pc.local", A, "10.9.1.1")), "withdrawn on shutdown")

    def test_the_advertised_name_follows_the_interfaces_addresses(self):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        ha = la.hearer()
        d = self.lab.daemon(conf("[Advertise]\nHostname=pc\n[Segment]\nName=s\nInterfaces=ra\n"))
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
        got = d.advance_until(lambda: ha.seen(alive("pc.local", A), heard))
        self.assertTrue(got and not got.message.has("pc.local", A, "10.9.1.9"), got)

    def test_a_name_with_an_interface_is_only_advertised_and_answered_for_there(self):
        la, lb = self.two_links()
        ha, hb = la.hearer(), lb.hearer()
        d = self.lab.daemon(conf("[Advertise]\nHostname=pc\nInterface=ra\nServices=_ssh._tcp:22\n[Segment]\nName=s\nInterfaces=ra,rb\n"))
        self.assertTrue(ha.wait(alive("pc.local", A, "10.9.1.1")), self.logs(d))
        la.device("10.9.1.50").multicast(query(("pc.local", A)))
        lb.device("10.9.2.50").multicast(query(("pc.local", A)))
        self.assertTrue(ha.wait(alive("pc.local", A, "10.9.1.1")))
        d.settle()
        self.assertTrue(hb.none(lambda h: h.message.has("pc.local")), "nothing of it on the other")

    def test_there_may_be_several_names_each_where_it_says(self):
        la, lb = self.two_links()
        ha, hb = la.hearer(), lb.hearer()
        d = self.lab.daemon(conf(
            "[Advertise]\nHostname=pc\nInterface=ra\nServices=_ssh._tcp:22\n"
            "[Advertise]\nHostname=files\nInterface=rb\nServices=_smb._tcp:445\n"
            "[Segment]\nName=s\nInterfaces=ra,rb\n"
        ))
        self.assertTrue(ha.wait(alive("pc.local", A, "10.9.1.1")), self.logs(d))
        self.assertTrue(hb.wait(alive("files.local", A, "10.9.2.1")), self.logs(d))
        self.assertTrue(hb.wait(alive("files._smb._tcp.local", SRV, "445 files.local")))
        d.settle()
        self.assertTrue(ha.none(lambda h: h.message.has("files.local")))
        self.assertTrue(hb.none(lambda h: h.message.has("pc.local")))


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
        d.settle()
        self.assertTrue(d.host("s", "tv.local"), self.logs(d))

    def test_it_is_not_heard_where_listening_is_to_the_group_only(self):
        d = self.world("multicast")
        d.settle()
        self.assertEqual(d.host("s", "tv.local"), [])

    def test_it_is_not_heard_from_a_host_that_is_not_on_the_link(self):
        d = self.world("on", source="192.168.77.5")
        d.settle()
        self.assertEqual(d.host("s", "tv.local"), [], "a host routed in is not believed")


class Questions(Case):
    def test_a_device_with_a_host_and_no_address_is_asked_for_its_address(self):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        ha = la.hearer()
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=ra\n"))
        dev = la.device("10.9.1.50")
        # It says where its service is, and not where it is: the daemon asks.
        dev.multicast(response(ptr("_http._tcp.local", "TV._http._tcp.local"), srv("TV._http._tcp.local", 80, "tv.local")))
        d.settle()
        self.assertTrue(d.host("s", "tv.local"), self.logs(d))
        self.assertEqual(d.host("s", "tv.local")[0]["addresses"], [], "not the address it sent from")
        self.assertTrue(d.advance_until(lambda: ha.seen(asks("tv.local", A))), "asked for it\n" + self.logs(d))
        dev.multicast(response(a("tv.local", "10.9.1.50")))
        d.settle()
        self.assertTrue(d.host("s", "tv.local") and d.host("s", "tv.local")[0]["addresses"] == ["10.9.1.50"])

    def test_what_a_router_says_of_the_devices_behind_it_is_not_taken_for_its_own(self):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=ra\n"))
        router = la.device("10.9.1.77")
        router.multicast(response(
            ptr("_raop._tcp.local", "Speakers._raop._tcp.local"), srv("Speakers._raop._tcp.local", 7000, "speakers.local"),
            ptr("_ssh._tcp.local", "router._ssh._tcp.local"),
        ))
        router.multicast(response(a("speakers.local", "10.9.8.73"), srv("Speakers._raop._tcp.local", 7000, "speakers.local")))
        d.settle()
        self.assertTrue(d.host("s", "speakers.local") and d.host("s", "speakers.local")[0]["addresses"], self.logs(d))
        speakers = d.host("s", "speakers.local")[0]
        self.assertEqual(speakers["addresses"], ["10.9.8.73"], speakers)
        self.assertEqual([s["type"] for s in speakers["services"]], ["_raop._tcp.local"], "no service of the router's")


class Avahi(Case):
    def test_names_are_resolved_as_avahi_does(self):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        path = os.path.join(self.lab.dir, "avahi.sock")
        ha = la.hearer()
        d = self.lab.daemon(conf(
            f"[Ipc]\nSocket={self.lab.dir}/mdnsd.sock\nAvahiSocket={path}\n"
            "[Advertise]\nHostname=pc\n[Segment]\nName=s\nInterfaces=ra\n"
        ))
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o666", "for anyone to use")
        la.device("10.9.1.50").multicast(announcement("tv", "10.9.1.50", "TV"))
        d.settle()
        self.assertTrue(d.host("s", "tv.local"))

        self.assertRegex(d.avahi(path, "RESOLVE-HOSTNAME-IPV4 tv.local"), r"^\+ \d+ 0 tv\.local 10\.9\.1\.50$")
        self.assertRegex(d.avahi(path, "RESOLVE-HOSTNAME-IPV4 TV.local."), r"^\+ \d+ 0 tv\.local 10\.9\.1\.50$")
        self.assertRegex(d.avahi(path, "RESOLVE-HOSTNAME-IPV4 pc.local"), r"^\+ \d+ 0 pc\.local 10\.9\.1\.1$", "itself")
        self.assertRegex(d.avahi(path, "RESOLVE-ADDRESS 10.9.1.1"), r"^\+ \d+ 0 pc\.local$")
        self.assertTrue(d.avahi(path, "RESOLVE-ADDRESS 10.9.1.222").startswith("-30"))
        self.assertTrue(d.avahi(path, "RESOLVE-HOSTNAME-IPV4 example.com").startswith("-3 "))
        self.assertTrue(d.avahi(path, "NONSENSE").startswith("-21"))

        # A name that is known has no address of the other family: not waited for long.
        call = d.avahi_send(path, "RESOLVE-HOSTNAME-IPV6 tv.local")
        d.settle()
        self.assertFalse(call.answered(), "it waits a little, in case it is told")
        d.advance(0.35)
        self.assertTrue(call.answered())
        self.assertTrue(call.reply().startswith("-15"))

        # One that is not known is asked for, and waited for.
        heard = ha.count()
        call = d.avahi_send(path, "RESOLVE-HOSTNAME-IPV4 nobody.local")
        d.settle()
        d.advance(1.5)
        self.assertFalse(call.answered(), "still waiting")
        self.assertTrue(ha.wait(asks("nobody.local", A), 5, since=heard), "it was asked for")
        d.advance(1)
        self.assertTrue(call.reply().startswith("-15"))

    def test_a_name_that_answers_late_is_told_when_it_does(self):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        path = os.path.join(self.lab.dir, "avahi.sock")
        ha = la.hearer()
        d = self.lab.daemon(conf(f"[Ipc]\nSocket={self.lab.dir}/mdnsd.sock\nAvahiSocket={path}\n[Segment]\nName=s\nInterfaces=ra\n"))
        sleepy = la.device("10.9.1.60")
        call = d.avahi_send(path, "RESOLVE-HOSTNAME-IPV4 sleepy.local")
        # It answers when it is asked, not before.
        self.assertTrue(ha.wait(asks("sleepy.local", A), 5), self.logs(d))
        self.assertFalse(call.answered())
        sleepy.multicast(response(a("sleepy.local", "10.9.1.60")))
        self.assertRegex(call.reply(5), r"^\+ \d+ 0 sleepy\.local 10\.9\.1\.60$")


@unittest.skipUnless(CTL, "needs --ctl")
class Ctl(Case):
    def test_mdnsctl_lists_and_asks(self):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        ha = la.hearer()
        d = self.lab.daemon(conf("[Advertise]\nHostname=pc\nServices=_ssh._tcp:22\n[Segment]\nName=lan\nInterfaces=ra\n"))
        la.device("10.9.1.50").multicast(announcement("tv", "10.9.1.50", "TV"))
        d.settle()
        self.assertTrue(d.host("lan", "tv.local"))

        out = d.ctl("segments")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("lan", out.stdout)
        out = d.ctl("devices", "lan")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("tv.local", out.stdout)
        self.assertIn("pc.local", out.stdout, "the host itself")
        self.assertIn("10.9.1.50", out.stdout)

        # A query is a watch for the type, for as long as it is told to wait.
        # What is there, as it takes no longer to be told than that (what it
        # waits for is its own time, not the daemon's).
        out = d.ctl("devices", "--query", "_ssh._tcp", "--wait", "1ms", "lan")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("pc.local", out.stdout)
        self.assertNotIn("tv.local", out.stdout, "it has no such service")
        self.assertTrue(d.advance_until(lambda: ha.seen(asks("_ssh._tcp.local", PTR))), "and the type was asked for")

        heard = ha.count()
        ctl = d.ctl_start("probe", "lan")
        self.assertTrue(d.advance_until(lambda: ha.seen(asks(*PROBE), heard)), "the types are asked for")
        self.assertTrue(d.advance_until(lambda: ctl.poll() is not None, step=1, limit=30), "and it is told when it is done")
        stdout, stderr = ctl.communicate(timeout=10)
        self.assertEqual(ctl.returncode, 0, stderr)
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
        d.settle()
        learned = (d.host("s", "tv.local") or [{}])[0].get("neighbour_addresses")
        self.assertEqual(learned, ["fd00:9::50"], self.logs(d))
        # The entry goes, and so does what was learned of it.
        self.lab.router("ip", "-6", "neigh", "del", "fd00:9::50", "dev", "ra")
        d.settle()
        self.assertTrue(not d.host("s", "tv.local")[0]["neighbour_addresses"], d.host("s", "tv.local"))


class Timers(Case):
    """What happens as time passes, which the daemon's clock is moved forward
    for."""

    def test_a_device_about_to_expire_is_asked_at_its_own_address_and_then_on_the_group(self):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        ha = la.hearer()
        d = self.lab.daemon(conf("[Probe]\nRefreshBefore=30s\n[Interface]\nMinimumLifetime=40s\n[Segment]\nName=s\nInterfaces=ra\n"))
        dev = la.device("10.9.1.50")
        dev.multicast(announcement("dev", "10.9.1.50", ttl=40))
        d.settle()
        self.assertTrue(d.host("s", "dev.local"))
        # It lives 40 seconds, and is asked at 30, a quarter of its life before the
        # end, as that is less than the margin: not before, and of itself, not of
        # the group.
        asked = dev.hearer.count()
        d.advance(29)
        self.assertTrue(dev.hearer.none(asks("dev.local", A), since=asked), "not yet")
        d.advance(2)
        got = dev.hearer.seen(asks("dev.local", A), asked) or dev.hearer.wait(asks("dev.local", A), 5, since=asked)
        self.assertTrue(got, self.logs(d))
        self.assertFalse(got.to_group)
        # It does not answer: the next try is to the group.
        group = ha.count()
        d.advance(8)  # a quarter of the margin after it was asked: 7.5 seconds
        again = ha.wait(asks("dev.local", A), 5, since=group)
        self.assertTrue(again, "tried the group\n" + self.logs(d))
        # It answers that, and is kept.
        dev.multicast(announcement("dev", "10.9.1.50", ttl=40))
        d.advance(20)
        self.assertTrue(d.host("s", "dev.local"))
        d.advance(30)
        self.assertFalse(d.host("s", "dev.local"), "and goes when it is not heard from again")

    def test_a_device_with_a_short_ttl_is_asked_three_quarters_of_the_way_in_and_not_at_once(self):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        # No minimum lifetime, so it lives for its TTL, which is less than the margin.
        d = self.lab.daemon(conf("[Probe]\nRefreshBefore=30s\n[Segment]\nName=s\nInterfaces=ra\n"))
        dev = la.device("10.9.1.50")
        dev.multicast(announcement("dev", "10.9.1.50", ttl=20))
        d.settle()
        self.assertTrue(d.host("s", "dev.local"))
        asked = dev.hearer.count()
        d.advance(14)
        self.assertTrue(dev.hearer.none(asks("dev.local", A), since=asked), "not the moment it was heard, nor yet")
        d.advance(2)
        got = dev.hearer.seen(asks("dev.local", A), asked) or dev.hearer.wait(asks("dev.local", A), 5, since=asked)
        self.assertTrue(got, "asked 15 seconds in\n" + self.logs(d))
        # It does not answer, so it goes when its TTL runs out.
        d.advance(5)
        self.assertFalse(d.host("s", "dev.local"))


if __name__ == "__main__":
    unittest.main()

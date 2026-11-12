"""The scenarios. See e2e.py for how to run them."""
import os
import signal
import subprocess
import unittest

from lab import A, AAAA, FOLLOWS_CHANGES, FREEBSD, PTR, SRV, TXT, Lab, announcement, a, aaaa, query, response, sh, ptr, srv, txt, until

BINARY = os.environ["E2E_DAEMON"]
CTL = os.environ.get("E2E_CTL")
LOGS = os.environ.get("E2E_LOGS")

PROBE = ("_services._dns-sd._udp.local", PTR)

# What the daemon follows as the network changes under it it gets from netlink
# on Linux and the routing socket on FreeBSD; the other BSDs' is not read yet.
follows_changes = unittest.skipUnless(FOLLOWS_CHANGES, "the daemon does not follow changes of the network on this system yet")


def conf(body, ipv6=False):
    """A config, with IPv6 left out unless wanted: most scenarios are of IPv4."""
    if ipv6:
        return body
    # In the section for every interface, which there is one of, if the body has it.
    header = "[Interface]\n"
    return header + "IPv6=off\n" + (body[len(header):] if body.startswith(header) else body)


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

    def test_a_txt_value_that_is_not_text_is_reflected_as_it_came(self):
        la, lb = self.two_links()
        hb = lb.hearer()
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=ra,rb\n"))
        binary = [b"\xff" * 100, b"k=\x80\x81v"]
        instance = "Dev._x._tcp.local"
        la.device("10.9.1.50").multicast(response(
            a("dev.local", "10.9.1.50"), ptr("_x._tcp.local", instance, 120), srv(instance, 80, "dev.local"),
            txt(instance, *binary, ttl=120)))
        said = b"".join(bytes([len(s)]) + s for s in binary).hex()
        self.assertTrue(hb.wait(alive(instance, TXT, said)), self.logs(d))

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

    def test_a_device_that_says_the_same_again_and_again_is_reflected_once(self):
        la, lb = self.two_links()
        hb = lb.hearer()
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=ra,rb\n"))
        tv, chatter = la.device("10.9.1.50"), announcement("tv", "10.9.1.50", "TV")

        def told():
            """How many times the other network was told of the device."""
            return len(hb.matching(lambda h: h.src == lb.router_addr and h.message.has("tv.local")))

        tv.multicast(chatter)
        self.assertTrue(hb.wait(alive("tv.local", A, "10.9.1.50")), self.logs(d))
        d.settle()
        once = told()
        self.assertGreater(once, 0)

        for _ in range(30):
            tv.multicast(chatter)
        d.settle()
        self.assertEqual(told(), once, "what is the same is not said again\n" + self.logs(d))

        # What changes is, so it was not that the device was not listened to.
        tv.multicast(response(a("tv.local", "10.9.1.51")))
        self.assertTrue(hb.wait(alive("tv.local", A, "10.9.1.51")), self.logs(d))
        self.assertGreater(told(), once)

    def test_a_question_is_forwarded_to_the_other_interfaces_when_the_interface_says_so(self):
        la, lb = self.two_links()
        hb = lb.hearer()
        d = self.lab.daemon(conf("[Interface]\nForwardQuestions=always\n[Segment]\nName=s\nInterfaces=ra,rb\n"))
        asker = la.device("10.9.1.50")
        asker.multicast(query(("_ipp._tcp.local", PTR)))
        got = hb.wait(asks("_ipp._tcp.local", PTR, src=lb.router_addr), 5)
        self.assertTrue(got, self.logs(d))

    def test_a_question_is_not_forwarded_when_the_interface_says_never(self):
        la, lb = self.two_links()
        hb = lb.hearer()
        d = self.lab.daemon(conf("[Interface]\nForwardQuestions=never\n[Segment]\nName=s\nInterfaces=ra,rb\n"))
        la.device("10.9.1.50").multicast(query(("_ipp._tcp.local", PTR)))
        d.settle()
        self.assertTrue(hb.none(asks("_ipp._tcp.local", PTR)))

    def test_a_question_is_forwarded_once_when_the_interface_says_once(self):
        la, lb = self.two_links()
        hb = lb.hearer()
        d = self.lab.daemon(conf("[Interface]\nName=rb\nForwardQuestions=once\n[Segment]\nName=s\nInterfaces=ra,rb\n"))
        asker = la.device("10.9.1.50")
        asker.multicast(query(("_ipp._tcp.local", PTR)))
        self.assertTrue(hb.wait(asks("_ipp._tcp.local", PTR, src=lb.router_addr), 5), "the first time it is asked\n" + self.logs(d))
        # Asked again, long after: it has been asked, so it is not, whatever is
        # heard of it. A question that is new is.
        d.advance(30)
        heard = hb.count()
        asker.multicast(query(("_ipp._tcp.local", PTR)))
        d.settle()
        self.assertTrue(hb.none(asks("_ipp._tcp.local", PTR), since=heard), "not a second time\n" + self.logs(d))
        asker.multicast(query(("_http._tcp.local", PTR)))
        self.assertTrue(hb.wait(asks("_http._tcp.local", PTR, src=lb.router_addr), 5, since=heard), "a new one\n" + self.logs(d))


class Topologies(Case):
    """Which networks hear of which, over several segments: what a segment
    reflects is what its interfaces heard themselves, not what was reflected
    onto them."""

    def three_links(self):
        la, lb = self.two_links()
        return la, lb, self.lab.link("rc", "10.9.3.1/24", "10.9.3.2/24")

    def test_a_chain_of_segments_is_not_followed_from_one_end_to_the_other(self):
        la, lb, lc = self.three_links()
        hb, hc = lb.hearer(), lc.hearer()
        d = self.lab.daemon(conf(
            "[Segment]\nName=ab\nInterfaces=ra,rb\nUntrusted=ra\n"
            "[Segment]\nName=bc\nInterfaces=rb,rc\nUntrusted=rb\n"))
        la.device("10.9.1.50").multicast(announcement("tv", "10.9.1.50", "TV"))
        self.assertTrue(hb.wait(alive("tv.local", A, "10.9.1.50")), "a is seen from b\n" + self.logs(d))
        d.settle()
        self.assertTrue(hc.none(lambda h: h.message.has("tv.local")), "but not from c, through b")

        lb.device("10.9.2.50").multicast(announcement("nas", "10.9.2.50", "NAS"))
        self.assertTrue(hc.wait(alive("nas.local", A, "10.9.2.50")), "b is seen from c\n" + self.logs(d))

    def told(self, hearer, link, host, **kind):
        """How many times `link`'s router told what `hearer` is on of `host`."""
        return len(hearer.matching(lambda h: h.src == link.router_addr and h.message.response and h.message.has(f"{host}.local", **kind)))

    def test_a_triangle_of_trusted_segments_tells_each_network_of_a_device_as_two_do_and_no_more(self):
        la, lb, lc = self.three_links()
        ha, hb, hc = la.hearer(), lb.hearer(), lc.hearer()
        d = self.lab.daemon(conf(
            "[Segment]\nName=ab\nInterfaces=ra,rb\n"
            "[Segment]\nName=bc\nInterfaces=rb,rc\n"
            "[Segment]\nName=ac\nInterfaces=ra,rc\n"))
        devices = [("tv", la, "10.9.1.50"), ("nas", lb, "10.9.2.50"), ("cam", lc, "10.9.3.50")]
        for host, link, addr in devices:
            link.device(addr).multicast(announcement(host, addr, host.upper()))
        links = [(la, ha), (lb, hb), (lc, hc)]
        for host, origin, addr in devices:
            for link, hearer in links:
                if link is not origin:
                    self.assertTrue(hearer.wait(alive(f"{host}.local", A, addr)), f"{host} on {link.router_addr}\n" + self.logs(d))
        # A device is announced twice, a second apart, as it is to one network.
        d.settle()
        d.advance(2)

        def counts():
            return {(host, link.router_addr): self.told(hearer, link, host) for host, _, _ in devices for link, hearer in links}

        first = counts()
        for host, origin, _ in devices:
            for link, _ in links:
                expected = 0 if link is origin else 2
                self.assertEqual(first[host, link.router_addr], expected, f"{host} on {link.router_addr}: {first}\n" + self.logs(d))

        # Nothing goes round: it stays quiet while the devices are fresh.
        d.advance(20)
        self.assertEqual(counts(), first, self.logs(d))

        # And when they are not, each network is told of a device's going once.
        d.advance(300)
        for host, origin, _ in devices:
            for link, hearer in links:
                if link is not origin:
                    self.assertEqual(self.told(hearer, link, host, goodbye=True), 1, f"{host} on {link.router_addr}\n" + self.logs(d))
                    self.assertEqual(self.told(hearer, link, host, alive=True), first[host, link.router_addr])
        self.assertEqual(self.told(ha, la, "tv"), 0, "never of where it is")

    def test_a_question_is_put_to_each_other_network_once_in_a_triangle_and_never_back(self):
        la, lb, lc = self.three_links()
        ha, hb, hc = la.hearer(), lb.hearer(), lc.hearer()
        d = self.lab.daemon(conf(
            "[Interface]\nForwardQuestions=always\n"
            "[Segment]\nName=ab\nInterfaces=ra,rb\n"
            "[Segment]\nName=bc\nInterfaces=rb,rc\n"
            "[Segment]\nName=ac\nInterfaces=ra,rc\n"))
        question = ("_ipp._tcp.local", PTR)
        def asked(link, hearer):
            return len(hearer.matching(lambda h: h.src == link.router_addr and h.message.asks(*question) and not h.message.response))

        self.assertTrue(hb.wait(asks(*PROBE)), self.logs(d))
        d.settle()
        before = [asked(la, ha), asked(lb, hb), asked(lc, hc)]

        la.device("10.9.1.50").multicast(query(question))
        self.assertTrue(hb.wait(asks(*question, src=lb.router_addr), 5), self.logs(d))
        self.assertTrue(hc.wait(asks(*question, src=lc.router_addr), 5), self.logs(d))
        d.settle()
        d.advance(20)
        after = [asked(la, ha), asked(lb, hb), asked(lc, hc)]
        self.assertEqual([x - y for x, y in zip(after, before)], [0, 1, 1], "once to each of the others, never back\n" + self.logs(d))

    def test_an_extra_segment_lets_one_end_of_a_chain_see_the_other(self):
        la, lb, lc = self.three_links()
        ha, hb, hc = la.hearer(), lb.hearer(), lc.hearer()
        d = self.lab.daemon(conf(
            "[Segment]\nName=ab\nInterfaces=ra,rb\nUntrusted=ra\n"
            "[Segment]\nName=bc\nInterfaces=rb,rc\nUntrusted=rb\n"
            "[Segment]\nName=ac\nInterfaces=ra,rc\nUntrusted=ra\n"))
        la.device("10.9.1.50").multicast(announcement("tv", "10.9.1.50", "TV"))
        self.assertTrue(hb.wait(alive("tv.local", A, "10.9.1.50")), self.logs(d))
        self.assertTrue(hc.wait(alive("tv.local", A, "10.9.1.50")), "a is seen from c\n" + self.logs(d))
        lc.device("10.9.3.50").multicast(announcement("cam", "10.9.3.50", "Cam"))
        d.settle()
        self.assertTrue(ha.none(lambda h: h.message.has("cam.local")), "c is not seen from a")

    def test_two_untrusted_interfaces_are_seen_from_the_trusted_one_and_not_from_each_other(self):
        la, lb, lc = self.three_links()
        ha, hb, hc = la.hearer(), lb.hearer(), lc.hearer()
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=ra,rb,rc\nUntrusted=ra,rb\n"))
        la.device("10.9.1.50").multicast(announcement("tv", "10.9.1.50", "TV"))
        lb.device("10.9.2.50").multicast(announcement("nas", "10.9.2.50", "NAS"))
        self.assertTrue(hc.wait(alive("tv.local", A, "10.9.1.50")), self.logs(d))
        self.assertTrue(hc.wait(alive("nas.local", A, "10.9.2.50")), self.logs(d))
        d.settle()
        self.assertTrue(ha.none(lambda h: h.message.has("nas.local")), "b is not seen from a")
        self.assertTrue(hb.none(lambda h: h.message.has("tv.local")), "a is not seen from b")


class Patterns(Case):
    """Interfaces named by a pattern: those there when the daemon starts, and
    those that come after."""

    @follows_changes
    def test_an_interface_a_pattern_matches_is_listened_to_whether_it_was_there_at_the_start_or_came_after(self):
        la, lb = self.two_links()
        ha, hb = la.hearer(), lb.hearer()
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=r?\n"))
        self.assertTrue(d.wait_log(r"ra: here \(index \d+\), listening", 5), self.logs(d))
        self.assertTrue(d.wait_log(r"rb: here \(index \d+\), listening", 5), self.logs(d))
        la.device("10.9.1.50").multicast(announcement("tv", "10.9.1.50", "TV"))
        self.assertTrue(hb.wait(alive("tv.local", A, "10.9.1.50")), "reflected between what the pattern matches\n" + self.logs(d))

        # One made after is listened to, told what is known, and heard.
        mark = d.mark()
        lc = self.lab.link("rc", "10.9.3.1/24", "10.9.3.2/24")
        hc = lc.hearer()
        self.assertTrue(d.wait_log(r"rc: here \(index \d+\), listening", 5, mark), self.logs(d))
        self.assertTrue(d.advance_until(lambda: hc.seen(alive("tv.local", A, "10.9.1.50"))), self.logs(d))
        lc.device("10.9.3.50").multicast(announcement("cam", "10.9.3.50", "Cam"))
        self.assertTrue(ha.wait(alive("cam.local", A, "10.9.3.50")), self.logs(d))
        self.assertEqual(d.request("segments")["segments"][0]["interfaces"], ["ra", "rb", "rc"])

        # And one that goes is forgotten.
        lc.delete()
        d.settle()
        self.assertTrue(not d.host("s", "cam.local"), self.logs(d))
        self.assertTrue(ha.wait(goodbye("cam.local", A, "10.9.3.50")), "withdrawn\n" + self.logs(d))
        self.assertEqual(d.request("segments")["segments"][0]["interfaces"], ["ra", "rb"])

    @follows_changes
    def test_interfaces_a_pattern_of_untrusted_names_match_are_told_nothing(self):
        lan = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        iot1 = self.lab.link("iot1", "10.9.2.1/24", "10.9.2.2/24")
        iot2 = self.lab.link("iot2", "10.9.3.1/24", "10.9.3.2/24")
        h_lan, h1, h2 = lan.hearer(), iot1.hearer(), iot2.hearer()
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=ra,iot*\nUntrusted=iot*\n"))
        self.assertTrue(d.wait_log(r"iot2: here", 5), self.logs(d))
        iot1.device("10.9.2.50").multicast(announcement("plug", "10.9.2.50", "Plug"))
        self.assertTrue(h_lan.wait(alive("plug.local", A, "10.9.2.50")), "what an untrusted one has is reflected out of it\n" + self.logs(d))
        lan.device("10.9.1.50").multicast(announcement("tv", "10.9.1.50", "TV"))
        d.settle()
        self.assertTrue(d.host("s", "tv.local"))
        self.assertTrue(h1.none(lambda h: h.message.has("tv.local") or h.message.has("plug.local")), "told nothing\n" + self.logs(d))
        self.assertTrue(h2.none(lambda h: h.message.has("tv.local") or h.message.has("plug.local")), "nor the other, of the first\n" + self.logs(d))

    def test_a_pattern_does_not_take_the_loopback_interface(self):
        self.two_links()
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=*\n"))
        self.assertTrue(d.wait_log(r"rb: here \(index \d+\), listening", 5), self.logs(d))
        self.assertTrue(d.wait_log(r"lo0?: a loopback interface", 5), self.logs(d))
        d.settle()
        self.assertEqual(d.request("segments")["segments"][0]["interfaces"], ["ra", "rb"])

    @follows_changes
    def test_an_interface_that_is_kept_out_is_not_listened_to(self):
        la, lb = self.two_links()
        lc = self.lab.link("rc", "10.9.3.1/24", "10.9.3.2/24")
        ha, hb, hc = la.hearer(), lb.hearer(), lc.hearer()
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=r?,!rc\n"))
        self.assertTrue(d.wait_log(r"rb: here \(index \d+\), listening", 5), self.logs(d))
        la.device("10.9.1.50").multicast(announcement("tv", "10.9.1.50", "TV"))
        self.assertTrue(hb.wait(alive("tv.local", A, "10.9.1.50")), self.logs(d))
        lc.device("10.9.3.50").multicast(announcement("cam", "10.9.3.50", "Cam"))
        d.settle()
        self.assertTrue(hc.none(lambda h: h.message.has("tv.local")), "kept out, so told nothing\n" + self.logs(d))
        self.assertTrue(ha.none(lambda h: h.message.has("cam.local")), "nor heard\n" + self.logs(d))
        self.assertNotIn("rc: here", self.logs(d))
        self.assertEqual(d.request("segments")["segments"][0]["interfaces"], ["ra", "rb"])

    def test_a_pattern_that_matches_nothing_is_waited_on(self):
        la, _ = self.two_links()
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=ra,zz*\n"))
        d.settle()
        self.assertIsNone(d.proc.poll(), self.logs(d))
        self.assertEqual(d.request("segments")["segments"][0]["interfaces"], ["ra"])


class ServiceTypes(Case):
    """Which of a device's services are reflected: ReflectedServices=."""

    def device(self, host, addr, *services):
        """What a device that has `host` at `addr` announces: a service of each
        of `services`, (instance, type)."""
        records = [a(f"{host}.local", addr)]
        for instance, kind in services:
            full = f"{instance}.{kind}.local"
            records += [ptr(f"{kind}.local", full, 120), srv(full, 631, f"{host}.local", 120), txt(full, "k=v", ttl=120)]
        return response(*records)

    def world(self, filtering, segments=None):
        la, lb = self.two_links()
        hb = lb.hearer()
        d = self.lab.daemon(conf(segments or f"[Segment]\nName=s\nInterfaces=ra,rb\n{filtering}\n"))
        dev = la.device("10.9.1.50")
        dev.multicast(self.device("office", "10.9.1.50", ("Office", "_ipp._tcp"), ("Shell", "_ssh._tcp")))
        dev.multicast(self.device("box", "10.9.1.51", ("Box", "_ssh._tcp")))
        return d, hb

    def overlapping(self, narrow_first):
        """A segment of every interface and one of two of them with a filter,
        in the order given: what the other network hears of the two devices."""
        everything = "[Segment]\nName=all\nInterfaces=r*\n"
        narrow = "[Segment]\nName=ipp\nInterfaces=ra,rb\nReflectedServices=_ipp._tcp\n"
        d, hb = self.world("", (narrow + everything) if narrow_first else (everything + narrow))
        self.assertTrue(hb.wait(alive("office.local", A, "10.9.1.50")), self.logs(d))
        self.assertTrue(hb.wait(alive("box.local", A, "10.9.1.51")), "the broader segment reflects what the narrower would not\n" + self.logs(d))
        d.settle()
        return hb.seen(alive("Shell._ssh._tcp.local", SRV)) is not None, hb.seen(alive("Office._ipp._tcp.local", SRV)) is not None

    def test_overlapping_segments_reflect_what_either_would_with_the_broader_one_first(self):
        self.assertEqual(self.overlapping(narrow_first=False), (True, True))

    def test_overlapping_segments_reflect_what_either_would_with_the_narrower_one_first(self):
        # Where they are in the file does not matter.
        self.assertEqual(self.overlapping(narrow_first=True), (True, True))

    def test_only_the_service_types_named_are_reflected_and_a_device_with_none_of_them_not_at_all(self):
        d, hb = self.world("ReflectedServices=_ipp._tcp")
        self.assertTrue(hb.wait(alive("office.local", A, "10.9.1.50")), self.logs(d))
        self.assertTrue(hb.wait(alive("Office._ipp._tcp.local", SRV, "631 office.local")), self.logs(d))
        d.settle()
        self.assertTrue(hb.none(lambda h: h.message.has("Shell._ssh._tcp.local")), "its other service is kept back")
        self.assertTrue(hb.none(lambda h: h.message.has("_ssh._tcp.local")))
        self.assertTrue(hb.none(lambda h: h.message.has("box.local")), "a device with only that is not reflected")
        self.assertEqual([x["addresses"] for x in d.host("s", "box.local")], [["10.9.1.51"]], "though it is known")

    def test_a_service_type_that_is_kept_out_is_not_reflected_whatever_else_is(self):
        d, hb = self.world("ReflectedServices=_ipp._tcp, _ssh._tcp, !_SSH._tcp")
        self.assertTrue(hb.wait(alive("Office._ipp._tcp.local", SRV, "631 office.local")), self.logs(d))
        d.settle()
        self.assertTrue(hb.none(lambda h: h.message.has("_ssh._tcp.local")))
        self.assertTrue(hb.none(lambda h: h.message.has("box.local")))

    def test_every_type_but_the_ones_kept_out_is_reflected(self):
        d, hb = self.world("ReflectedServices=!_ssh._tcp")
        self.assertTrue(hb.wait(alive("Office._ipp._tcp.local", SRV, "631 office.local")), self.logs(d))
        d.settle()
        self.assertTrue(hb.none(lambda h: h.message.has("_ssh._tcp.local")))
        self.assertTrue(hb.none(lambda h: h.message.has("box.local")))


class IPv6(Case):
    """What is said over IPv6, as the devices of the other scenarios, which speak
    IPv4 whatever addresses they have, do not."""

    # FreeBSD's sockets are not yet tried with a device that speaks it.
    @unittest.skipIf(FREEBSD, "not yet tried with a device that speaks IPv6")
    def test_a_device_that_announces_over_ipv6_is_heard_and_reflected(self):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        la.add_router_addr("fd00:9::1/64")
        lb = self.lab.link("rb", "10.9.2.1/24", "10.9.2.2/24")
        hb = lb.hearer()
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=ra,rb\n", ipv6=True))
        tv = la.device6("fd00:9::50")
        tv.multicast(response(aaaa("tv.local", "fd00:9::50"), srv("TV._http._tcp.local", 80, "tv.local"),
                              ptr("_http._tcp.local", "TV._http._tcp.local")))
        self.assertTrue(hb.wait(alive("tv.local", AAAA, "fd00:9::50")), "reflected\n" + self.logs(d))
        self.assertTrue(hb.wait(alive("TV._http._tcp.local", SRV, "80 tv.local")), self.logs(d))
        d.settle()
        listed = d.host("s", "tv.local")
        self.assertEqual([x["addresses"] for x in listed], [["fd00:9::50"]], listed)
        self.assertEqual(listed[0]["interface"], "ra")


class Vlans(Case):
    """Interfaces that are VLANs of one link, as a router has them: each a
    network of its own, over the same wire."""

    def vlans(self):
        trunk = self.lab.trunk("ra")
        return trunk, trunk.vlan(10, "10.10.0.1/24", "10.10.0.2/24"), trunk.vlan(20, "10.20.0.1/24", "10.20.0.2/24")

    def test_a_device_on_one_vlan_is_reflected_to_another_and_not_back(self):
        _, v10, v20 = self.vlans()
        h10, h20 = v10.hearer(), v20.hearer()
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=ra.10,ra.20\n"))
        v10.device("10.10.0.50").multicast(announcement("tv", "10.10.0.50", "TV"))
        self.assertTrue(h20.wait(alive("tv.local", A, "10.10.0.50")), self.logs(d))
        d.settle()
        self.assertTrue(h10.none(lambda h: h.src == v10.router_addr and h.message.has("tv.local", A)), "reflected back")
        listed = d.host("s", "tv.local")
        self.assertEqual([(x["interface"], x["addresses"]) for x in listed], [("ra.10", ["10.10.0.50"])], listed)

    def test_vlans_that_share_no_segment_are_kept_apart(self):
        _, v10, v20 = self.vlans()
        h20 = v20.hearer()
        d = self.lab.daemon(conf("[Segment]\nName=a\nInterfaces=ra.10\n[Segment]\nName=b\nInterfaces=ra.20\n"))
        v10.device("10.10.0.50").multicast(announcement("tv", "10.10.0.50", "TV"))
        d.settle()
        self.assertTrue(d.host("a", "tv.local"), "heard where it is\n" + self.logs(d))
        self.assertEqual(d.host("b", "tv.local"), [], "and not of the other")
        self.assertTrue(h20.none(lambda h: h.message.has("tv.local")), "told of it on the other VLAN")

    def test_a_name_is_advertised_on_the_vlan_it_names_and_not_on_the_other(self):
        _, v10, v20 = self.vlans()
        h10, h20 = v10.hearer(), v20.hearer()
        d = self.lab.daemon(conf("[Advertise]\nHostname=pc\nInterface=ra.10\n[Segment]\nName=s\nInterfaces=ra.10,ra.20\n"))
        self.assertTrue(h10.wait(alive("pc.local", A, "10.10.0.1")), self.logs(d))
        # Asked for on the other, it does not answer.
        v20.device("10.20.0.50").multicast(query(("pc.local", A)))
        d.settle()
        self.assertTrue(h20.none(lambda h: h.message.has("pc.local")), "advertised on the other VLAN")

    @follows_changes
    def test_a_vlan_that_is_made_after_the_daemon_started_is_listened_to_and_told_what_is_known(self):
        trunk = self.lab.trunk("ra")
        v10 = trunk.vlan(10, "10.10.0.1/24", "10.10.0.2/24")
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=ra.10,ra.20\n"))
        self.assertTrue(d.wait_log(r"ra\.20: not there yet", 5), self.logs(d))
        v10.device("10.10.0.50").multicast(announcement("tv", "10.10.0.50", "TV"))
        d.settle()
        v20 = trunk.vlan(20, "10.20.0.1/24", "10.20.0.2/24")
        h20 = v20.hearer()
        self.assertTrue(d.wait_log(r"ra\.20: here \(index \d+\), listening", 5), self.logs(d))
        self.assertTrue(d.advance_until(lambda: h20.seen(alive("tv.local", A, "10.10.0.50"))), "what is known is announced on it\n" + self.logs(d))


class Bridges(Case):
    """A bridge of the router, with the devices on its ports and the address on the
    bridge: what the daemon is on is the bridge, and what comes in on a port is the
    bridge's."""

    def world(self, ports=2):
        bridge = self.lab.bridge("br0", "10.9.1.1/24")
        ports = [bridge.port(f"rp{i + 1}", f"10.9.1.{i + 2}/24") for i in range(ports)]
        return bridge, ports, self.lab.link("rc", "10.9.3.1/24", "10.9.3.2/24")

    def test_devices_on_every_port_of_a_bridge_are_heard_as_on_the_bridge_and_reflected(self):
        bridge, (p1, p2), other = self.world()
        ho = other.hearer()
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=br0,rc\n"))
        p1.device("10.9.1.50").multicast(announcement("tv", "10.9.1.50", "TV"))
        p2.device("10.9.1.60").multicast(announcement("nas", "10.9.1.60", "NAS"))
        self.assertTrue(ho.wait(alive("tv.local", A, "10.9.1.50")), self.logs(d))
        self.assertTrue(ho.wait(alive("nas.local", A, "10.9.1.60")), self.logs(d))
        d.settle()
        for host in ("tv.local", "nas.local"):
            self.assertEqual([x["interface"] for x in d.host("s", host)], ["br0"], f"{host}: on the bridge, not a port\n" + self.logs(d))

    def test_what_is_sent_to_a_bridge_is_heard_on_every_port_from_its_address(self):
        bridge, (p1, p2), other = self.world()
        h1, h2 = p1.hearer(), p2.hearer()
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=br0,rc\n"))
        other.device("10.9.3.50").multicast(announcement("cam", "10.9.3.50", "Cam"))
        for h in (h1, h2):
            got = h.wait(alive("cam.local", A, "10.9.3.50"))
            self.assertTrue(got, self.logs(d))
            self.assertEqual(got.src, bridge.router_addr)

    def test_a_name_advertised_on_a_bridge_is_heard_on_every_port(self):
        bridge, (p1, p2), _ = self.world()
        h1, h2 = p1.hearer(), p2.hearer()
        d = self.lab.daemon(conf("[Advertise]\nHostname=pc\nInterface=br0\n[Segment]\nName=s\nInterfaces=br0\n"))
        for h in (h1, h2):
            self.assertTrue(h.wait(alive("pc.local", A, bridge.router_addr)), self.logs(d))

    def test_a_port_added_after_the_daemon_started_is_heard(self):
        bridge, _, other = self.world(ports=1)
        ho = other.hearer()
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=br0,rc\n"))
        late = bridge.port("rp2", "10.9.1.3/24")
        late.device("10.9.1.70").multicast(announcement("printer", "10.9.1.70", "Printer"))
        self.assertTrue(ho.wait(alive("printer.local", A, "10.9.1.70")), self.logs(d))


class Interfaces(Case):
    @follows_changes
    @unittest.skipIf(FREEBSD, "the flood is made with iproute2")
    def test_what_the_kernel_had_no_room_to_say_is_found_by_looking_again(self):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=r?\n"))
        self.assertTrue(d.wait_log(r"ra: here \(index \d+\), listening", 5), self.logs(d))
        # While it is not reading, more happens than its socket has room for, and
        # after that an interface comes, which the kernel has no room to tell it of.
        os.kill(d.proc.pid, signal.SIGSTOP)
        try:
            flood = "".join(
                f"neigh replace 10.{n >> 16 & 255}.{n >> 8 & 255}.{n % 253 + 1} lladdr 02:00:00:00:{n >> 8 & 255:02x}:{n & 255:02x} dev ra nud permanent\n"
                for n in range(20000))
            subprocess.run([*self.lab.net.router_argv(), "ip", "-batch", "-"], input=flood, text=True, check=True, timeout=60)
            self.lab.link("rb", "10.9.2.1/24", "10.9.2.2/24")
        finally:
            os.kill(d.proc.pid, signal.SIGCONT)
        self.assertTrue(d.wait_log(r"rb: here \(index \d+\), listening", 10), "found by looking again\n" + self.logs(d))

    @follows_changes
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
        late.delete()
        self.assertTrue(d.wait_log(r"late: (gone|down); waiting for it to come", 5, mark), self.logs(d))
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
        late.delete()
        d.settle()
        self.assertTrue(not d.host("s", "cam.local"), "what was heard there is forgotten\n" + self.logs(d))
        self.assertEqual(d.stop(), 0)

    @follows_changes
    def test_an_interface_that_goes_down_and_comes_up_is_announced_on_again(self):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        ha = la.hearer()
        d = self.lab.daemon(conf("[Advertise]\nHostname=pc\n[Segment]\nName=s\nInterfaces=ra\n"))
        self.assertTrue(ha.wait(alive("pc.local", A, "10.9.1.1")), self.logs(d))
        la.set_router_up(False)
        d.settle()
        mark, heard = d.mark(), ha.count()
        la.set_router_up(True)
        self.assertTrue(d.wait_log(r"ra: up$", 5, mark), self.logs(d))
        self.assertTrue(ha.wait(alive("pc.local", A, "10.9.1.1"), 5, since=heard), "announced again\n" + self.logs(d))
        self.assertTrue(d.advance_until(lambda: ha.seen(asks(*PROBE), heard)), "and asked on again")

    def test_a_daemon_starts_where_an_interface_has_no_ipv4_address_yet(self):
        self.lab.link("ra", None, "10.9.1.2/24")
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=ra\n", ipv6=True))
        d.settle()
        self.assertIsNone(d.proc.poll(), "it waits for the address; it does not stop\n" + self.logs(d))

    @follows_changes
    def test_ipv6_is_listened_to_while_ipv4_waits_for_an_address(self):
        la = self.lab.link("ra", None, "10.9.1.2/24")
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=ra\n", ipv6=True))
        self.assertTrue(d.wait_log(r"listening on ra \(V6\)", 5), self.logs(d))
        la.add_router_addr("10.9.1.1/24")
        self.assertTrue(d.wait_log(r"listening on ra \(V4\)", 5), self.logs(d))

    @follows_changes
    def test_an_interface_that_is_up_before_it_has_an_address_is_waited_for_when_the_daemon_starts(self):
        # As one is that is yet to be given its address, by DHCP, when the daemon starts at boot.
        la = self.lab.link("ra", None, "10.9.1.2/24")
        ha = la.hearer()
        d = self.lab.daemon(conf("[Advertise]\nHostname=pc\n[Segment]\nName=s\nInterfaces=ra\n"))
        la.add_router_addr("10.9.1.1/24")
        self.assertTrue(d.advance_until(lambda: ha.seen(alive("pc.local", A, "10.9.1.1"))), "it is listened to when it has one\n" + self.logs(d))

    @follows_changes
    def test_an_interface_that_appears_before_it_has_an_address_is_listened_to_when_it_gets_one(self):
        d = self.lab.daemon(conf("[Advertise]\nHostname=pc\n[Segment]\nName=s\nInterfaces=ra\n"))
        la = self.lab.link("ra", None, "10.9.1.2/24")
        ha = la.hearer()
        la.add_router_addr("10.9.1.1/24")
        self.assertTrue(d.advance_until(lambda: ha.seen(alive("pc.local", A, "10.9.1.1"))), "and announces on it\n" + self.logs(d))
        self.assertTrue(d.advance_until(lambda: ha.seen(asks(*PROBE))), "and probes it\n" + self.logs(d))
        # It is a device that is heard from too, where it did not hear before.
        la.device("10.9.1.50").multicast(announcement("tv", "10.9.1.50", "TV"))
        d.settle()
        self.assertTrue(d.host("s", "tv.local"), self.logs(d))

    @follows_changes
    def test_a_change_of_mtu_is_taken(self):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=ra\n"))
        self.assertTrue(d.wait_log(r"ra: MTU is 1500", 2), self.logs(d))
        mark = d.mark()
        la.set_router_mtu(1400)
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

    @follows_changes
    def test_the_advertised_name_follows_the_interfaces_addresses(self):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        ha = la.hearer()
        d = self.lab.daemon(conf("[Advertise]\nHostname=pc\n[Segment]\nName=s\nInterfaces=ra\n"))
        self.assertTrue(ha.wait(alive("pc.local", A, "10.9.1.1")))
        # A second address is announced.
        la.add_router_addr("10.9.1.9/24")
        self.assertTrue(ha.wait(alive("pc.local", A, "10.9.1.9"), 5), self.logs(d))
        # The one that goes is retracted, with a goodbye.
        la.del_router_addr("10.9.1.9/24")
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
        self.lab.net.relax_source_checks()
        d = self.lab.daemon(f"[Interface]\nIPv4={listen}\nIPv6=off\n[Segment]\nName=s\nInterfaces=ra\n")
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

    def test_it_is_heard_on_the_interface_that_listens_for_it_and_not_on_the_one_that_does_not(self):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        lb = self.lab.link("rb", "10.9.2.1/24", "10.9.2.2/24")
        self.lab.net.relax_source_checks()
        d = self.lab.daemon(
            "[Interface]\nIPv6=off\n[Interface]\nName=ra\nIPv4=multicast\n"
            "[Segment]\nName=a\nInterfaces=ra\n[Segment]\nName=b\nInterfaces=rb\n"
        )
        la.device("10.9.1.50").unicast(announcement("tv", "10.9.1.50", "TV"), "10.9.1.1")
        lb.device("10.9.2.50").unicast(announcement("nas", "10.9.2.50", "NAS"), "10.9.2.1")
        d.settle()
        self.assertTrue(d.host("b", "nas.local"), self.logs(d))
        self.assertEqual(d.host("a", "tv.local"), [], "ra is to hear the group alone, whatever rb does")

    def test_it_is_not_heard_from_a_host_that_is_not_on_the_link(self):
        d = self.world("on", source="192.168.77.5")
        d.settle()
        self.assertEqual(d.host("s", "tv.local"), [], "a host routed in is not believed")


class Peers(Case):
    """An interface that talks to a host alone, as a tunnel does that cannot carry
    multicast: the peer is a device that is the other daemon, and the other
    interface is a link as any."""

    def daemon(self, config):
        """The daemon, unless it cannot talk to a peer: a socket for each interface, which
        the BSDs, and the sockets shared by every interface, do not have, is what it takes."""
        try:
            return self.lab.daemon(config)
        except RuntimeError as e:
            if "which this system cannot make" in str(e):
                self.skipTest("a peer needs a socket of the interface's own")
            raise

    def world(self, interface="Peer=10.9.1.2", segment="Interfaces=ra,rb"):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        lb = self.lab.link("rb", "10.9.2.1/24", "10.9.2.2/24")
        # A packet from an address that is not on the link is not for the kernel to drop.
        self.lab.net.relax_source_checks()
        d = self.daemon(f"[Interface]\nIPv6=off\n[Interface]\nName=ra\n{interface}\n[Segment]\nName=s\n{segment}\n")
        peer = la.device("10.9.1.2")
        return la, lb, d, peer

    def test_what_the_peer_sends_is_heard_and_reflected_to_the_other_interface(self):
        la, lb, d, peer = self.world()
        hb = lb.hearer()
        peer.unicast(announcement("tv", "10.9.8.50", "TV"), "10.9.1.1")
        d.settle()
        self.assertTrue(d.host("s", "tv.local"), self.logs(d))
        self.assertTrue(hb.wait(alive("tv.local", A, "10.9.8.50")), self.logs(d))

    def test_what_is_reflected_to_the_peer_is_sent_to_it_alone(self):
        la, lb, d, peer = self.world()
        pc = lb.device("10.9.2.50")
        pc.multicast(announcement("pc", "10.9.2.50", "PC"))
        d.settle()
        heard = peer.hearer.wait(alive("pc.local", A, "10.9.2.50"))
        self.assertTrue(heard, self.logs(d))
        self.assertFalse(heard.to_group, "to the peer, not to a group")
        # Nothing went to the group on the interface.
        self.assertTrue(la.hearer().none(lambda h: h.message.has("pc.local")))

    def test_a_host_that_is_not_the_peer_is_not_heard(self):
        la, lb, d, peer = self.world()
        other = la.device("10.9.1.60")
        other.unicast(announcement("tv", "10.9.8.50", "TV"), "10.9.1.1")
        other.multicast(announcement("tv", "10.9.8.50", "TV"))
        d.settle()
        self.assertEqual(d.host("s", "tv.local"), [], "it is not the peer")

    def test_an_untrusted_peer_is_told_nothing_of_the_others_and_its_devices_are_reflected(self):
        la, lb, d, peer = self.world(segment="Interfaces=ra,rb\nUntrusted=ra")
        hb = lb.hearer()
        peer.unicast(announcement("tv", "10.9.8.50", "TV"), "10.9.1.1")
        lb.device("10.9.2.50").multicast(announcement("pc", "10.9.2.50", "PC"))
        d.settle()
        self.assertTrue(hb.wait(alive("tv.local", A, "10.9.8.50")), self.logs(d))
        self.assertTrue(peer.hearer.none(lambda h: h.message.has("pc.local")), "nothing is announced to it")

    def test_every_peer_of_an_interface_is_sent_to_and_heard(self):
        la, lb, d, peer = self.world(interface="Peer=10.9.1.2, 10.9.1.3")
        second = la.device("10.9.1.3")
        second.unicast(announcement("nas", "10.9.8.60", "NAS"), "10.9.1.1")
        lb.device("10.9.2.50").multicast(announcement("pc", "10.9.2.50", "PC"))
        d.settle()
        self.assertTrue(d.host("s", "nas.local"), self.logs(d))
        for who in (peer, second):
            self.assertTrue(who.hearer.wait(alive("pc.local", A, "10.9.2.50")), self.logs(d))

    def test_a_peer_is_at_the_port_that_is_said(self):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        lb = self.lab.link("rb", "10.9.2.1/24", "10.9.2.2/24")
        d = self.daemon("[Interface]\nIPv6=off\n[Interface]\nName=ra\nPeer=10.9.1.2\nPeerPort=5454\n[Segment]\nName=s\nInterfaces=ra,rb\n")
        peer = la.device("10.9.1.2", port=5454)
        peer.unicast(announcement("tv", "10.9.8.50", "TV"), "10.9.1.1", port=5454)
        lb.device("10.9.2.50").multicast(announcement("pc", "10.9.2.50", "PC"))
        d.settle()
        self.assertTrue(d.host("s", "tv.local"), self.logs(d))
        self.assertTrue(peer.hearer.wait(alive("pc.local", A, "10.9.2.50")), self.logs(d))


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
        self.assertTrue(d.advance_until_exits(ctl), "and it is told when it is done")
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
            ("[Interface]\nIPv4=off\nIPv6=off\n[Segment]\nName=s\nInterfaces=ra\n", r"both off"),
            ("[Interface]\nIPv4=yes\n[Segment]\nName=s\nInterfaces=ra\n", r"must be off, multicast or on"),
            ("[Advertise]\nServices=_ssh._tcp:22\n[Segment]\nName=s\nInterfaces=ra\n", r"no Hostname="),
            ("[Advertise]\nHostname=pc\nInterface=other\n[Segment]\nName=s\nInterfaces=ra\n", r"not in any segment"),
            ("[Advertise]\nHostname=pc\n[Advertise]\nHostname=pc\n[Segment]\nName=s\nInterfaces=ra\n", r"same interface"),
            ("[Advertise]\nHostname=router.lan\n[Segment]\nName=s\nInterfaces=ra\n", r"not under \.local"),
            ("[Segment]\nName=s\nInterfaces=ra\nReflectedWhen=hostname\nReflectedServices=_ipp._tcp\n", r"without enabling service filtering"),
            ("[Segment]\nName=s\nInterfaces=ra\nReflectedServices=ipp\n", r"invalid ReflectedServices"),
            ("[Segment]\nName=s\nInterfaces=ra,rb\n[Segment]\nName=t\nInterfaces=rb,rc,ra\n", r'segments "s" and "t" both reflect between (ra and rb|rb and ra)'),
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


@follows_changes
class Neighbours(Case):
    def test_addresses_the_neighbour_table_has_for_a_device_are_learned(self):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        la.add_router_addr("fd00:9::1/64")
        la.add_peer_cidr("fd00:9::2/64")
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=ra\n", ipv6=True))
        mac = "02:00:00:00:00:50"
        # The device announces an IPv4 address and a link-local IPv6 one, and
        # is known to the router's neighbour table at a routable one too.
        la.neighbour("fd00:9::50", mac)
        la.neighbour("10.9.1.50", mac)
        dev = la.device("10.9.1.50")
        dev.multicast(response(a("tv.local", "10.9.1.50"), aaaa("tv.local", "fe80::50"), srv("TV._http._tcp.local", 80, "tv.local"),
                               ptr("_http._tcp.local", "TV._http._tcp.local")))
        d.settle()
        learned = (d.host("s", "tv.local") or [{}])[0].get("neighbour_addresses")
        self.assertEqual(learned, ["fd00:9::50"], self.logs(d))
        # The entry goes, and so does what was learned of it.
        la.forget_neighbour("fd00:9::50")
        d.settle()
        self.assertTrue(not d.host("s", "tv.local")[0]["neighbour_addresses"], d.host("s", "tv.local"))

    def v6_link(self):
        """A link with IPv6 on both ends, a device's far end of it and the router's."""
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        la.add_router_addr("fd00:9::1/64")
        la.add_peer_cidr("fd00:9::2/64")
        return la

    def known(self, d, host="tv.local"):
        """What the daemon has of `host`, after what it was sent."""
        d.settle()
        listed = d.host("s", host)
        self.assertTrue(listed, d.devices("s"))
        return listed[0]

    def test_the_kernel_is_asked_to_find_a_device_with_only_a_link_local_address_and_what_it_has_is_learned(self):
        la = self.v6_link()
        la.add_peer_cidr("fe80::50/64")
        mac = la.peer_mac()
        # The router knows the device at a routable address already, under the
        # link-layer address its link-local one is to be found at.
        la.neighbour("fd00:9::2", mac)
        watch = self.lab.neighbours("ra")
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=ra\n", ipv6=True))
        la.device("10.9.1.50").multicast(response(aaaa("tv.local", "fe80::50"), srv("TV._http._tcp.local", 80, "tv.local"),
                                                  ptr("_http._tcp.local", "TV._http._tcp.local")))
        d.settle()
        # It has no routable address, so the kernel is made to look the link-local one up: the
        # daemon asks it a question there, and the table has it.
        self.assertTrue(watch.wait(self.lab.net.neighbour_seen("fe80::50", mac)), "the kernel found it\n" + self.logs(d))
        tv = self.known(d)
        self.assertEqual(tv["neighbour_addresses"], ["fd00:9::2"], self.logs(d))
        self.assertEqual(tv["addresses"], ["fd00:9::2", "fe80::50"])

    @unittest.skipIf(FREEBSD, "FreeBSD's netlink does not tell of an entry for an address that no network of the interface has")
    def test_an_address_in_a_network_the_interface_is_not_on_is_learned_when_it_is(self):
        la = self.v6_link()
        mac = "02:00:00:00:00:50"
        la.neighbour("10.9.1.50", mac)
        la.neighbour("fd00:7::50", mac)
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=ra\n", ipv6=True))
        la.device("10.9.1.50").multicast(announcement("tv", "10.9.1.50", "TV"))
        self.assertEqual(self.known(d)["neighbour_addresses"], [], "the interface is not on fd00:7::/64")
        la.add_router_addr("fd00:7::1/64")
        self.assertEqual(self.known(d)["neighbour_addresses"], ["fd00:7::50"], "and is, now")
        la.del_router_addr("fd00:7::1/64")
        self.assertEqual(self.known(d)["neighbour_addresses"], [], "and is not again")

    def test_an_entry_that_comes_after_the_device_was_heard_is_learned_and_forgotten_when_it_changes_hands(self):
        la = self.v6_link()
        mac, other = "02:00:00:00:00:50", "02:00:00:00:00:51"
        la.neighbour("10.9.1.50", mac)
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=ra\n", ipv6=True))
        la.device("10.9.1.50").multicast(announcement("tv", "10.9.1.50", "TV"))
        self.assertEqual(self.known(d)["neighbour_addresses"], [])
        # Another address under its link-layer address turns up in the table.
        la.neighbour("fd00:9::50", mac)
        self.assertEqual(self.known(d)["neighbour_addresses"], ["fd00:9::50"])
        # It is another device that has it now.
        la.neighbour("fd00:9::50", other)
        self.assertEqual(self.known(d)["neighbour_addresses"], [], "no longer the device's")
        # And it is the device's again, with another beside it.
        la.neighbour("fd00:9::50", mac)
        la.neighbour("fd00:9::51", mac)
        self.assertEqual(self.known(d)["neighbour_addresses"], ["fd00:9::50", "fd00:9::51"])

    def test_nothing_is_learned_of_a_family_the_device_announced_a_routable_address_of(self):
        la = self.v6_link()
        mac = "02:00:00:00:00:50"
        for ip in ("10.9.1.50", "10.9.1.51"):
            la.neighbour(ip, mac)
        for ip in ("fd00:9::50", "fd00:9::51"):
            la.neighbour(ip, mac)
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=ra\n", ipv6=True))
        # It says what it has of both families: what it announces is what it has.
        la.device("10.9.1.50").multicast(response(a("tv.local", "10.9.1.50"), aaaa("tv.local", "fd00:9::50"),
                                                  srv("TV._http._tcp.local", 80, "tv.local"), ptr("_http._tcp.local", "TV._http._tcp.local")))
        tv = self.known(d)
        self.assertEqual(tv["neighbour_addresses"], [], self.logs(d))
        self.assertEqual(tv["addresses"], ["10.9.1.50", "fd00:9::50"])


class Timers(Case):
    """What happens as time passes, which the daemon's clock is moved forward
    for."""

    def test_a_device_about_to_expire_is_asked_at_its_own_address_and_then_on_the_group(self):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        ha = la.hearer()
        d = self.lab.daemon(conf("[Interface]\nRefreshBefore=30s\nMinimumLifetime=40s\n[Segment]\nName=s\nInterfaces=ra\n"))
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
        d = self.lab.daemon(conf("[Interface]\nRefreshBefore=30s\nMinimumLifetime=0\n[Segment]\nName=s\nInterfaces=ra\n"))
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

    def test_a_ttl_of_a_second_is_kept_the_minute_and_asked_once_in_it(self):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        d = self.lab.daemon(conf("[Interface]\nRefreshBefore=30s\n[Segment]\nName=s\nInterfaces=ra\n"))
        dev = la.device("10.9.1.50")
        dev.multicast(announcement("dev", "10.9.1.50", ttl=1))
        d.settle()
        asked = dev.hearer.count()
        d.advance(44)
        self.assertTrue(d.host("s", "dev.local"), "kept, not dropped after its second")
        self.assertTrue(dev.hearer.none(asks("dev.local", A), since=asked), "and not asked about every few seconds")
        d.advance(2)
        got = dev.hearer.seen(asks("dev.local", A), asked) or dev.hearer.wait(asks("dev.local", A), 5, since=asked)
        self.assertTrue(got, "asked three quarters of the minute in\n" + self.logs(d))
        d.advance(10)
        self.assertEqual(len(dev.hearer.matching(asks("dev.local", A), asked)), 1, "once")
        d.advance(5)
        self.assertFalse(d.host("s", "dev.local"))

    def probing(self, d):
        """What of a probe is still to be done: its rounds, not the next one's start."""
        timers = d.request("timers")["timers"]
        return [p for t in timers for p in t["pending"] if p["what"] == "probe" and "as configured" not in p["who"]]

    def test_an_interface_is_probed_again_every_probe_interval(self):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        ha = la.hearer()
        d = self.lab.daemon(conf("[Interface]\nProbeInterval=1min\n[Segment]\nName=s\nInterfaces=ra\n"))
        self.assertTrue(d.advance_until(lambda: ha.seen(asks(*PROBE))), "probed at startup\n" + self.logs(d))
        self.assertTrue(d.advance_until(lambda: not self.probing(d), step=1), "and the rounds of that are done")
        heard = ha.count()
        # The interval is between the starts of two probes: a minute from the first.
        d.advance(30)
        self.assertTrue(ha.none(asks(*PROBE), since=heard), "not yet")
        d.advance(30)
        self.assertTrue(d.advance_until(lambda: ha.seen(asks(*PROBE), heard), step=1, limit=10), "and again\n" + self.logs(d))
        # And again after that.
        self.assertTrue(d.advance_until(lambda: not self.probing(d), step=1))
        heard = ha.count()
        d.advance(60)
        self.assertTrue(d.advance_until(lambda: ha.seen(asks(*PROBE), heard), step=1, limit=10), "every time")

    def test_the_types_an_interface_is_told_to_probe_for_are_asked_at_startup(self):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        ha = la.hearer()
        d = self.lab.daemon(conf("[Interface]\nProbeServices=_http._tcp\n[Segment]\nName=s\nInterfaces=ra\n"))
        self.assertTrue(d.advance_until(lambda: ha.seen(asks("_http._tcp.local", PTR))), "asked for\n" + self.logs(d))

    @follows_changes
    def test_the_types_are_asked_on_an_interface_that_appears_late_and_on_one_that_comes_back(self):
        d = self.lab.daemon(conf("[Interface]\nProbeServices=_http._tcp\n[Segment]\nName=s\nInterfaces=ra\n"))
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        ha = la.hearer()
        self.assertTrue(d.advance_until(lambda: ha.seen(asks(*PROBE)) and ha.seen(asks("_http._tcp.local", PTR))), "probed when it appears\n" + self.logs(d))
        la.set_router_up(False)
        d.settle()
        mark, heard = d.mark(), ha.count()
        la.set_router_up(True)
        self.assertTrue(d.wait_log(r"ra: up$", 5, mark), self.logs(d))
        self.assertTrue(d.advance_until(lambda: ha.seen(asks("_http._tcp.local", PTR), heard)), "and when it is back")

    def test_each_interface_of_a_segment_is_probed_for_its_own_types(self):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        lb = self.lab.link("rb", "10.9.2.1/24", "10.9.2.2/24")
        ha, hb = la.hearer(), lb.hearer()
        d = self.lab.daemon(conf("[Interface]\nName=ra\nProbeServices=_http._tcp\n[Interface]\nName=rb\nProbeServices=_ssh._tcp\n[Segment]\nName=s\nInterfaces=ra,rb\n"))
        self.assertTrue(d.advance_until(lambda: ha.seen(asks("_http._tcp.local", PTR)) and hb.seen(asks("_ssh._tcp.local", PTR))), self.logs(d))
        self.assertTrue(d.advance_until(lambda: not self.probing(d), step=1))
        self.assertTrue(ha.none(asks("_ssh._tcp.local", PTR)) and hb.none(asks("_http._tcp.local", PTR)), "and not for the other's")

    def test_an_interface_with_no_probe_interval_is_only_probed_at_startup_and_on_request(self):
        la = self.lab.link("ra", "10.9.1.1/24", "10.9.1.2/24")
        ha = la.hearer()
        d = self.lab.daemon(conf("[Segment]\nName=s\nInterfaces=ra\n"))
        self.assertTrue(d.advance_until(lambda: ha.seen(asks(*PROBE))), "probed at startup\n" + self.logs(d))
        self.assertTrue(d.advance_until(lambda: not self.probing(d), step=1))
        heard = ha.count()
        d.advance(600)
        self.assertTrue(ha.none(asks(*PROBE), since=heard), "and not again by itself")
        ctl = d.ctl_start("probe", "s")
        self.assertTrue(d.advance_until(lambda: ha.seen(asks(*PROBE), heard)), "but when asked")
        self.assertTrue(d.advance_until_exits(ctl))
        ctl.communicate(timeout=10)


if __name__ == "__main__":
    unittest.main()

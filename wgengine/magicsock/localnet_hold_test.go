// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"encoding/hex"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// localHome is a device on a home Wi-Fi: en0 holds a private /24, a
// directly connected /24 outside the private ranges and a global IPv6 /64;
// cellular (pdp_ip0) and a tunnel (utun3) are up beside it.
func localHome() *netmon.State {
	return &netmon.State{
		InterfaceIPs: map[string][]netip.Prefix{
			"en0": {
				netip.PrefixFrom(localV4(192, 168, 1, 5), 24),
				netip.PrefixFrom(localV4(192, 0, 2, 5), 24),
				netip.PrefixFrom(localV6(0x42, 1), 64),
			},
			"pdp_ip0": {netip.PrefixFrom(localV4(10, 9, 8, 7), 32)},
			"utun3":   {netip.PrefixFrom(localV4(100, 101, 102, 103), 32)},
		},
		Interface: map[string]netmon.Interface{
			"en0":     localUp("en0"),
			"pdp_ip0": localUp("pdp_ip0"),
			"utun3":   localUp("utun3"),
		},
	}
}

// localMask is s with each of the given addresses written as <addr>, so a
// failure message records the line's shape and no address.
func localMask(s string, aps ...netip.AddrPort) string {
	for _, ap := range aps {
		s = strings.ReplaceAll(s, ap.String(), "<addr>")
	}
	return s
}

// TestLocalHold: with Android's hold on, every send to an address in the
// Android scope, a disco ping or data, is held and not sent; the release
// lifts it, and the hold is never set again in this process. The fork is
// told only that the hold is lifted: the release takes no argument.
func TestLocalHold(t *testing.T) {
	c, _ := localTestConn(t)
	c.local.ifState.Store(localHome())
	public := localAP(localV4(203, 0, 113, 7), 3478)
	c.lastNetCheckReport.Store(localReport(public, netip.AddrPort{}))
	SetLocalNetworkRule(LocalNetworkRule{Scope: LocalNetworkAndroid, Hold: true})
	now := c.localStart.Add(localWaitMax)

	held := map[string]netip.AddrPort{
		"private":                 localAP(localV4(10, 1, 2, 3), 41641),
		"carrier-grade-nat":       localAP(localV4(100, 64, 1, 1), 41641),
		"link-local-v4":           localAP(localV4(169, 254, 1, 1), 41641),
		"link-local-v6":           localAP(netip.AddrFrom16([16]byte{0xfe, 0x80, 15: 1}), 41641),
		"unique-local-v6":         localAP(netip.AddrFrom16([16]byte{0xfd, 0x00, 15: 1}), 41641),
		"directly-connected-v4":   localAP(localV4(192, 0, 2, 77), 41641),
		"directly-connected-v6":   localAP(localV6(0x42, 9), 41641),
		"connected-private-range": localAP(localV4(192, 168, 1, 30), 41641),
	}
	notHeld := map[string]netip.AddrPort{
		"public-v4":           localAP(localV4(203, 0, 113, 9), 41641),
		"public-v6-elsewhere": localAP(localV6(0x99, 5), 41641),
		"derp":                netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 1),
	}
	peerKey := key.NewNode().Public()
	for name, ap := range held {
		if !c.localHeld(ap, peerKey, now) {
			t.Errorf("%s: held false, want true (read at %s)", name, localAt())
		}
	}
	for name, ap := range notHeld {
		if c.localHeld(ap, peerKey, now) {
			t.Errorf("%s: held true, want false (read at %s)", name, localAt())
		}
	}

	// The peer shares this device's public address, so the rule itself
	// allows its addresses: what stops them is the hold alone.
	lan := held["connected-private-range"]
	de := localTestPeer(t, c, lan, localAP(public.Addr(), 61000))
	derp := netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 1)
	de.mu.Lock()
	de.startDiscoPingLocked(epAddr{ap: lan}, now, pingDiscovery, 0, nil)
	pinged := !de.endpointState[lan].lastPing.IsZero() || len(de.sentPing) > 0
	de.bestAddr = addrQuality{epAddr: epAddr{ap: lan}}
	de.trustBestAddrUntil = now.Add(time.Hour)
	de.derpAddr = derp
	sendTo, sendDERP, _ := de.addrForSendLocked(now)
	de.mu.Unlock()
	if pinged || sendTo.ap.IsValid() || sendDERP != derp {
		t.Errorf("held: disco ping started %v, data to the direct address %v, data by DERP %v; want false, false, true (read at %s)",
			pinged, sendTo.ap.IsValid(), sendDERP == derp, localAt())
	}
	// sendAddr refuses a held address before any socket. This test Conn has
	// none, so a send that went on would crash the test binary: it is only
	// tried while the hold reads held.
	if !c.localHeld(lan, de.publicKey, now) {
		t.Errorf("held: the peer's address reads not held, so sendAddr is not tried (read at %s)", localAt())
	} else if sent, err := c.sendAddr(lan, de.publicKey, []byte("x"), true, false); sent || err != nil {
		t.Errorf("held: sendAddr sent %v, err %v; want false, nil (read at %s)", sent, err, localAt())
	}

	ReleaseLocalNetworkHold()
	for name, ap := range held {
		if c.localHeld(ap, peerKey, now) {
			t.Errorf("after the release: %s held true, want false (read at %s)", name, localAt())
		}
	}
	de.mu.Lock()
	sendTo, _, _ = de.addrForSendLocked(now)
	de.startDiscoPingLocked(epAddr{ap: lan}, now, pingDiscovery, 0, nil)
	pinged = !de.endpointState[lan].lastPing.IsZero()
	de.mu.Unlock()
	if sendTo.ap != lan || !pinged {
		t.Errorf("after the release: data to the direct address %v, disco ping started %v; want true, true (read at %s)", sendTo.ap == lan, pinged, localAt())
	}

	// The hold is never set again in this process.
	SetLocalNetworkRule(LocalNetworkRule{Scope: LocalNetworkAndroid, Hold: true})
	if c.localHeld(held["private"], peerKey, now) {
		t.Errorf("the hold set again after its release: held true, want false (read at %s)", localAt())
	}
}

// TestLooksLocal: a peer looks local when it shares this device's public
// address or IPv6 network; with no public address known, also when one of
// its addresses is on a network this device is on. The fork answers per
// node key, rule or no rule.
func TestLooksLocal(t *testing.T) {
	own := []netip.Prefix{netip.PrefixFrom(localV4(192, 168, 1, 0), 24)}
	lanPeer := localAP(localV4(192, 168, 1, 30), 41641)
	public := localAP(localV4(203, 0, 113, 7), 3478)
	otherPublic := localAP(localV4(198, 51, 100, 40), 41641)
	for _, tc := range []struct {
		name  string
		f     localFacts
		peer  []netip.AddrPort
		local bool
	}{
		{"shares-the-public-address", localFacts{own: own, report: localReport(public, netip.AddrPort{})}, []netip.AddrPort{lanPeer, localAP(public.Addr(), 6000)}, true},
		{"shares-the-v6-network", localFacts{own: own, ownV6: []netip.Addr{localV6(0x42, 1)}}, []netip.AddrPort{localAP(localV6(0x42, 9), 41641)}, true},
		{"known-shares-neither", localFacts{own: own, report: localReport(public, netip.AddrPort{})}, []netip.AddrPort{lanPeer, otherPublic}, false},
		{"unknown-on-the-own-network", localFacts{own: own, report: localReport(netip.AddrPort{}, netip.AddrPort{})}, []netip.AddrPort{lanPeer, otherPublic}, true},
		{"unknown-not-on-the-own-network", localFacts{own: own}, []netip.AddrPort{otherPublic}, false},
	} {
		if got := looksLocalFor(&tc.f, slices.Values(tc.peer)); got != tc.local {
			t.Errorf("%s: looksLocalFor = %v, want %v (read at %s)", tc.name, got, tc.local, localAt())
		}
	}

	c, _ := localTestConn(t)
	c.local.ifState.Store(localHome())
	c.lastNetCheckReport.Store(localReport(public, netip.AddrPort{}))
	localRegister(c)
	t.Cleanup(func() { localDeregister(c) })
	near := localTestPeer(t, c, lanPeer, localAP(public.Addr(), 6000))
	far := localTestPeer(t, c, localAP(localV4(192, 168, 1, 31), 41641), otherPublic)
	stranger := key.NewNode().Public()
	for _, rule := range []string{"no-rule", "apple-rule"} {
		if rule == "apple-rule" {
			SetLocalNetworkRule(LocalNetworkRule{Scope: LocalNetworkApple})
		}
		for _, tc := range []struct {
			name      string
			k         key.NodePublic
			local, ok bool
		}{
			{"near", near.publicKey, true, true},
			{"far", far.publicKey, false, true},
			{"not-a-peer", stranger, false, false},
		} {
			l, ok := LooksLocal(tc.k)
			if l != tc.local || ok != tc.ok {
				t.Errorf("%s, %s: LooksLocal = %v, %v; want %v, %v (read at %s)", rule, tc.name, l, ok, tc.local, tc.ok, localAt())
			}
		}
	}
}

// TestLocalRuleLines: each skipped address, each held send and each attempt
// at an address on this device's own network writes one line through the
// Conn's logf, once per peer and address in localLineWindow. The line starts
// with its fixed words and writes the address as an address, the form a log
// funnel's IPv4 and IPv6 rules match, never quoted, split or in hex. No line
// names the platform. The release writes one line, with no address.
func TestLocalRuleLines(t *testing.T) {
	if localLineWindow < time.Second || localLineWindow > 10*time.Minute {
		t.Fatalf("localLineWindow = %v, want a window between 1s and 10m (read at %s)", localLineWindow, localAt())
	}
	c, lg := localTestConn(t)
	c.local.ifState.Store(localHome())
	public := localAP(localV4(203, 0, 113, 7), 3478)
	c.lastNetCheckReport.Store(localReport(public, netip.AddrPort{}))
	SetLocalNetworkRule(LocalNetworkRule{Scope: LocalNetworkAndroid, Hold: true})
	localRegister(c)
	t.Cleanup(func() { localDeregister(c) })
	now := c.localStart.Add(localWaitMax)

	skipV4 := localAP(localV4(192, 168, 1, 30), 41641)                      // a far peer's private address
	skipV6 := localAP(netip.AddrFrom16([16]byte{0xfd, 0x00, 15: 7}), 41641) // a far peer's unique-local one
	far := localTestPeer(t, c, skipV4, skipV6, localAP(localV4(198, 51, 100, 40), 41641))
	far2 := localTestPeer(t, c, skipV4, localAP(localV4(198, 51, 100, 41), 41641))
	heldAP := localAP(localV4(10, 1, 2, 3), 41641)
	ownAP := localAP(localV6(0x42, 9), 41641) // on en0's /64
	near := localTestPeer(t, c, ownAP, localAP(public.Addr(), 6000))

	for range 3 {
		far.mu.Lock()
		far.localAllowLocked(skipV4, now)
		far.localAllowLocked(skipV6, now)
		far.mu.Unlock()
		c.localHeld(heldAP, far.publicKey, now)
	}
	far2.mu.Lock()
	far2.localAllowLocked(skipV4, now) // another peer, the same address: its own line
	far2.mu.Unlock()

	// The own-network attempt is the hook's: the hold is lifted first, so
	// the ping to the near peer's address is started.
	ReleaseLocalNetworkHold()
	ReleaseLocalNetworkHold() // a second release says nothing
	near.mu.Lock()
	near.startDiscoPingLocked(epAddr{ap: ownAP}, now, pingDiscovery, 0, nil)
	near.startDiscoPingLocked(epAddr{ap: ownAP}, now.Add(time.Second), pingDiscovery, 0, nil)
	near.mu.Unlock()

	// After the window, the skip is written again.
	far.mu.Lock()
	far.localAllowLocked(skipV4, now.Add(localLineWindow))
	far.mu.Unlock()

	all := []netip.AddrPort{skipV4, skipV6, heldAP, ownAP}
	type want struct {
		prefix string
		ap     netip.AddrPort
		peer   key.NodePublic
		n      int
	}
	for _, w := range []want{
		{"localnet skip ", skipV4, far.publicKey, 2},
		{"localnet skip ", skipV6, far.publicKey, 1},
		{"localnet skip ", skipV4, far2.publicKey, 1},
		{"localnet held ", heldAP, far.publicKey, 1},
		{"localnet own-network ", ownAP, near.publicKey, 1},
	} {
		n := 0
		for _, line := range lg.with(w.prefix) {
			f := strings.Fields(strings.TrimPrefix(line, w.prefix))
			if len(f) == 0 {
				continue
			}
			got, err := netip.ParseAddrPort(f[0])
			if err != nil || got != w.ap || !strings.Contains(line, w.peer.ShortString()) {
				continue
			}
			n++
		}
		if n != w.n {
			var saw []string
			for _, line := range lg.with("localnet ") {
				saw = append(saw, localMask(line, all...))
			}
			t.Errorf("%q lines for one address and peer: %d, want %d; saw %q (read at %s)", w.prefix, n, w.n, saw, localAt())
		}
	}
	if got := len(lg.with("localnet hold lifted")); got != 1 {
		t.Errorf("localnet hold lifted lines: %d, want 1 (read at %s)", got, localAt())
	}
	for _, line := range lg.with("localnet ") {
		low := strings.ToLower(line)
		for _, word := range []string{"android", "ios", "darwin", "macos", "apple", "windows", "linux"} {
			if strings.Contains(low, word) {
				t.Errorf("a line names the platform (%q): %q (read at %s)", word, localMask(line, all...), localAt())
			}
		}
		if strings.ContainsAny(line, "\"'`") {
			t.Errorf("a line quotes: %q (read at %s)", localMask(line, all...), localAt())
		}
		for _, ap := range all {
			b := ap.Addr().AsSlice()
			if strings.Contains(low, hex.EncodeToString(b)) {
				t.Errorf("a line writes an address in hex: %q (read at %s)", localMask(line, all...), localAt())
			}
			if strings.Contains(line, ap.Addr().String()) && strings.Count(line, ap.Addr().String()) != 1 {
				t.Errorf("a line writes an address more than once: %q (read at %s)", localMask(line, all...), localAt())
			}
		}
	}
	if line := lg.with("localnet hold lifted"); len(line) == 1 && line[0] != "localnet hold lifted" {
		t.Errorf("the release line carries more than its words: %q (read at %s)", localMask(line[0], all...), localAt())
	}
}

// TestLocalRuleTwoNetworksOneRange stands in for the decision's read "two
// networks with one address range", reasoned and not yet seen on a phone:
// this device and a far peer are each on a network with the same private
// range, behind different public addresses. The peer's same-range address
// is skipped, it does not look local, and it stays reachable by its public
// address and by DERP; a near peer on the same range, behind this device's
// public address, is tried and looks local.
func TestLocalRuleTwoNetworksOneRange(t *testing.T) {
	c, lg := localTestConn(t)
	c.local.ifState.Store(localHome()) // en0: the private 192.168.1.0/24
	c.lastNetCheckReport.Store(localReport(localAP(localV4(203, 0, 113, 7), 3478), netip.AddrPort{}))
	SetLocalNetworkRule(LocalNetworkRule{Scope: LocalNetworkApple})
	localRegister(c)
	t.Cleanup(func() { localDeregister(c) })
	now := c.localStart.Add(localWaitMax)

	sameRange := localAP(localV4(192, 168, 1, 30), 41641) // the far peer's own home network
	farPublic := localAP(localV4(198, 51, 100, 40), 41641)
	far := localTestPeer(t, c, sameRange, farPublic)
	nearLAN := localAP(localV4(192, 168, 1, 31), 41641)
	near := localTestPeer(t, c, nearLAN, localAP(localV4(203, 0, 113, 7), 6000))
	derp := netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 2)

	far.mu.Lock()
	far.derpAddr = derp
	far.sendDiscoPingsLocked(now, false)
	pingedSame := !far.endpointState[sameRange].lastPing.IsZero()
	pingedPublic := !far.endpointState[farPublic].lastPing.IsZero()
	udp, viaDERP, _ := far.addrForSendLocked(now)
	far.mu.Unlock()
	near.mu.Lock()
	near.sendDiscoPingsLocked(now, false)
	pingedNear := !near.endpointState[nearLAN].lastPing.IsZero()
	near.mu.Unlock()
	farLocal, _ := LooksLocal(far.publicKey)
	nearLocal, _ := LooksLocal(near.publicKey)
	skips := len(lg.with("localnet skip "))

	if pingedSame || !pingedPublic || udp.ap.IsValid() || viaDERP != derp || farLocal || skips == 0 {
		t.Errorf("far peer: pinged its same-range address %v, its public address %v; data direct %v, by DERP %v; looks local %v; %d skip lines; want false, true, false, true, false, at least 1 (read at %s)",
			pingedSame, pingedPublic, udp.ap.IsValid(), viaDERP == derp, farLocal, skips, localAt())
	}
	if !pingedNear || !nearLocal {
		t.Errorf("near peer: pinged its same-range address %v, looks local %v; want true, true (read at %s)", pingedNear, nearLocal, localAt())
	}
}

// TestLocalRuleVPNOrOffice stands in for the decision's read "a VPN or an
// office with several exits", reasoned and not yet seen on a phone: a peer
// on this device's own network whose traffic leaves by another public
// address. The rule skips its local address, as decided (the "after a yes"
// layer, which would catch this case, stays held), and the peer stays
// reachable by its public address and by DERP. It does not look local while
// this device knows its public address; with none known it does, by its
// address on the own network.
func TestLocalRuleVPNOrOffice(t *testing.T) {
	c, lg := localTestConn(t)
	// The home network with no IPv6: a global IPv6 address held would make
	// the public address known before any report.
	st := localHome()
	st.InterfaceIPs["en0"] = slices.DeleteFunc(st.InterfaceIPs["en0"], func(p netip.Prefix) bool { return p.Addr().Is6() })
	c.local.ifState.Store(st)
	SetLocalNetworkRule(LocalNetworkRule{Scope: LocalNetworkApple})
	localRegister(c)
	t.Cleanup(func() { localDeregister(c) })
	now := c.localStart.Add(localWaitMax)

	onTheLAN := localAP(localV4(192, 168, 1, 40), 41641) // beside this device on en0
	exit := localAP(localV4(198, 51, 100, 50), 41641)    // the VPN's or the office's other exit
	peer := localTestPeer(t, c, onTheLAN, exit)
	derp := netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 3)

	// No public address known yet, after the wait: tried, and it looks
	// local by its address on the own network.
	c.lastNetCheckReport.Store(localReport(netip.AddrPort{}, netip.AddrPort{}))
	peer.mu.Lock()
	allowedUnknown := peer.localAllowLocked(onTheLAN, now)
	peer.mu.Unlock()
	localUnknown, _ := LooksLocal(peer.publicKey)

	// This device learns its public address: the peer shares neither it nor
	// its IPv6 network, so its local address is skipped.
	c.lastNetCheckReport.Store(localReport(localAP(localV4(203, 0, 113, 7), 3478), netip.AddrPort{}))
	peer.mu.Lock()
	peer.derpAddr = derp
	peer.sendDiscoPingsLocked(now.Add(discoPingInterval), false)
	pingedLAN := !peer.endpointState[onTheLAN].lastPing.IsZero()
	pingedExit := !peer.endpointState[exit].lastPing.IsZero()
	udp, viaDERP, _ := peer.addrForSendLocked(now)
	peer.mu.Unlock()
	localKnown, _ := LooksLocal(peer.publicKey)
	skips := len(lg.with("localnet skip "))

	if !allowedUnknown || !localUnknown {
		t.Errorf("no public address known: allowed %v, looks local %v; want true, true (read at %s)", allowedUnknown, localUnknown, localAt())
	}
	if pingedLAN || !pingedExit || udp.ap.IsValid() || viaDERP != derp || localKnown || skips == 0 {
		t.Errorf("public address known: pinged its LAN address %v, its exit %v; data direct %v, by DERP %v; looks local %v; %d skip lines; want false, true, false, true, false, at least 1 (read at %s)",
			pingedLAN, pingedExit, udp.ap.IsValid(), viaDERP == derp, localKnown, skips, localAt())
	}
}

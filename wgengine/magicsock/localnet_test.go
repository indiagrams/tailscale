// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/net/netcheck"
	"tailscale.com/net/netmon"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// The tests build their addresses from bytes, in the documentation and
// private ranges, so no test file or test log carries an address literal. A
// failure says what the test saw, as booleans and decisions, and when.

func localV4(a, b, c, d byte) netip.Addr { return netip.AddrFrom4([4]byte{a, b, c, d}) }

// localV6 is 2001:db8:<net>::<host>, in the IPv6 documentation range.
func localV6(net, host uint16) netip.Addr {
	return netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, byte(net >> 8), byte(net), 14: byte(host >> 8), 15: byte(host)})
}

func localAP(a netip.Addr, port uint16) netip.AddrPort { return netip.AddrPortFrom(a, port) }

func localAt() string { return time.Now().UTC().Format(time.RFC3339) }

// TestLocalRuleTable is the rule's eight combinations of its three inputs. An
// address is skipped only when it is in the guarded scope, the peer shares
// neither this device's public IPv4 address nor its IPv6 network, and this
// device knows its public address.
func TestLocalRuleTable(t *testing.T) {
	// The guarded scope: the device's own Wi-Fi, a private /24.
	lan := netip.PrefixFrom(localV4(192, 168, 7, 0), 24)
	inScope := localAP(localV4(192, 168, 7, 20), 41641)
	outScope := localAP(localV4(198, 51, 100, 20), 41641)
	// This device's public address, as a STUN answer reports it.
	public := localAP(localV4(203, 0, 113, 7), 3478)
	// The peer's other address: the device's own public address (the two
	// are behind one NAT) or another public address.
	samePublic := localAP(public.Addr(), 61000)
	otherPublic := localAP(localV4(198, 51, 100, 99), 51820)

	for _, scope := range []bool{true, false} {
		for _, shares := range []bool{false, true} {
			for _, known := range []bool{true, false} {
				name := fmt.Sprintf("scope-%s_shares-%s_public-%s", yesNo(scope, "in", "out"), yesNo(shares, "yes", "no"), yesNo(known, "known", "unknown"))
				t.Run(name, func(t *testing.T) {
					addr := outScope
					if scope {
						addr = inScope
					}
					peer := []netip.AddrPort{addr, otherPublic}
					if shares {
						peer = []netip.AddrPort{addr, samePublic}
					}
					// A completed report: with known, it holds the public
					// address; without, it found none.
					report := &netcheck.Report{Now: time.Now(), UDP: true, IPv4: true}
					if known {
						report.GlobalV4 = public
					}
					f := &localFacts{scope: []netip.Prefix{lan}, report: report, waited: true}
					want := localSend
					if scope && !shares && known {
						want = localSkip
					}
					if got := decideLocal(f, addr, slices.Values(peer)); got != want {
						t.Errorf("decideLocal = %v, want %v (address in scope %v, peer shares the public address %v, report has a public address %v; read at %s)",
							got, want, scope, shares, known, localAt())
					}
				})
			}
		}
	}
}

func yesNo(v bool, yes, no string) string {
	if v {
		return yes
	}
	return no
}

// localLog collects a Conn's log lines.
type localLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *localLog) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

// with is the lines that start with prefix.
func (l *localLog) with(prefix string) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, s := range l.lines {
		if strings.HasPrefix(s, prefix) {
			out = append(out, s)
		}
	}
	return out
}

// localTestConn is a Conn with no sockets, for the rule's tests. Its log is
// collected, and the process-wide rule is reset when the test ends.
func localTestConn(t *testing.T) (*Conn, *localLog) {
	t.Helper()
	resetLocalNetworkForTest()
	t.Cleanup(resetLocalNetworkForTest)
	lg := new(localLog)
	return newConn(lg.logf), lg
}

// localTestPeer is a peer of c with the given addresses, known to c's
// peerMap by its node key. Its disco key is set after it joins the peerMap,
// so no disco message to it reaches a socket (the test Conn has none).
func localTestPeer(t *testing.T, c *Conn, addrs ...netip.AddrPort) *endpoint {
	t.Helper()
	c.mu.Lock()
	id := tailcfg.NodeID(c.peerMap.nodeCount() + 1)
	c.mu.Unlock()
	de := &endpoint{
		c:             c,
		nodeID:        id,
		publicKey:     key.NewNode().Public(),
		sentPing:      map[stun.TxID]sentPing{},
		endpointState: map[netip.AddrPort]*endpointState{},
	}
	for _, a := range addrs {
		de.endpointState[a] = &endpointState{}
	}
	c.mu.Lock()
	c.peerMap.upsertEndpoint(de, key.DiscoPublic{}, false)
	c.mu.Unlock()
	de.updateDiscoKey(key.NewDisco().Public())
	t.Cleanup(func() {
		de.mu.Lock()
		defer de.mu.Unlock()
		for _, sp := range de.sentPing {
			sp.timer.Stop()
		}
	})
	return de
}

// localReport is a completed netcheck report with the given public
// addresses; a zero AddrPort is none.
func localReport(v4, v6 netip.AddrPort) *netcheck.Report {
	r := &netcheck.Report{Now: time.Now(), UDP: true, IPv4: true, IPv6: v6.IsValid()}
	r.GlobalV4 = v4
	r.GlobalV6 = v6
	return r
}

// localUp is an up interface named name, for a netmon.State.
func localUp(name string) netmon.Interface {
	return netmon.Interface{Interface: &net.Interface{Name: name, Flags: net.FlagUp}}
}

// TestLocalRuleWait: right after start, an address in the guarded scope
// waits for the first netcheck report, at most localWaitMax; with no public
// address learned by then, every address is tried, as upstream does. An
// address outside the scope never waits, and a completed report ends the
// wait early.
func TestLocalRuleWait(t *testing.T) {
	if localWaitMax <= 0 || localWaitMax > 5*time.Second {
		t.Fatalf("localWaitMax = %v, want a wait of at most 5s (read at %s)", localWaitMax, localAt())
	}
	lan := netip.PrefixFrom(localV4(192, 168, 7, 0), 24)
	inScope := localAP(localV4(192, 168, 7, 20), 41641)
	outScope := localAP(localV4(198, 51, 100, 20), 41641)
	peer := []netip.AddrPort{inScope, outScope}

	t.Run("decision", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			addr   netip.AddrPort
			report *netcheck.Report
			waited bool
			want   localDecision
		}{
			{"in-scope-no-report-inside-the-wait", inScope, nil, false, localWait},
			{"in-scope-no-report-after-the-wait", inScope, nil, true, localSend},
			{"out-of-scope-no-report-inside-the-wait", outScope, nil, false, localSend},
			{"in-scope-a-report-with-no-public-address", inScope, localReport(netip.AddrPort{}, netip.AddrPort{}), false, localSend},
		} {
			f := &localFacts{scope: []netip.Prefix{lan}, report: tc.report, waited: tc.waited}
			if got := decideLocal(f, tc.addr, slices.Values(peer)); got != tc.want {
				t.Errorf("%s: decideLocal = %v, want %v (read at %s)", tc.name, got, tc.want, localAt())
			}
		}
	})

	t.Run("conn", func(t *testing.T) {
		c, _ := localTestConn(t)
		SetLocalNetworkRule(LocalNetworkRule{Scope: LocalNetworkTest, TestPrefixes: []netip.Prefix{lan}})
		de := localTestPeer(t, c, inScope, outScope)
		start := c.localStart
		for _, tc := range []struct {
			name  string
			after time.Duration
			want  bool
		}{
			{"at-start", 0, false},
			{"inside-the-wait", localWaitMax - time.Millisecond, false},
			{"at-the-end-of-the-wait", localWaitMax, true},
		} {
			now := start.Add(tc.after)
			f := c.localFacts(now)
			de.mu.Lock()
			got := de.localAllowLocked(inScope, now)
			gotOut := de.localAllowLocked(outScope, now)
			de.mu.Unlock()
			if f.waited != tc.want || got != tc.want || !gotOut {
				t.Errorf("%s: waited %v, in-scope address allowed %v, want %v; out-of-scope address allowed %v, want true (read at %s)",
					tc.name, f.waited, got, tc.want, gotOut, localAt())
			}
		}
		// A completed report with no public address ends the wait: the
		// in-scope address is tried at once.
		c.lastNetCheckReport.Store(localReport(netip.AddrPort{}, netip.AddrPort{}))
		de.mu.Lock()
		got := de.localAllowLocked(inScope, start)
		de.mu.Unlock()
		if !got {
			t.Errorf("after a completed report with no public address: in-scope address allowed %v, want true (read at %s)", got, localAt())
		}
	})
}

// TestLocalRuleIPv6Counts: a global IPv6 address counts as a public address,
// whether a netcheck report found it or this device holds it, and a peer in
// one of this device's global /64s shares its IPv6 network. A unique-local
// or link-local address is not a public one.
func TestLocalRuleIPv6Counts(t *testing.T) {
	lan := netip.PrefixFrom(localV4(192, 168, 7, 0), 24)
	inScope := localAP(localV4(192, 168, 7, 20), 41641)
	otherV6 := localAP(localV6(0x99, 5), 41641)   // a /64 that is not this device's
	sameNetV6 := localAP(localV6(0x42, 9), 41641) // in this device's /64
	ownV6 := localV6(0x42, 1)

	for _, tc := range []struct {
		name   string
		report *netcheck.Report
		ownV6  []netip.Addr
		peer   []netip.AddrPort
		want   localDecision
	}{
		{"report-v6-only-peer-elsewhere", localReport(netip.AddrPort{}, localAP(ownV6, 41641)), nil, []netip.AddrPort{inScope, otherV6}, localSkip},
		{"report-v6-only-peer-in-the-64", localReport(netip.AddrPort{}, localAP(ownV6, 41641)), nil, []netip.AddrPort{inScope, sameNetV6}, localSend},
		{"held-v6-no-report-yet", nil, []netip.Addr{ownV6}, []netip.AddrPort{inScope, otherV6}, localSkip},
		{"held-v6-peer-in-the-64", nil, []netip.Addr{ownV6}, []netip.AddrPort{inScope, sameNetV6}, localSend},
		{"no-v6-no-v4-after-a-report", localReport(netip.AddrPort{}, netip.AddrPort{}), nil, []netip.AddrPort{inScope, otherV6}, localSend},
	} {
		// waited is false: a held global IPv6 address is known at once, so
		// nothing waits for the first report.
		f := &localFacts{scope: []netip.Prefix{lan}, report: tc.report, ownV6: tc.ownV6}
		if got := decideLocal(f, inScope, slices.Values(tc.peer)); got != tc.want {
			t.Errorf("%s: decideLocal = %v, want %v (read at %s)", tc.name, got, tc.want, localAt())
		}
	}

	// What this device holds, read from netmon's state: a global address on
	// an up interface counts; a unique-local or link-local one, a down
	// interface's and loopback's do not.
	ula := netip.AddrFrom16([16]byte{0xfd, 0x12, 15: 1})
	ll := netip.AddrFrom16([16]byte{0xfe, 0x80, 15: 1})
	st := &netmon.State{
		InterfaceIPs: map[string][]netip.Prefix{
			"en0":     {netip.PrefixFrom(localV4(192, 168, 7, 5), 24), netip.PrefixFrom(ownV6, 64), netip.PrefixFrom(ula, 64), netip.PrefixFrom(ll, 64)},
			"en9":     {netip.PrefixFrom(localV6(0x77, 1), 64)},
			"lo0":     {netip.PrefixFrom(netip.IPv6Loopback(), 128)},
			"pdp_ip0": {netip.PrefixFrom(localV6(0x43, 1), 64)},
		},
		Interface: map[string]netmon.Interface{
			"en0":     localUp("en0"),
			"en9":     {Interface: &net.Interface{Name: "en9"}}, // down
			"lo0":     {Interface: &net.Interface{Name: "lo0", Flags: net.FlagUp | net.FlagLoopback}},
			"pdp_ip0": localUp("pdp_ip0"),
		},
	}
	got := ownGlobalV6(st)
	want := []netip.Addr{ownV6, localV6(0x43, 1)}
	slices.SortFunc(got, netip.Addr.Compare)
	slices.SortFunc(want, netip.Addr.Compare)
	if !slices.Equal(got, want) {
		t.Errorf("ownGlobalV6 found %d addresses, want %d: the global ones on up interfaces, cellular included (read at %s)", len(got), len(want), localAt())
	}
}

// TestLocalRuleLatestCheck: only the latest completed netcheck report
// counts. A peer that shared an earlier report's public address does not
// share a later one's, and a later report that found no public address
// leaves this device not knowing one. The rule reads the Conn's
// lastNetCheckReport, which updateNetInfo stores only once GetReport has
// returned, so a check still running never counts.
func TestLocalRuleLatestCheck(t *testing.T) {
	c, _ := localTestConn(t)
	// The Apple scope, read from netmon's state: the device's own Wi-Fi.
	c.local.ifState.Store(&netmon.State{
		InterfaceIPs: map[string][]netip.Prefix{"en0": {netip.PrefixFrom(localV4(192, 168, 7, 5), 24)}},
		Interface:    map[string]netmon.Interface{"en0": localUp("en0")},
	})
	SetLocalNetworkRule(LocalNetworkRule{Scope: LocalNetworkApple})
	inScope := localAP(localV4(192, 168, 7, 20), 41641)
	first := localV4(203, 0, 113, 7)
	second := localV4(203, 0, 113, 8)
	// The peer is behind the first public address.
	de := localTestPeer(t, c, inScope, localAP(first, 61000))
	now := c.localStart.Add(localWaitMax)
	for _, tc := range []struct {
		name   string
		report *netcheck.Report
		want   bool
	}{
		{"first-report-the-peer-shares-it", localReport(localAP(first, 3478), netip.AddrPort{}), true},
		{"second-report-another-public-address", localReport(localAP(second, 3478), netip.AddrPort{}), false},
		{"third-report-no-public-address", localReport(netip.AddrPort{}, netip.AddrPort{}), true},
	} {
		c.lastNetCheckReport.Store(tc.report)
		de.mu.Lock()
		got := de.localAllowLocked(inScope, now)
		de.mu.Unlock()
		if got != tc.want {
			t.Errorf("%s: in-scope address allowed %v, want %v (read at %s)", tc.name, got, tc.want, localAt())
		}
	}
}

// TestLocalRuleOff: with nothing set, or LocalNetworkOff, the fork behaves
// as upstream does. Each hook is shown acting with the rule set first, so
// the off reading is not vacuous.
func TestLocalRuleOff(t *testing.T) {
	lan := netip.PrefixFrom(localV4(192, 168, 7, 0), 24)
	inScope := localAP(localV4(192, 168, 7, 20), 41641)
	public := localAP(localV4(203, 0, 113, 7), 3478)
	otherPublic := localAP(localV4(198, 51, 100, 99), 51820)
	derp := netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 1)

	type seen struct {
		allowed, pinged bool
		sendTo          epAddr
		sendDERP        netip.AddrPort
		lines           int
	}
	run := func(t *testing.T, set func()) seen {
		c, lg := localTestConn(t)
		set()
		c.lastNetCheckReport.Store(localReport(public, netip.AddrPort{}))
		de := localTestPeer(t, c, inScope, otherPublic)
		now := c.localStart.Add(localWaitMax)
		de.mu.Lock()
		defer de.mu.Unlock()
		var s seen
		s.allowed = de.localAllowLocked(inScope, now)
		de.sendDiscoPingsLocked(now, false)
		s.pinged = !de.endpointState[inScope].lastPing.IsZero()
		de.bestAddr = addrQuality{epAddr: epAddr{ap: inScope}}
		de.trustBestAddrUntil = now.Add(time.Hour)
		de.derpAddr = derp
		s.sendTo, s.sendDERP, _ = de.addrForSendLocked(now)
		s.lines = len(lg.with("localnet "))
		return s
	}
	ruleOn := func() {
		SetLocalNetworkRule(LocalNetworkRule{Scope: LocalNetworkTest, TestPrefixes: []netip.Prefix{lan}})
	}
	on := run(t, ruleOn)
	if on.allowed || on.pinged || on.sendTo.ap.IsValid() || on.sendDERP != derp {
		t.Errorf("the rule set: allowed %v, pinged %v, sends to a direct address %v, sends by DERP %v; want false, false, false, true (read at %s)",
			on.allowed, on.pinged, on.sendTo.ap.IsValid(), on.sendDERP == derp, localAt())
	}
	for _, tc := range []struct {
		name string
		set  func()
	}{
		{"nothing-set", func() {}},
		{"scope-off", func() {
			SetLocalNetworkRule(LocalNetworkRule{Scope: LocalNetworkOff, TestPrefixes: []netip.Prefix{lan}})
		}},
		{"set-then-off", func() { ruleOn(); SetLocalNetworkRule(LocalNetworkRule{}) }},
	} {
		off := run(t, tc.set)
		if !off.allowed || !off.pinged || off.sendTo.ap != inScope || off.sendDERP.IsValid() || off.lines != 0 {
			t.Errorf("%s: allowed %v, pinged %v, sends to the best address %v, sends by DERP %v, %d localnet lines; want true, true, true, false, 0 (read at %s)",
				tc.name, off.allowed, off.pinged, off.sendTo.ap == inScope, off.sendDERP.IsValid(), off.lines, localAt())
		}
	}
}

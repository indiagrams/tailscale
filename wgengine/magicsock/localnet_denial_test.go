// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
	"tailscale.com/util/usermetric"
)

// localDenialSetup is a Conn on the home Wi-Fi (localHome) that knows its
// public address, and a peer of it with an address on en0's private /24 and
// another public address. By the address rule alone the peer does not look
// local: this device knows its public address and the peer shares neither it
// nor its IPv6 network. The rule is LocalNetworkTest with no guarded address,
// so the peer's address on the own network is tried; with denied, the
// stand-in refuses every send to en0's private /24 as the system's Local
// Network denial does. The peer's disco key is known to the Conn, so a disco
// ping to it reaches the send.
func localDenialSetup(t *testing.T, denied bool) (c *Conn, lg *localLog, de *endpoint, lan netip.AddrPort) {
	t.Helper()
	c, lg = localTestConn(t)
	c.local.ifState.Store(localHome())
	c.lastNetCheckReport.Store(localReport(localAP(localV4(203, 0, 113, 7), 3478), netip.AddrPort{}))
	rule := LocalNetworkRule{Scope: LocalNetworkTest}
	if denied {
		rule.TestDenied = []netip.Prefix{netip.PrefixFrom(localV4(192, 168, 1, 0), 24)}
	}
	SetLocalNetworkRule(rule)
	localRegister(c)
	t.Cleanup(func() { localDeregister(c) })
	lan = localAP(localV4(192, 168, 1, 30), 41641)
	de = localTestPeer(t, c, lan, localAP(localV4(198, 51, 100, 40), 41641))
	de.heartbeatDisabled = true // no heartbeat pings the peer's other address, which no socket here could send to
	c.mu.Lock()
	c.peerMap.upsertEndpoint(de, key.DiscoPublic{}, false) // the disco key, now set, joins the peerMap
	c.mu.Unlock()
	return c, lg, de, lan
}

// localWaitFor reports whether cond held within d, polling.
func localWaitFor(d time.Duration, cond func() bool) bool {
	for end := time.Now().Add(d); ; time.Sleep(5 * time.Millisecond) {
		if cond() {
			return true
		}
		if time.Now().After(end) {
			return false
		}
	}
}

// TestLooksLocalDenialArm is the denial arm: a peer whose send to an address
// on a network this device is on failed as the system's Local Network denial
// fails one (host unreachable) looks local, though by the address rule alone
// it does not. Each failure is made by LocalNetworkTest's stand-in for the
// denial, before any socket.
func TestLooksLocalDenialArm(t *testing.T) {
	// The control: no send failed, so the address rule alone answers, and the
	// peer does not look local.
	t.Run("control-no-failure", func(t *testing.T) {
		_, _, de, _ := localDenialSetup(t, true)
		if l, ok := LooksLocal(de.publicKey); l || !ok {
			t.Errorf("denial-arm: control: LooksLocal = %v, %v; want false, true: no send failed and the address rule alone says not local (read at %s)", l, ok, localAt())
		}
	})

	// The session's failure: the disco ping to the peer's address on the own
	// network fails host unreachable.
	t.Run("failed-ping", func(t *testing.T) {
		c, lg, de, lan := localDenialSetup(t, true)
		de.mu.Lock()
		de.startDiscoPingLocked(epAddr{ap: lan}, mono0(c), pingDiscovery, 0, nil)
		de.mu.Unlock()
		failed := localWaitFor(5*time.Second, func() bool { return len(lg.with("magicsock: disco: failed to send ")) > 0 })
		local := localWaitFor(time.Second, func() bool { l, _ := LooksLocal(de.publicKey); return l })
		if !failed || !local {
			var saw []string
			for _, line := range lg.with("magicsock: disco: failed to send ") {
				saw = append(saw, localMask(line, lan))
			}
			t.Errorf("denial-arm: failed ping: the ping's send failed %v (saw %q), the peer looks local %v; want true, true (read at %s)", failed, saw, local, localAt())
		}
	})

	// The data send to the peer's best address fails host unreachable: the
	// send's isBadEndpointErr path. Three sends write one denied line.
	t.Run("failed-data-send", func(t *testing.T) {
		c, lg, de, lan := localDenialSetup(t, true)
		c.metrics = registerMetrics(new(usermetric.Registry))
		var errs []error
		for range 3 {
			de.mu.Lock()
			de.bestAddr = addrQuality{epAddr: epAddr{ap: lan}}
			de.trustBestAddrUntil = mono0(c).Add(time.Hour)
			de.mu.Unlock()
			errs = append(errs, de.send(0, [][]byte{[]byte("x")}, 0))
		}
		unreachable := true
		for _, err := range errs {
			unreachable = unreachable && errors.Is(err, errHOSTUNREACH)
		}
		local, _ := LooksLocal(de.publicKey)
		n := 0
		for _, line := range lg.with("localnet denied ") {
			f := strings.Fields(strings.TrimPrefix(line, "localnet denied "))
			if len(f) == 3 && f[0] == lan.String() && f[1] == "peer" && f[2] == de.publicKey.ShortString() {
				n++
			}
		}
		if !unreachable || !local || n != 1 {
			var saw []string
			for _, line := range lg.with("localnet ") {
				saw = append(saw, localMask(line, lan))
			}
			t.Errorf("denial-arm: failed data send: each send failed host unreachable %v, the peer looks local %v, %d denied lines for the peer and address; want true, true, 1; saw %q (read at %s)", unreachable, local, n, saw, localAt())
		}
	})

	// The cases below are told of a failure as the send's hooks tell it,
	// with no rule set: the arm answers rule or no rule.
	noRule := func(t *testing.T) (*Conn, *localLog, *endpoint, netip.AddrPort, netip.AddrPort) {
		c, lg := localTestConn(t)
		c.local.ifState.Store(localHome())
		c.lastNetCheckReport.Store(localReport(localAP(localV4(203, 0, 113, 7), 3478), netip.AddrPort{}))
		localRegister(c)
		t.Cleanup(func() { localDeregister(c) })
		lan := localAP(localV4(192, 168, 1, 30), 41641)
		other := localAP(localV4(198, 51, 100, 40), 41641)
		return c, lg, localTestPeer(t, c, lan, other), lan, other
	}

	t.Run("no-rule", func(t *testing.T) {
		c, _, de, lan, _ := noRule(t)
		before, _ := LooksLocal(de.publicKey)
		c.localNoteSendErr(de.publicKey, lan, errHOSTUNREACH, mono.Now())
		after, _ := LooksLocal(de.publicKey)
		if before || !after {
			t.Errorf("denial-arm: no rule: looks local before the failure %v, after it %v; want false, true (read at %s)", before, after, localAt())
		}
	})

	t.Run("window", func(t *testing.T) {
		if localDeniedWindow < time.Minute || localDeniedWindow > 10*time.Minute {
			t.Fatalf("denial-arm: localDeniedWindow = %v, want a window between 1m and 10m (read at %s)", localDeniedWindow, localAt())
		}
		c, _, de, lan, _ := noRule(t)
		at := mono0(c)
		c.localNoteSendErr(de.publicKey, lan, errHOSTUNREACH, at)
		inside, _ := c.localLooksLocal(de.publicKey, at.Add(localDeniedWindow-time.Millisecond))
		end, _ := c.localLooksLocal(de.publicKey, at.Add(localDeniedWindow))
		c.localNoteSendErr(de.publicKey, lan, errHOSTUNREACH, at.Add(localDeniedWindow))
		renewed, _ := c.localLooksLocal(de.publicKey, at.Add(2*localDeniedWindow-time.Millisecond))
		if !inside || end || !renewed {
			t.Errorf("denial-arm: window: looks local inside the window %v, at its end %v, inside a later failure's window %v; want true, false, true (read at %s)", inside, end, renewed, localAt())
		}
	})

	// A failure that is not host unreachable, a failure to an address on no
	// network this device is on, an address the peer no longer has, and a
	// failure read after this device left that network never count.
	t.Run("what-never-counts", func(t *testing.T) {
		c, lg, de, lan, other := noRule(t)
		now := mono0(c)
		c.localNoteSendErr(de.publicKey, lan, errors.New("another failure"), now)
		c.localNoteSendErr(de.publicKey, other, errHOSTUNREACH, now)
		otherErr, _ := c.localLooksLocal(de.publicKey, now)
		lines := len(lg.with("localnet denied "))

		gone := localAP(localV4(192, 168, 1, 31), 41641) // on en0's /24, not among the peer's addresses
		c.localNoteSendErr(de.publicKey, gone, errHOSTUNREACH, now)
		notTheirs, _ := c.localLooksLocal(de.publicKey, now)

		c.localNoteSendErr(de.publicKey, lan, errHOSTUNREACH, now)
		st := localHome()
		delete(st.InterfaceIPs, "en0")
		delete(st.Interface, "en0")
		c.local.ifState.Store(st) // this device left the home Wi-Fi
		left, _ := c.localLooksLocal(de.publicKey, now)
		if otherErr || lines != 0 || notTheirs || left {
			t.Errorf("denial-arm: what never counts: another failure or an address on no own network looks local %v (%d denied lines), an address the peer does not have %v, after this device left the network %v; want false (0), false, false (read at %s)", otherErr, lines, notTheirs, left, localAt())
		}
	})

	// The denied line: once per peer and address in localLineWindow, its
	// fixed words, the address written once as an address, the form a log
	// funnel's rules match, and no platform named.
	t.Run("line", func(t *testing.T) {
		c, lg, de, lan, _ := noRule(t)
		now := mono0(c)
		for i := range 3 {
			c.localNoteSendErr(de.publicKey, lan, errHOSTUNREACH, now.Add(time.Duration(i)*time.Second))
		}
		c.localNoteSendErr(de.publicKey, lan, errHOSTUNREACH, now.Add(localLineWindow))
		lines := lg.with("localnet denied ")
		bad := 0
		for _, line := range lines {
			f := strings.Fields(strings.TrimPrefix(line, "localnet denied "))
			if len(f) != 3 {
				bad++
				continue
			}
			ap, err := netip.ParseAddrPort(f[0])
			low := strings.ToLower(line)
			if err != nil || ap != lan || f[1] != "peer" || f[2] != de.publicKey.ShortString() || strings.Count(line, lan.Addr().String()) != 1 || strings.ContainsAny(line, "\"'`") {
				bad++
			}
			for _, word := range []string{"android", "ios", "darwin", "macos", "apple", "windows", "linux"} {
				if strings.Contains(low, word) {
					bad++
				}
			}
		}
		if len(lines) != 2 || bad != 0 {
			var saw []string
			for _, line := range lines {
				saw = append(saw, localMask(line, lan))
			}
			t.Errorf("denial-arm: line: %d denied lines for four failures, two windows apart, %d malformed; want 2, 0; saw %q (read at %s)", len(lines), bad, saw, localAt())
		}
	})
}

// mono0 is c's start, after the rule's wait for the first report.
func mono0(c *Conn) mono.Time { return c.localStart.Add(localWaitMax) }

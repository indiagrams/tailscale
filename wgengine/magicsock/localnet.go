// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

// localnet.go is the Local Network rule.
//
// Apple platforms ask the person before an app first sends to an address on
// its local network, and Android 17 refuses such a send until the app holds
// ACCESS_LOCAL_NETWORK. magicsock tries every address a peer advertises, so a
// peer far away whose list holds a private address (its own home network's)
// makes this device send to that address on whatever network this device is
// on, and the system asks about a peer that cannot be near.
//
// The rule, off unless the embedding app sets it, skips an address of a peer
// only when all three hold:
//
//   - the address is in the guarded scope;
//   - none of the peer's addresses is this device's public IPv4 address or in
//     one of its global IPv6 /64s;
//   - this device knows its public address.
//
// This device knows its public address when the latest completed netcheck
// report holds a global IPv4 or IPv6 address, or when it holds a global IPv6
// address itself. Right after a Conn starts, an address in the scope waits at
// most localWaitMax for the first report; with no public address learned,
// every address is tried, as upstream does. The peer's address list is never
// changed and nothing is stored: a skipped address is simply not sent to.

import (
	"iter"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/net/netcheck"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
)

// LocalNetworkScope names the addresses a [LocalNetworkRule] guards.
type LocalNetworkScope int

const (
	// LocalNetworkOff is no rule: every address is tried, as upstream does.
	LocalNetworkOff LocalNetworkScope = iota
	// LocalNetworkApple guards the prefixes of this device's own Wi-Fi and
	// Ethernet interfaces (en*), as netmon reads them: never a cellular
	// (pdp_ip*), tunnel (utun*) or loopback interface's.
	LocalNetworkApple
	// LocalNetworkAndroid guards the ranges Android counts as local
	// (private: 10/8, 172.16/12, 192.168/16, fc00::/7; carrier-grade NAT:
	// 100.64/10; link-local: 169.254/16, fe80::/10) and every network this
	// device is directly connected to, IPv6 included.
	LocalNetworkAndroid
	// LocalNetworkTest guards [LocalNetworkRule.TestPrefixes] alone, for
	// tests and an embedding app's own test lab.
	LocalNetworkTest
)

// LocalNetworkRule is the process-wide Local Network rule.
type LocalNetworkRule struct {
	Scope        LocalNetworkScope
	TestPrefixes []netip.Prefix // LocalNetworkTest only
	// Hold is Android's hold: every send to an address in the scope is held
	// until [ReleaseLocalNetworkHold].
	Hold bool
}

// ReleaseLocalNetworkHold lifts the hold.
//
// STUB: it lifts nothing.
func ReleaseLocalNetworkHold() {}

// localLineWindow is how often one line is written for one peer and address.
const localLineWindow = time.Minute

// localHeld reports whether the hold keeps back a send to ap.
//
// STUB: it holds nothing.
func (c *Conn) localHeld(ap netip.AddrPort, peer key.NodePublic, now mono.Time) bool { return false }

// looksLocalFor reports whether a peer with the given addresses looks local.
//
// STUB: no peer does.
func looksLocalFor(f *localFacts, peer iter.Seq[netip.AddrPort]) bool { return false }

// LooksLocal reports whether the peer whose node key is k looks local.
//
// STUB: it knows no peer.
func LooksLocal(k key.NodePublic) (looksLocal, ok bool) { return false, false }

// localRegister and localDeregister keep the set of live Conns.
//
// STUB: they keep none.
func localRegister(c *Conn)   {}
func localDeregister(c *Conn) {}

// localRuleP is the rule every Conn in the process reads; nil is no rule.
var localRuleP atomic.Pointer[LocalNetworkRule]

// SetLocalNetworkRule sets the rule for every Conn in this process. It is
// process-wide because an embedding app need not hold the Conn its engine
// builds; the app sets it once, at start, before its first Conn. A rule
// whose Scope is LocalNetworkOff, the zero rule included, is no rule.
func SetLocalNetworkRule(r LocalNetworkRule) {
	if r.Scope == LocalNetworkOff {
		localRuleP.Store(nil)
		return
	}
	r.TestPrefixes = slices.Clone(r.TestPrefixes)
	localRuleP.Store(&r)
}

// localRule is the rule, or nil.
func localRule() *LocalNetworkRule { return localRuleP.Load() }

// resetLocalNetworkForTest returns the process-wide rule to its zero state.
func resetLocalNetworkForTest() {
	localRuleP.Store(nil)
}

// localWaitMax is how long, right after a Conn starts, an address in the
// guarded scope waits for the first netcheck report. With none by then,
// every address is tried, as upstream does.
const localWaitMax = 3 * time.Second

// localConnState is the rule's state in one Conn.
type localConnState struct {
	// ifState is netmon's interface state, read only where the Conn holds
	// no lock (NewConn, updateNetInfo, Rebind): the rule is read under
	// endpoint.mu and Conn.mu, and netmon takes its own lock to answer.
	ifState atomic.Pointer[netmon.State]

	mu    sync.Mutex // guards the cache below
	valid bool
	rule  *LocalNetworkRule
	st    *netmon.State
	scope []netip.Prefix
	own   []netip.Prefix
	ownV6 []netip.Addr
}

// localRefresh reads netmon's interface state into c. c.mu and every
// endpoint.mu must not be held.
func (c *Conn) localRefresh() {
	if c.netMon == nil {
		return
	}
	if st := c.netMon.InterfaceState(); st != nil {
		c.local.ifState.Store(st)
	}
}

// localDecision is the rule's answer for one address of one peer.
type localDecision uint8

const (
	localSend localDecision = iota // try the address, as upstream does
	localSkip                      // do not try it: it cannot be the peer near this device
	localWait                      // not yet: no netcheck report has completed
)

func (d localDecision) String() string {
	switch d {
	case localSend:
		return "send"
	case localSkip:
		return "skip"
	case localWait:
		return "wait"
	}
	return "unknown"
}

// localFacts is what the rule reads about this device at one moment.
type localFacts struct {
	scope   []netip.Prefix   // the guarded scope; empty when the rule is off
	android bool             // the scope also holds the ranges Android counts as local
	own     []netip.Prefix   // the networks this device is on: every up interface's prefixes
	report  *netcheck.Report // the latest completed netcheck report, or nil before the first
	ownV6   []netip.Addr     // the global IPv6 addresses this device holds
	waited  bool             // the wait for the first report is over
}

// localAddr is a with no zone and no IPv4-in-IPv6 mapping, the form the
// prefixes compare.
func localAddr(a netip.Addr) netip.Addr { return a.Unmap().WithZone("") }

// androidLocal reports whether a is in a range Android counts as local.
func androidLocal(a netip.Addr) bool {
	return a.IsPrivate() || a.IsLinkLocalUnicast() || tsaddr.CGNATRange().Contains(a)
}

// inScope reports whether a is in the guarded scope.
func (f *localFacts) inScope(a netip.Addr) bool {
	a = localAddr(a)
	if f.android && androidLocal(a) {
		return true
	}
	return prefixesContain(f.scope, a)
}

// onOwnNetwork reports whether a is on a network this device is on.
func (f *localFacts) onOwnNetwork(a netip.Addr) bool { return prefixesContain(f.own, localAddr(a)) }

func prefixesContain(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// publicV4 is this device's public IPv4 address, or the zero Addr.
func (f *localFacts) publicV4() netip.Addr {
	if f.report == nil || !f.report.GlobalV4.IsValid() {
		return netip.Addr{}
	}
	return localAddr(f.report.GlobalV4.Addr())
}

// publicV6Nets is this device's global IPv6 /64s: the report's and those of
// the global IPv6 addresses it holds.
func (f *localFacts) publicV6Nets() []netip.Prefix {
	var out []netip.Prefix
	add := func(a netip.Addr) {
		if p, err := localAddr(a).Prefix(64); err == nil {
			out = append(out, p)
		}
	}
	if f.report != nil && f.report.GlobalV6.IsValid() {
		add(f.report.GlobalV6.Addr())
	}
	for _, a := range f.ownV6 {
		add(a)
	}
	return out
}

// known reports whether this device knows its public address.
func (f *localFacts) known() bool {
	return f.publicV4().IsValid() || (f.report != nil && f.report.GlobalV6.IsValid()) || len(f.ownV6) > 0
}

// shares reports whether one of peer's addresses is this device's public
// IPv4 address or in one of its global IPv6 /64s.
func (f *localFacts) shares(peer iter.Seq[netip.AddrPort]) bool {
	v4 := f.publicV4()
	v6 := f.publicV6Nets()
	for ap := range peer {
		a := localAddr(ap.Addr())
		if a.Is4() {
			if v4.IsValid() && a == v4 {
				return true
			}
			continue
		}
		if prefixesContain(v6, a) {
			return true
		}
	}
	return false
}

// decideLocal is the rule for addr, one of peer's addresses.
func decideLocal(f *localFacts, addr netip.AddrPort, peer iter.Seq[netip.AddrPort]) localDecision {
	if !f.inScope(addr.Addr()) {
		return localSend
	}
	if f.shares(peer) {
		return localSend
	}
	if f.known() {
		return localSkip
	}
	if f.report == nil && !f.waited {
		return localWait
	}
	return localSend
}

// forEachUpPrefix calls fn for each address prefix of each up, non-loopback
// interface in st, in interface-name order.
func forEachUpPrefix(st *netmon.State, fn func(name string, p netip.Prefix)) {
	if st == nil {
		return
	}
	for _, name := range slices.Sorted(maps.Keys(st.InterfaceIPs)) {
		iface, ok := st.Interface[name]
		if !ok || !iface.IsUp() || iface.IsLoopback() {
			continue
		}
		for _, p := range st.InterfaceIPs[name] {
			if !p.IsValid() || p.Bits() == 0 || p.Addr().IsLoopback() || p.Addr().IsUnspecified() {
				continue
			}
			fn(name, p)
		}
	}
}

// appleScope is the prefixes of st's Wi-Fi and Ethernet interfaces, en* on
// Apple platforms: never pdp_ip* (cellular), utun* (tunnels) or lo*.
func appleScope(st *netmon.State) []netip.Prefix {
	var out []netip.Prefix
	forEachUpPrefix(st, func(name string, p netip.Prefix) {
		if strings.HasPrefix(name, "en") {
			out = append(out, p.Masked())
		}
	})
	return out
}

// ownNetworks is the prefixes of every up interface in st: the networks this
// device is directly connected to.
func ownNetworks(st *netmon.State) []netip.Prefix {
	var out []netip.Prefix
	forEachUpPrefix(st, func(_ string, p netip.Prefix) { out = append(out, p.Masked()) })
	return out
}

// ownGlobalV6 is the global IPv6 addresses st's up interfaces hold: not
// unique-local, link-local or loopback.
func ownGlobalV6(st *netmon.State) []netip.Addr {
	var out []netip.Addr
	forEachUpPrefix(st, func(_ string, p netip.Prefix) {
		a := localAddr(p.Addr())
		if a.Is6() && a.IsGlobalUnicast() && !a.IsPrivate() {
			out = append(out, a)
		}
	})
	return out
}

// localScopeOf is rule's guarded scope on st, and whether it holds Android's
// local ranges.
func localScopeOf(rule *LocalNetworkRule, st *netmon.State) (scope []netip.Prefix, android bool) {
	if rule == nil {
		return nil, false
	}
	switch rule.Scope {
	case LocalNetworkApple:
		return appleScope(st), false
	case LocalNetworkAndroid:
		return ownNetworks(st), true
	case LocalNetworkTest:
		return rule.TestPrefixes, false
	}
	return nil, false
}

// localFacts is what the rule reads of c at now: the rule's scope on the
// interface state c last read, the latest completed netcheck report, and
// whether the start wait is over. It takes only c.local.mu, so it may be
// called with c.mu or an endpoint.mu held.
func (c *Conn) localFacts(now mono.Time) localFacts {
	rule := localRule()
	st := c.local.ifState.Load()
	c.local.mu.Lock()
	if !c.local.valid || c.local.rule != rule || c.local.st != st {
		c.local.scope, _ = localScopeOf(rule, st)
		c.local.own = ownNetworks(st)
		c.local.ownV6 = ownGlobalV6(st)
		c.local.rule, c.local.st, c.local.valid = rule, st, true
	}
	f := localFacts{scope: c.local.scope, own: c.local.own, ownV6: c.local.ownV6}
	c.local.mu.Unlock()
	f.android = rule != nil && rule.Scope == LocalNetworkAndroid
	f.report = c.lastNetCheckReport.Load()
	f.waited = now.Sub(c.localStart) >= localWaitMax
	return f
}

// localAllowLocked reports whether the rule lets de send to ap at now: true
// for every address when no rule is set, and for a DERP address.
//
// de.mu must be held.
func (de *endpoint) localAllowLocked(ap netip.AddrPort, now mono.Time) bool {
	if localRule() == nil || ap.Addr() == tailcfg.DerpMagicIPAddr {
		return true
	}
	f := de.c.localFacts(now)
	return decideLocal(&f, ap, maps.Keys(de.endpointState)) == localSend
}

// localAllow is localAllowLocked at the present moment, taking de.mu.
func (de *endpoint) localAllow(ap netip.AddrPort) bool {
	if localRule() == nil {
		return true
	}
	de.mu.Lock()
	defer de.mu.Unlock()
	return de.localAllowLocked(ap, mono.Now())
}

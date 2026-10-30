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

import (
	"iter"
	"net/netip"
	"sync/atomic"
	"time"

	"tailscale.com/net/netcheck"
	"tailscale.com/net/netmon"
	"tailscale.com/tstime/mono"
)

// LocalNetworkScope names the addresses a [LocalNetworkRule] guards.
type LocalNetworkScope int

const (
	// LocalNetworkOff is no rule: every address is tried, as upstream does.
	LocalNetworkOff LocalNetworkScope = iota
	// LocalNetworkApple guards the prefixes of this device's own Wi-Fi and
	// Ethernet interfaces.
	LocalNetworkApple
	// LocalNetworkAndroid guards the ranges Android counts as local and every
	// network this device is directly connected to.
	LocalNetworkAndroid
	// LocalNetworkTest guards [LocalNetworkRule.TestPrefixes].
	LocalNetworkTest
)

// LocalNetworkRule is the process-wide Local Network rule.
type LocalNetworkRule struct {
	Scope        LocalNetworkScope
	TestPrefixes []netip.Prefix // LocalNetworkTest only
}

// SetLocalNetworkRule sets the rule for every Conn in this process.
//
// STUB: it sets nothing.
func SetLocalNetworkRule(r LocalNetworkRule) {}

// resetLocalNetworkForTest returns the process-wide rule to its zero state.
func resetLocalNetworkForTest() {}

// localWaitMax is how long, right after a Conn starts, an address in the
// guarded scope waits for the first netcheck report.
const localWaitMax = 3 * time.Second

// localConnState is the rule's state in one Conn.
type localConnState struct {
	ifState atomic.Pointer[netmon.State] // netmon's state, read with no lock held
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

// decideLocal is the rule for addr, one of peer's addresses.
//
// STUB: it never skips. The rule replaces it.
func decideLocal(f *localFacts, addr netip.AddrPort, peer iter.Seq[netip.AddrPort]) localDecision {
	return localSend
}

// ownGlobalV6 is the global IPv6 addresses st's up interfaces hold.
//
// STUB: it finds none.
func ownGlobalV6(st *netmon.State) []netip.Addr { return nil }

// localFacts is what the rule reads of c at now.
//
// STUB: it reads nothing.
func (c *Conn) localFacts(now mono.Time) localFacts { return localFacts{} }

// localAllowLocked reports whether the rule lets de send to ap at now.
//
// STUB: it allows every address.
func (de *endpoint) localAllowLocked(ap netip.AddrPort, now mono.Time) bool { return true }

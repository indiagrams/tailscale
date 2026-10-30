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

	"tailscale.com/net/netcheck"
)

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
	scope  []netip.Prefix   // the guarded scope; empty when the rule is off
	own    []netip.Prefix   // the networks this device is on: every up interface's prefixes
	report *netcheck.Report // the latest completed netcheck report, or nil before the first
	ownV6  []netip.Addr     // the global IPv6 addresses this device holds
	waited bool             // the wait for the first report is over
}

// decideLocal is the rule for addr, one of peer's addresses.
//
// STUB: it never skips. The rule replaces it.
func decideLocal(f *localFacts, addr netip.AddrPort, peer iter.Seq[netip.AddrPort]) localDecision {
	return localSend
}

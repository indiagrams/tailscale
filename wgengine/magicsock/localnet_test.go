// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"tailscale.com/net/netcheck"
)

// The tests build their addresses from bytes, in the documentation and
// private ranges, so no test file or test log carries an address literal.

func localV4(a, b, c, d byte) netip.Addr { return netip.AddrFrom4([4]byte{a, b, c, d}) }

func localAP(a netip.Addr, port uint16) netip.AddrPort { return netip.AddrPortFrom(a, port) }

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
							got, want, scope, shares, known, time.Now().UTC().Format(time.RFC3339))
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

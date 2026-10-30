// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package magicsock

import (
	"net"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// TestAndroidEPERM: on android an EPERM is not healed by a rebind. Android 17
// refuses a send to the local network without ACCESS_LOCAL_NETWORK, and a new
// socket is refused the same way, so a rebind there only churns. Elsewhere
// EPERM still rebinds, as upstream does for EDR software.
func TestAndroidEPERM(t *testing.T) {
	eperm := &net.OpError{Err: syscall.EPERM}
	epipe := &net.OpError{Err: syscall.EPIPE}
	for _, tc := range []struct {
		goos   string
		err    error
		ok     bool
		reason string
	}{
		{"android", eperm, false, ""},
		{"android", epipe, true, "broken-pipe"},
		{"linux", eperm, true, "operation-not-permitted"},
		{"darwin", eperm, true, "operation-not-permitted"},
		{"ios", eperm, true, "operation-not-permitted"},
		{"windows", eperm, true, "operation-not-permitted"},
	} {
		if ok, reason := shouldRebindOn(tc.goos, tc.err); ok != tc.ok || reason != tc.reason {
			t.Errorf("shouldRebindOn(%q, %v) = %v, %q; want %v, %q (read at %s)", tc.goos, tc.err, ok, reason, tc.ok, tc.reason, time.Now().UTC().Format(time.RFC3339))
		}
	}
	ok, reason := shouldRebind(eperm)
	wok, wreason := shouldRebindOn(runtime.GOOS, eperm)
	if ok != wok || reason != wreason {
		t.Errorf("shouldRebind(EPERM) = %v, %q; shouldRebindOn(%q, EPERM) = %v, %q; want them equal", ok, reason, runtime.GOOS, wok, wreason)
	}
}

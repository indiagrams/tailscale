// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build wasm || plan9

package magicsock

import "errors"

// errHOSTUNREACH is the error LocalNetworkTest's stand-in for the system's
// denial fails a send with; these platforms name no EHOSTUNREACH, and
// isBadEndpointErr never reads it as bad.
var errHOSTUNREACH error = errors.New("no route to host")

// isBadEndpointErr checks if err is one which is known to report that an
// endpoint can no longer be sent to. It is not exhaustive, but covers known
// cases.
func isBadEndpointErr(err error) bool {
	return false
}

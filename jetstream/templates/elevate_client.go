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
	"os"
	"syscall"

	"github.com/iDigitalFlame/xmt/com/pipe"
	"github.com/iDigitalFlame/xmt/device"
	"github.com/iDigitalFlame/xmt/device/winapi"
	"github.com/iDigitalFlame/xmt/util"
)

func main() {
	var (
		n      int32
		v, err = syscall.CommandLineToArgv(syscall.GetCommandLine(), &n)
	)
	if err != nil {
		device.GoExit()
		return
	}
	var b util.Builder
	for i := int32(1); i < n; i++ {
		if i > 1 {
			b.WriteByte(' ')
		}
		b.WriteString(winapi.UTF16ToString(v[i][:]))
	}
	c, err := pipe.Dial(pipe.Format(`$pipe`))
	if err != nil {
		os.Exit(1)
	}
	c.Write([]byte(b.Output()))
	c.Close()
	device.GoExit()
}

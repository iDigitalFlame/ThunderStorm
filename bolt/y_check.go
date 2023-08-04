//go:build !no_check
// +build !no_check

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

package bolt

import (
	"github.com/iDigitalFlame/xmt/device/local"
	"github.com/iDigitalFlame/xmt/man"
)

func checkGuard(l man.Linker, g string) string {
	if len(g) == 0 {
		return ""
	}
	if local.Elevated() {
		return g
	}
	return g + "A"
}

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

// Package bolt contains the functions for launching a Bolt instance.
package bolt

import (
	"time"

	"github.com/iDigitalFlame/xmt/c2/cfg"
)

func checkBuild(c cfg.Config) cfg.Profile {
	p, err := c.Build()
	if err != nil {
		return nil
	}
	// If we have a killdate that's after now, quit.
	if k, ok := p.KillDate(); ok && !k.IsZero() && time.Now().After(k) {
		return nil
	}
	return p
}

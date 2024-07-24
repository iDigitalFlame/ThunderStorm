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

package cirrus

import (
	"context"
	"encoding/base64"
	"os"
	"sync"
	"time"

	"github.com/iDigitalFlame/xmt/c2"
	"github.com/iDigitalFlame/xmt/com"
	"github.com/iDigitalFlame/xmt/util"
)

const (
	header = "DateTime,SessionID,IP,Event,JobID,JobType,JobData,\r\n"

	sJobError     = uint8(c2.StatusError)
	sJobWaiting   = uint8(c2.StatusWaiting)
	sJobAccepted  = uint8(c2.StatusAccepted)
	sJobReceiving = uint8(c2.StatusReceiving)
	sJobCompleted = uint8(c2.StatusCompleted)

	sSessionNew    = 0
	sSessionUpdate = 1
	sSessionDelete = 2
)

type stats struct {
	_    [0]func()
	f, t *os.File
	ch   chan struct{}
	ej   chan statJobEvent
	es   chan statSessionEvent
	ep   chan statPacketEvent
	e    [0xFF]uint64
	j, s uint64
	sync.Mutex
}
type statJobEvent struct {
	_       [0]func()
	Time    time.Time
	Data    string
	Session string
	Job     uint16
	Type    uint8
	Status  uint8
}
type statPacketEvent struct {
	_       [0]func()
	Time    time.Time
	Session string
	Data    string
	ID      uint8
}
type statSessionEvent struct {
	_       [0]func()
	Time    time.Time
	Session string
	Addr    string
	Type    uint8
}

func (s *stats) writeTacker() {
	if s.t == nil {
		return
	}
	s.t.Truncate(0)
	s.t.Seek(0, 0)
	s.t.WriteString("Sessions:\t" + util.Uitoa(s.s) + "\n\n")
	s.t.WriteString("Jobs:\t" + util.Uitoa(s.j) + "\n")
	s.Lock()
	for i := range s.e {
		if s.e[i] == 0 {
			continue
		}
		if i < 16 {
			s.t.WriteString("   ")
		} else {
			s.t.WriteString("  ")
		}
		s.t.WriteString(util.Uitoa16(uint64(i)) + ":\t" + util.Uitoa(s.e[i]) + "\n")
	}
	s.Unlock()
	s.t.Sync()
}
func (s *stats) track(x context.Context) {
	var (
		c <-chan time.Time
		t *time.Ticker
	)
	if s.t != nil {
		t = time.NewTicker(time.Minute)
		c = t.C
	}
loop:
	for {
		select {
		case <-c:
			s.writeTacker()
		case <-x.Done():
			break loop
		case v := <-s.ej:
			if v.Status == sJobWaiting {
				s.Lock()
				s.e[v.Type]++
				s.Unlock()
				s.j++
			}
			s.writeJobEvent(v)
		case v := <-s.es:
			if v.Type == sSessionNew {
				s.s++
			}
			s.writeSessionEvent(v)
		case v := <-s.ep:
			s.writePacketEvent(v)
		}
	}
	if s.t != nil {
		s.writeTacker()
		s.t.Sync()
		s.t.Close()
		t.Stop()
	}
	if s.f != nil {
		s.f.Sync()
		s.f.Close()
	}
	close(s.ep)
	close(s.ej)
	close(s.es)
	close(s.ch)
}
func (c *Cirrus) packetEvent(n *com.Packet) {
	if c.st == nil {
		return
	}
	var d string
	if !n.Empty() {
		d = base64.StdEncoding.EncodeToString(n.Payload())
	}
	c.st.ep <- statPacketEvent{
		ID:      n.ID,
		Data:    d,
		Time:    time.Now(),
		Session: n.Device.String(),
	}
}
func (s *stats) writeJobEvent(e statJobEvent) {
	if s.f == nil {
		return
	}
	switch s.f.WriteString(e.Time.Format(time.RFC3339) + "," + e.Session + ",,JOB_"); e.Status {
	case sJobError:
		s.f.WriteString("ERROR,")
	case sJobWaiting:
		s.f.WriteString("WAITING,")
	case sJobAccepted:
		s.f.WriteString("ACCEPTED,")
	case sJobReceiving:
		s.f.WriteString("RECEIVING,")
	case sJobCompleted:
		s.f.WriteString("COMPLETED,")
	default:
		s.f.WriteString("INVALID,")
	}
	s.f.WriteString(util.Uitoa(uint64(e.Job)) + "," + util.Uitoa(uint64(e.Type)) + "," + e.Data + ",\r\n")
	s.f.Sync()
}
func (s *stats) writePacketEvent(e statPacketEvent) {
	if s.f == nil {
		return
	}
	s.f.WriteString(e.Time.Format(time.RFC3339) + "," + e.Session + ",,ONESHOT," + util.Uitoa(uint64(e.ID)) + ",," + e.Data + ",\r\n")
	s.f.Sync()
}
func (s *stats) writeSessionEvent(e statSessionEvent) {
	switch s.f.WriteString(e.Time.Format(time.RFC3339) + "," + e.Session + "," + e.Addr + ",SESSION_"); e.Type {
	case sSessionNew:
		s.f.WriteString("NEW,")
	case sSessionUpdate:
		s.f.WriteString("UPDATE,")
	case sSessionDelete:
		s.f.WriteString("DELETE,")
	default:
		s.f.WriteString("INVALID,")
	}
	s.f.WriteString(",,,\r\n")
	s.f.Sync()
}
func (c *Cirrus) sessionEvent(x *c2.Session, t uint8) {
	if c.st == nil {
		return
	}
	c.st.es <- statSessionEvent{
		Type:    t,
		Time:    time.Now(),
		Addr:    x.RemoteAddr(),
		Session: x.ID.String(),
	}
}
func (c *Cirrus) jobEvent(x *c2.Session, j *c2.Job, v string) {
	if c.st == nil {
		return
	}
	c.st.ej <- statJobEvent{
		Job:     j.ID,
		Data:    v,
		Type:    j.Type,
		Time:    time.Now(),
		Status:  uint8(j.Status),
		Session: x.ID.String(),
	}
}

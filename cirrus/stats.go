package cirrus

import (
	"context"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/iDigitalFlame/xmt/c2"
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
	sync.Mutex
	f, t *os.File
	ch   chan struct{}
	ej   chan statJobEvent
	es   chan statSessionEvent
	ep   chan statPacketEvent
	e    [0xFF]uint64
	j, s uint64
}
type statJobEvent struct {
	Time    time.Time
	Data    string
	Session string
	Job     uint16
	Type    uint8
	Status  uint8
}
type statPacketEvent struct {
	Time    time.Time
	Session string
	ID      uint8
}
type statSessionEvent struct {
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
	s.f.WriteString("Sessions:\t" + strconv.FormatUint(s.s, 10) + "\n\n")
	s.f.WriteString("Jobs:\t" + strconv.FormatUint(s.j, 10) + "\n")
	s.Lock()
	for i := range s.e {
		if s.e[i] == 0 {
			continue
		}
		s.f.WriteString("  " + strconv.FormatUint(uint64(i), 16) + ":\t" + strconv.FormatUint(s.e[i], 10) + "\n")
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
			s.Lock()
			s.e[v.Type]++
			s.Unlock()
			s.j++
			s.writeJobEvent(v)
		case v := <-s.es:
			s.s++
			s.writeSessionEvent(v)
		case v := <-s.ep:
			s.writePacketEvent(v)
		}
	}
	if t.Stop(); s.t != nil {
		s.writeTacker()
		s.t.Sync()
		s.t.Close()
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
	s.f.WriteString(
		strconv.FormatUint(uint64(e.Job), 10) + "," + strconv.FormatUint(uint64(e.Type), 10) + "," + e.Data + ",\r\n",
	)
	s.f.Sync()
}
func (s *stats) writePacketEvent(e statPacketEvent) {
	if s.f == nil {
		return
	}
	s.f.WriteString(
		e.Time.Format(time.RFC3339) + "," + e.Session + ",,ONESHOT," +
			strconv.FormatUint(uint64(e.ID), 10) + ",,,\r\n",
	)
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

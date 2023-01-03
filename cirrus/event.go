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

package cirrus

import (
	"context"
	"io"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/PurpleSec/escape"
	"github.com/gorilla/websocket"
	"github.com/iDigitalFlame/xmt/data"
)

var bufs = sync.Pool{
	New: func() any {
		return new(data.Chunk)
	},
}

type event struct {
	_                   [0]func()
	Name, Action        string
	Value, Count, Total uint16
}
type eventManager struct {
	*Cirrus
	in      chan event
	new     chan *websocket.Conn
	clients []*websocket.Conn
	status  uint32
}

func (e event) write(b io.Writer) {
	if b.Write([]byte(`{"name":` + escape.JSON(e.Name) + `,"action":"` + e.Action + `"`)); e.Value > 0 {
		b.Write([]byte(`,"value":` + strconv.FormatUint(uint64(e.Value), 10)))
	}
	if e.Count > 0 {
		b.Write([]byte(`,"count":` + strconv.FormatUint(uint64(e.Count), 10)))
	}
	if e.Total > 0 {
		b.Write([]byte(`,"total":` + strconv.FormatUint(uint64(e.Total), 10)))
	}
	b.Write([]byte{'}'})
}
func (e *eventManager) shutdown() {
	if atomic.SwapUint32(&e.status, 2) == 2 {
		return
	}
	for i := range e.clients {
		e.clients[i].Close()
	}
	e.clients = nil
	close(e.new)
	close(e.in)
	close(e.ch)
}
func (e *eventManager) run(x context.Context) {
	if atomic.SwapUint32(&e.status, 1) != 0 {
		return
	}
loop:
	for e.log.Debug("[cirrus/event] Starting up eventer.."); ; {
		select {
		case <-x.Done():
			break loop
		case n := <-e.in:
			e.log.Trace(`[cirrus/event] Sending event "%s".`, n.Action)
			var (
				b = bufs.Get().(*data.Chunk)
				c = make([]*websocket.Conn, 0, len(e.clients))
			)
			n.write(b)
			for i := range e.clients {
				w, err := e.clients[i].NextWriter(websocket.TextMessage)
				if err != nil {
					e.clients[i].Close()
					continue
				}
				_, err = b.WriteTo(w)
				if b.Seek(0, 0); err != nil {
					e.clients[i].Close()
					continue
				}
				if err = w.Close(); err != nil {
					e.clients[i].Close()
					continue
				}
				c = append(c, e.clients[i])
			}
			b.Clear()
			if bufs.Put(b); len(e.clients) != len(c) {
				e.clients, c = c, nil
			} else {
				c = nil
			}
		case n := <-e.new:
			e.clients = append(e.clients, n)
		}
	}
	e.log.Debug("[cirrus/event] Shutting down eventer.")
	e.shutdown()
}
func (e *eventManager) publishScriptNew(s string) {
	if atomic.LoadUint32(&e.status) != 1 {
		return
	}
	e.in <- event{Action: "script_new", Name: s}
}
func (e *eventManager) publishSessionNew(s string) {
	if atomic.LoadUint32(&e.status) != 1 {
		return
	}
	e.in <- event{Action: "session_new", Name: s}
}
func (e *eventManager) publishProfileNew(s string) {
	if atomic.LoadUint32(&e.status) != 1 {
		return
	}
	e.in <- event{Action: "profile_new", Name: s}
}
func (e *eventManager) subscribe(n *websocket.Conn) {
	if atomic.LoadUint32(&e.status) != 1 {
		return
	}
	e.new <- n
}
func (e *eventManager) publishListenerNew(s string) {
	if atomic.LoadUint32(&e.status) != 1 {
		return
	}
	e.in <- event{Action: "listener_new", Name: s}
}
func (e *eventManager) publishScriptUpdate(s string) {
	if atomic.LoadUint32(&e.status) != 1 {
		return
	}
	e.in <- event{Action: "script_update", Name: s}
}
func (e *eventManager) publishScriptDelete(s string) {
	if atomic.LoadUint32(&e.status) != 1 {
		return
	}
	e.in <- event{Action: "script_delete", Name: s}
}
func (e *eventManager) publishSessionDelete(s string) {
	if atomic.LoadUint32(&e.status) != 1 {
		return
	}
	e.in <- event{Action: "session_delete", Name: s}
}
func (e *eventManager) publishProfileDelete(s string) {
	if atomic.LoadUint32(&e.status) != 1 {
		return
	}
	e.in <- event{Action: "profile_delete", Name: s}
}
func (e *eventManager) publishProfileUpdate(s string) {
	if atomic.LoadUint32(&e.status) != 1 {
		return
	}
	e.in <- event{Action: "profile_update", Name: s}
}
func (e *eventManager) publishSessionUpdate(s string) {
	if atomic.LoadUint32(&e.status) != 1 {
		return
	}
	e.in <- event{Action: "session_update", Name: s}
}
func (e *eventManager) publishListenerDelete(s string) {
	if atomic.LoadUint32(&e.status) != 1 {
		return
	}
	e.in <- event{Action: "listener_delete", Name: s}
}
func (e *eventManager) publishListenerUpdate(s string) {
	if atomic.LoadUint32(&e.status) != 1 {
		return
	}
	e.in <- event{Action: "listener_update", Name: s}
}
func (e *eventManager) publishJobNew(s string, j uint16) {
	if atomic.LoadUint32(&e.status) != 1 {
		return
	}
	e.in <- event{Action: "job_new", Name: s, Value: j}
}
func (e *eventManager) publishPacketNew(s string, i uint8) {
	if atomic.LoadUint32(&e.status) != 1 {
		return
	}
	e.in <- event{Action: "packet_new", Name: s, Value: uint16(i)}
}
func (e *eventManager) publishJobUpdate(s string, j uint16) {
	if atomic.LoadUint32(&e.status) != 1 {
		return
	}
	e.in <- event{Action: "job_update", Name: s, Value: j}
}
func (e *eventManager) publishJobDelete(s string, j uint16) {
	if atomic.LoadUint32(&e.status) != 1 {
		return
	}
	e.in <- event{Action: "job_delete", Name: s, Value: j}
}
func (e *eventManager) publishPacketDelete(s string, i uint8) {
	if atomic.LoadUint32(&e.status) != 1 {
		return
	}
	e.in <- event{Action: "packet_delete", Name: s, Value: uint16(i)}
}
func (e *eventManager) publishJobComplete(s string, j uint16) {
	if atomic.LoadUint32(&e.status) != 1 {
		return
	}
	e.in <- event{Action: "job_complete", Name: s, Value: j}
}
func (e *eventManager) publishJobReceiving(s string, j, t, c uint16) {
	if atomic.LoadUint32(&e.status) != 1 {
		return
	}
	e.in <- event{Action: "job_receiving", Name: s, Value: j, Total: t, Count: c}
}

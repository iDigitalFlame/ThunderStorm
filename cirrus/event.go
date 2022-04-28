package cirrus

import (
	"context"
	"sync/atomic"

	"github.com/gorilla/websocket"
)

type event struct {
	Name   string `json:"name"`
	Action string `json:"action"`
	Value  uint16 `json:"value,omitempty"`
}
type eventManager struct {
	*Cirrus
	in      chan event
	new     chan *websocket.Conn
	clients []*websocket.Conn
	status  uint32
}

func (e *eventManager) run(x context.Context) {
loop:
	for atomic.SwapUint32(&e.status, 1); ; {
		select {
		case <-x.Done():
			break loop
		case n := <-e.in:
			c := make([]*websocket.Conn, 0, len(e.clients))
			for i := range e.clients {
				if err := e.clients[i].WriteJSON(n); err == nil {
					c = append(c, e.clients[i])
					continue
				}
				e.clients[i].Close()
			}
			e.clients, c = c, nil
		case n := <-e.new:
			e.clients = append(e.clients, n)
		}
	}
	atomic.SwapUint32(&e.status, 0)
	for i := range e.clients {
		e.clients[i].Close()
	}
	e.clients = nil
	close(e.new)
	close(e.in)
	close(e.ch)
}
func (e *eventManager) publishSessionNew(s string) {
	if atomic.LoadUint32(&e.status) == 0 {
		return
	}
	e.in <- event{Action: "session_new", Name: s}
}
func (e *eventManager) publishProfileNew(s string) {
	if atomic.LoadUint32(&e.status) == 0 {
		return
	}
	e.in <- event{Action: "profile_new", Name: s}
}
func (e *eventManager) subscribe(n *websocket.Conn) {
	if atomic.LoadUint32(&e.status) == 0 {
		return
	}
	e.new <- n
}
func (e *eventManager) publishListenerNew(s string) {
	if atomic.LoadUint32(&e.status) == 0 {
		return
	}
	e.in <- event{Action: "listener_new", Name: s}
}
func (e *eventManager) publishSessionDelete(s string) {
	if atomic.LoadUint32(&e.status) == 0 {
		return
	}
	e.in <- event{Action: "session_delete", Name: s}
}
func (e *eventManager) publishProfileDelete(s string) {
	if atomic.LoadUint32(&e.status) == 0 {
		return
	}
	e.in <- event{Action: "profile_delete", Name: s}
}
func (e *eventManager) publishProfileUpdate(s string) {
	if atomic.LoadUint32(&e.status) == 0 {
		return
	}
	e.in <- event{Action: "profile_update", Name: s}
}
func (e *eventManager) publishSessionUpdate(s string) {
	if atomic.LoadUint32(&e.status) == 0 {
		return
	}
	e.in <- event{Action: "session_update", Name: s}
}
func (e *eventManager) publishListenerDelete(s string) {
	if atomic.LoadUint32(&e.status) == 0 {
		return
	}
	e.in <- event{Action: "listener_delete", Name: s}
}
func (e *eventManager) publishListenerUpdate(s string) {
	if atomic.LoadUint32(&e.status) == 0 {
		return
	}
	e.in <- event{Action: "listener_update", Name: s}
}
func (e *eventManager) publishJobNew(s string, j uint16) {
	if atomic.LoadUint32(&e.status) == 0 {
		return
	}
	e.in <- event{Action: "job_new", Name: s, Value: j}
}
func (e *eventManager) publishJobUpdate(s string, j uint16) {
	if atomic.LoadUint32(&e.status) == 0 {
		return
	}
	e.in <- event{Action: "job_update", Name: s, Value: j}
}

func (e *eventManager) publishJobDelete(s string, j uint16) {
	if atomic.LoadUint32(&e.status) == 0 {
		return
	}
	e.in <- event{Action: "job_delete", Name: s, Value: j}
}
func (e *eventManager) publishJobComplete(s string, j uint16) {
	if atomic.LoadUint32(&e.status) == 0 {
		return
	}
	e.in <- event{Action: "job_complete", Name: s, Value: j}
}
func (e *eventManager) publishJobReceiving(s string, j uint16) {
	if atomic.LoadUint32(&e.status) == 0 {
		return
	}
	e.in <- event{Action: "job_receiving", Name: s, Value: j}
}

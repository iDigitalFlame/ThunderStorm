package cirrus

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PurpleSec/routex"
	"github.com/iDigitalFlame/xmt/com"
	"github.com/iDigitalFlame/xmt/util/text"
)

const (
	msgNoPacket = "packet was not found"

	packetExpire = time.Minute * 10
)

type packet struct {
	Time time.Time
	*com.Packet
}
type packetManager struct {
	*Cirrus
	sync.RWMutex

	e map[string]*packet
}

func (c *Cirrus) prunePackets() {
	if c.packets.Lock(); len(c.packets.e) > 0 {
		n := time.Now()
		for k, v := range c.packets.e {
			if v.Time.Add(packetExpire).After(n) {
				continue
			}
			v.Clear()
			c.packets.e[k] = nil
			delete(c.packets.e, k)
			c.packets.events.publishPacketDelete(k, v.ID)
			v = nil
		}
	}
	c.packets.Unlock()
}
func (c *Cirrus) packetNew(n *com.Packet) {
	if n == nil || n.Flags&com.FlagOneshot == 0 {
		return
	}
	v := text.Lower.String(16)
	c.packets.Lock()
	if _, ok := c.packets.e[v]; ok {
		c.packets.Unlock()
		return
	}
	c.packets.e[v] = &packet{Packet: n, Time: time.Now()}
	c.packets.Unlock()
	c.events.publishPacketNew(v, n.ID)
	c.packetEvent(n)
}
func (p *packetManager) httpPacketsGet(_ context.Context, w http.ResponseWriter, _ *routex.Request) {
	p.RLock()
	if w.Write([]byte{'{'}); len(p.e) > 0 {
		var n int
		for k, v := range p.e {
			if len(k) == 0 {
				continue
			}
			if n > 0 {
				w.Write([]byte{','})
			}
			w.Write([]byte(
				`"` + k + `": {"id":` + strconv.FormatUint(uint64(v.ID), 10) + `,"flags":"` + v.Flags.String() + `","device":"` + v.Device.String() +
					`","sig":"` + v.Device.Full() + `","time":"` + v.Time.Format(time.RFC3339) + `"}`,
			))
			n++
		}
	}
	p.RUnlock()
	w.Write([]byte{'}'})
}
func (p *packetManager) httpPacketGetDelete(_ context.Context, w http.ResponseWriter, r *routex.Request) {
	n := r.Values.StringDefault("name", "")
	if len(n) == 0 {
		writeError(http.StatusNotFound, msgNoPacket, w, r)
		return
	}
	i := strings.ToLower(n)
	p.RLock()
	v, ok := p.e[i]
	if p.RUnlock(); !ok {
		writeError(http.StatusNotFound, msgNoPacket, w, r)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(
		`{"id":` + strconv.FormatUint(uint64(v.ID), 10) + `,"flags":"` + v.Flags.String() + `","device":"` + v.Device.String() +
			`","sig":"` + v.Device.Full() + `"hardware":"` + v.Device.Signature() + `","time":"` + v.Time.Format(time.RFC3339) + `","data":"`,
	))
	writeBase64(w, v.Payload())
	if w.Write([]byte{'"', '}'}); !r.IsDelete() {
		v.Seek(0, 0)
		return
	}
	v.Clear()
	p.Lock()
	p.e[i] = nil
	delete(p.e, i)
	p.Unlock()
	p.events.publishPacketDelete(n, v.ID)
}

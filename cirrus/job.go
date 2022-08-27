// Copyright (C) 2020 - 2022 iDigitalFlame
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
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/PurpleSec/routex"
	"github.com/iDigitalFlame/xmt/c2"
	"github.com/iDigitalFlame/xmt/data"
)

const msgNoJob = "job was not found"

type jobManager struct {
	sync.RWMutex
	*Cirrus

	e map[uint64]*c2.Job
}

func (c *Cirrus) removeJob(j *c2.Job) {
	c.events.publishJobDelete(j.Session().ID.String(), j.ID)
}
func (c *Cirrus) completeJob(j *c2.Job) {
	switch c.jobEvent(j.Session(), j, ""); j.Status {
	case c2.StatusAccepted:
		c.events.publishJobUpdate(j.Session().ID.String(), j.ID)
	case c2.StatusReceiving:
		c.events.publishJobReceiving(j.Session().ID.String(), j.ID, j.Frags, j.Current)
	case c2.StatusCompleted, c2.StatusError:
		c.events.publishJobComplete(j.Session().ID.String(), j.ID)
	}
}
func (j *jobManager) prune(x context.Context) {
	for t := time.NewTicker(time.Minute); ; {
		select {
		case n := <-t.C:
			j.prunePackets()
			if j.Lock(); len(j.e) > 0 {
				for k, v := range j.e {
					var t time.Duration
					switch {
					case v.Session().Last.IsZero():
						t = time.Hour
					case !v.IsDone() || v.Complete.IsZero():
						t = time.Since(v.Session().Last)*3 + (time.Minute * 15)
					default:
						t = v.Complete.Sub(v.Start)*3 + (time.Minute * 15)
					}
					if !v.Complete.IsZero() {
						if n.Sub(v.Complete) < t {
							continue
						}
					} else if n.Sub(v.Start) < t {
						continue
					}
					if j.removeJob(v); v.Result != nil {
						v.Result.Clear()
					}
					j.e[k] = nil
					delete(j.e, k)
				}
			}
			if j.sessions.Lock(); len(j.sessions.e) > 0 {
				for i := range j.sessions.e {
					if j.sessions.e[i].Lock(); len(j.sessions.e[i].j) == 0 {
						j.sessions.e[i].Unlock()
						continue
					}
					if len(j.sessions.e[i].j) == 1 {
						// Fastpath, we only need to check one.
						if _, ok := j.e[uint64(j.sessions.e[i].h)<<16|uint64(j.sessions.e[i].j[0])]; !ok {
							// If job does not exist, fastpath reslice the array (keeps the backing memory)
							j.sessions.e[i].j = j.sessions.e[i].j[:0]
						}
						j.sessions.e[i].Unlock()
						continue
					}
					b := make([]uint16, 0, len(j.sessions.e[i].j)) // Cache array
					for x := range j.sessions.e[i].j {
						// Inverse cache, copy all ACTIVE to the backed array and 'copy' and reslice
						if _, ok := j.e[uint64(j.sessions.e[i].h)<<16|uint64(j.sessions.e[i].j[x])]; !ok {
							// NOT ACTIVE, IGNORE
							continue
						}
						// Add to cache
						b = append(b, j.sessions.e[i].j[x])
					}
					if len(b) > 0 {
						// Copy and reslice
						j.sessions.e[i].j = j.sessions.e[i].j[:copy(j.sessions.e[i].j, b)]
					}
					b = nil
					j.sessions.e[i].Unlock()
				}
			}
			j.sessions.Unlock()
			j.Unlock()
		case <-x.Done():
			t.Stop()
			return
		}
	}
}
func (c *Cirrus) watchJob(s *session, j *c2.Job, v string) {
	if j == nil || j.ID == 0 || s == nil {
		return
	}
	if s.Lock(); s.j == nil {
		s.j = make([]uint16, 0, 32)
	}
	s.j = append(s.j, j.ID)
	s.Unlock()
	c.jobs.Lock()
	c.jobs.e[uint64(s.h)<<16|uint64(j.ID)] = j
	c.jobs.Unlock()
	c.events.publishJobNew(s.s.ID.String(), j.ID)
	j.Update = c.completeJob
	c.jobEvent(s.s, j, v)
}
func (c *Cirrus) job(s string, j uint64, d bool) (*c2.Job, string) {
	if j == 0 || j > data.LimitMedium {
		return nil, msgNoJob
	}
	x := c.session(s)
	if x == nil {
		return nil, msgNoSession
	}
	c.jobs.RLock()
	var (
		a     = uint64(x.h)<<16 | j
		v, ok = c.jobs.e[a]
	)
	if c.jobs.RUnlock(); !ok {
		return nil, msgNoJob
	}
	if !d {
		return v, ""
	}
	if x.Lock(); len(x.j) == 1 {
		x.j = x.j[:0]
	}
	x.Unlock()
	c.jobs.Lock()
	c.jobs.e[a] = nil
	delete(c.jobs.e, a)
	c.jobs.Unlock()
	x = nil
	return v, ""
}
func (j *jobManager) httpJobsGet(_ context.Context, w http.ResponseWriter, r *routex.Request) {
	x := j.session(r.Values.StringDefault("session", ""))
	if x == nil {
		writeError(http.StatusNotFound, msgNoSession, w, r)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte{'{'})
	if x.RLock(); len(x.j) > 0 {
		j.RLock()
		for n, i := 0, 0; i < len(x.j); i++ {
			if n > 0 {
				w.Write([]byte{','})
			}
			if v, ok := j.e[uint64(x.h)<<16|uint64(x.j[i])]; ok {
				w.Write([]byte(`"` + strconv.FormatUint(uint64(x.j[i]), 10) + `":`))
				v.JSON(w)
				n++
			}
		}
		j.RUnlock()
	}
	x.RUnlock()
	w.Write([]byte{'}'})
}
func (j *jobManager) httpJobGetDelete(_ context.Context, w http.ResponseWriter, r *routex.Request) {
	v, msg := j.job(r.Values.StringDefault("session", ""), r.Values.UintDefault("job", 0), r.IsDelete())
	if v == nil {
		writeError(http.StatusNotFound, msg, w, r)
		return
	}
	w.WriteHeader(http.StatusOK)
	v.JSON(w)
}
func (j *jobManager) httpJobResultGetDelete(_ context.Context, w http.ResponseWriter, r *routex.Request) {
	v, msg := j.job(r.Values.StringDefault("session", ""), r.Values.UintDefault("job", 0), r.IsDelete())
	if v == nil {
		writeError(http.StatusNotFound, msg, w, r)
		return
	}
	switch {
	case v.Status == c2.StatusError:
		writeError(http.StatusPartialContent, v.Error, w, r)
	case v.Status < c2.StatusCompleted:
		writeError(http.StatusTooEarly, "job not yet completed", w, r)
	case v.Result == nil || v.Result.Empty():
		w.WriteHeader(http.StatusNoContent)
	default:
		if err := writeJobJSON(false, v.Type, v.Result, w); err != nil {
			writeError(http.StatusInternalServerError, "job type is invald", w, r)
		}
		v.Result.Seek(0, 0)
	}
}

/*
 * Copyright 2019 Dgraph Labs, Inc. and Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package badger

import (
	"bytes"
	"sync"

	"github.com/dgraph-io/badger/pb"
	"github.com/dgraph-io/badger/y"
)

type subscriber struct {
	prefix []byte
	sendCh chan<- *pb.KVList
}

type publisher struct {
	sync.Mutex
	pubCh       chan []*request
	subscribers map[uint64]subscriber
	lastID      uint64
}

func newPublisher() *publisher {
	return &publisher{
		pubCh:       make(chan []*request, 10000),
		subscribers: make(map[uint64]subscriber),
		lastID:      0,
	}
}

func (p *publisher) listenForUpdates(c *y.Closer) {
	defer func() {
		c.Done()
		p.cleanSubscribers()
	}()

listen:
	for {
		reqs := []*request{}
		select {
		case <-c.HasBeenClosed():
			break listen
		case r := <-p.pubCh:
			reqs = append(reqs, r...)
		}
	drainer:
		for {
			select {
			case r := <-p.pubCh:
				reqs = append(reqs, r...)
			default:
				break drainer
			}
		}
		p.publishUpdates(reqs)
	}
}

func (p *publisher) publishUpdates(reqs []*request) {
	p.Lock()
	defer p.Unlock()
	for id, s := range p.subscribers {
		kvs := &pb.KVList{}
		for _, req := range reqs {
			for _, e := range req.Entries {
				if bytes.HasPrefix(e.Key, s.prefix) {
					k := y.SafeCopy(nil, e.Key)
					kv := &pb.KV{
						Key:       y.ParseKey(k),
						Value:     y.SafeCopy(nil, e.Value),
						Meta:      []byte{e.UserMeta},
						ExpiresAt: e.ExpiresAt,
						Version:   y.ParseTs(k),
					}
					kvs.Kv = append(kvs.Kv, kv)
				}
			}
			req.DecrRef() // release the request
		}
		if len(kvs.GetKv()) > 0 {
			select {
			case s.sendCh <- kvs:
			default:
				close(s.sendCh)
				delete(p.subscribers, id)
			}
		}
	}
}

func (p *publisher) newSubscriber(prefix []byte) (<-chan *pb.KVList, uint64) {
	p.Lock()
	defer p.Unlock()
	ch := make(chan *pb.KVList, 1000)
	// increment last ID
	p.lastID++
	p.subscribers[p.lastID] = subscriber{
		prefix: prefix,
		sendCh: ch,
	}
	return ch, p.lastID
}

// cleanSubscribers stops all the subscribers. Ideally, It should be called while closing DB
func (p *publisher) cleanSubscribers() {
	p.Lock()
	defer p.Unlock()
	for id, s := range p.subscribers {
		close(s.sendCh)
		delete(p.subscribers, id)
	}
}

func (p *publisher) deleteSubscriber(id uint64) {
	p.Lock()
	defer p.Unlock()
	subscriber, ok := p.subscribers[id]
	if !ok {
		return
	}
	close(subscriber.sendCh)
	delete(p.subscribers, id)
}

func (p *publisher) sendUpdates(reqs []*request) {
	p.pubCh <- reqs
}

/*
 * Copyright 2017 Dgraph Labs, Inc. and Contributors
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
	"container/heap"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/dgraph-io/badger/y"
	farm "github.com/dgryski/go-farm"
	"github.com/pkg/errors"
)

type uint64Heap []uint64

func (u uint64Heap) Len() int               { return len(u) }
func (u uint64Heap) Less(i int, j int) bool { return u[i] < u[j] }
func (u uint64Heap) Swap(i int, j int)      { u[i], u[j] = u[j], u[i] }
func (u *uint64Heap) Push(x interface{})    { *u = append(*u, x.(uint64)) }
func (u *uint64Heap) Pop() interface{} {
	old := *u
	n := len(old)
	x := old[n-1]
	*u = old[0 : n-1]
	return x
}

type globalTxnState struct {
	sync.Mutex
	curRead    uint64
	nextCommit uint64

	// These two structures are used to figure out when a commit is done. The minimum done commit is
	// used to update curRead.
	commitMark     uint64Heap
	pendingCommits map[uint64]struct{}

	// commits stores a key fingerprint and latest commit counter for it.
	commits map[uint64]uint64
}

func (gs *globalTxnState) readTs() uint64 {
	return atomic.LoadUint64(&gs.curRead)
}

// hasConflict must be called while having a lock.
func (gs *globalTxnState) hasConflict(txn *Txn) bool {
	if len(txn.reads) == 0 {
		return false
	}
	for _, ro := range txn.reads {
		if ts, has := gs.commits[ro]; has && ts > txn.readTs {
			return true
		}
	}
	return false
}

func (gs *globalTxnState) newCommitTs(txn *Txn) uint64 {
	gs.Lock()
	defer gs.Unlock()

	if gs.hasConflict(txn) {
		return 0
	}
	ts := gs.nextCommit
	for _, w := range txn.writes {
		gs.commits[w] = ts // Update the commitTs.
	}
	heap.Push(&gs.commitMark, ts)
	if _, has := gs.pendingCommits[ts]; has {
		panic(fmt.Sprintf("We shouldn't have the commit ts: %d", ts))
	}
	gs.pendingCommits[ts] = struct{}{}

	gs.nextCommit++
	return ts
}

func (gs *globalTxnState) doneCommit(cts uint64) {
	gs.Lock()
	defer gs.Unlock()

	if _, has := gs.pendingCommits[cts]; !has {
		panic(fmt.Sprintf("We should already have the commit ts: %d", cts))
	}
	delete(gs.pendingCommits, cts)

	var min uint64
	for len(gs.commitMark) > 0 {
		ts := gs.commitMark[0]
		if _, has := gs.pendingCommits[ts]; has {
			// Still waiting for a txn to commit.
			break
		}
		min = ts
		heap.Pop(&gs.commitMark)
	}
	if min == 0 {
		return
	}
	atomic.StoreUint64(&gs.curRead, min)
	// nextCommit must never be reset.
}

type Txn struct {
	readTs uint64

	update bool     // update is used to conditionally keep track of reads.
	reads  []uint64 // contains fingerprints of keys read.
	writes []uint64 // contains fingerprints of keys written.

	pendingWrites map[string]*Entry // cache stores any writes done by txn.

	gs *globalTxnState
	kv *KV
}

// Set sets the provided value for a given key. If key is not present, it is created.  If it is
// present, a new version is created at commit timestamp.
// Along with key and value, Set can also take an optional userMeta byte. This byte is stored
// alongside the key, and can be used as an aid to interpret the value or store other contextual
// bits corresponding to the key-value pair.
// If this is not an update transaction, Set would be a NOOP.
// This would fail with ErrReadOnlyTxn if update flag was set to false when creating this
// transaction.
func (txn *Txn) Set(key, val []byte, userMeta byte) error {
	if !txn.update {
		return ErrReadOnlyTxn
	} else if len(key) == 0 {
		return ErrEmptyKey
	} else if len(key) > maxKeySize {
		return exceedsMaxKeySizeError(key)
	} else if int64(len(val)) > txn.kv.opt.ValueLogFileSize {
		return exceedsMaxValueSizeError(val, txn.kv.opt.ValueLogFileSize)
	}

	fp := farm.Fingerprint64(key) // Avoid dealing with byte arrays.
	txn.writes = append(txn.writes, fp)

	e := &Entry{
		Key:      key,
		Value:    val,
		UserMeta: userMeta,
	}
	txn.pendingWrites[string(key)] = e
	return nil
}

// Delete deletes a key. This is done by adding a delete marker for the key at commit timestamp.
// Any reads happening before this timestamp would be unaffected. Any reads after this commit would
// see the deletion.
func (txn *Txn) Delete(key []byte) error {
	if !txn.update {
		return ErrReadOnlyTxn
	} else if len(key) == 0 {
		return ErrEmptyKey
	} else if len(key) > maxKeySize {
		return exceedsMaxKeySizeError(key)
	}

	fp := farm.Fingerprint64(key) // Avoid dealing with byte arrays.
	txn.writes = append(txn.writes, fp)

	e := &Entry{
		Key:  key,
		Meta: BitDelete,
	}
	txn.pendingWrites[string(key)] = e
	return nil
}

// Get looks for key and returns a KVItem.
// If key is not found, item.Value() is nil.
func (txn *Txn) Get(key []byte) (item KVItem, rerr error) {
	if txn.update {
		if e, has := txn.pendingWrites[string(key)]; has && bytes.Compare(key, e.Key) == 0 {
			// Fulfill from cache.
			item.meta = e.Meta
			item.val = e.Value
			item.userMeta = e.UserMeta
			item.key = key
			item.status = prefetched
			// We probably don't need to set KV on item here.
			return item, nil
		}
		fp := farm.Fingerprint64(key)
		txn.reads = append(txn.reads, fp)
	}

	seek := y.KeyWithTs(key, txn.readTs)
	next, vs, err := txn.kv.get(seek)
	if err != nil {
		return item, errors.Wrapf(err, "KV::Get key: %q", key)
	}
	if vs.Value == nil && vs.Meta == 0 {
		return item, ErrKeyNotFound
	}
	if (vs.Meta & BitDelete) != 0 {
		return item, ErrKeyNotFound
	}

	item.meta = vs.Meta
	item.userMeta = vs.UserMeta
	item.key = next
	item.kv = txn.kv
	item.vptr = vs.Value
	return item, nil
}

// Commit commits the transaction, following these steps:
// 1. If there are no writes, return immediately.
// 2. Check if read rows were updated since txn started. If so, return ErrConflict.
// 3. If no conflict, generate a commit timestamp and update written rows' commit ts.
// 4. Batch up all writes, write them to value log and LSM tree.
// 5. If callback is provided, don't block on these writes, running this part asynchronously. The
// callback would be run once writes are done, along with any errors.
//
// If error is nil, the transaction is successfully committed. Else, Badger would automatically
// rollback the transaction, removing any writes from LSM tree. Note that the writes might be
// present on value log, but those can be garbage collected later.
func (txn *Txn) Commit(callback func(error)) error {
	if len(txn.writes) == 0 {
		return nil // Read only transaction.
	}

	commitTs := txn.gs.newCommitTs(txn)
	if commitTs == 0 {
		return ErrConflict
	}
	defer txn.gs.doneCommit(commitTs)

	entries := make([]*Entry, 0, len(txn.pendingWrites)+1)
	for _, e := range txn.pendingWrites {
		// Suffix the keys with commit ts, so the key versions are sorted in
		// descending order of commit timestamp.
		e.Key = y.KeyWithTs(e.Key, commitTs)
		entries = append(entries, e)
	}
	// TODO: Add logic in replay to deal with this.
	entry := &Entry{
		Key:   txnKey,
		Value: []byte(strconv.FormatUint(commitTs, 10)),
		Meta:  BitFinTxn,
	}
	entries = append(entries, entry)
	if callback == nil {
		err := txn.kv.batchSet(entries)
		if err != nil {
			// TODO: Run cleanup.
		}
		return err
	}

	cb := func(err error) {
		if err != nil {
			// TODO: Run cleanup.
		}
		callback(err)
	}
	txn.kv.batchSetAsync(entries, callback)
	return nil
}

// NewIterator returns a new iterator. Depending upon the options, either only keys, or both
// key-value pairs would be fetched. The keys are returned in lexicographically sorted order.
// Usage:
//   opt := badger.DefaultIteratorOptions
//   itr := txn.NewIterator(opt)
//   for itr.Rewind(); itr.Valid(); itr.Next() {
//     item := itr.Item()
//     key := item.Key()
//     var val []byte
//     err = item.Value(func(v []byte) {
//         val = make([]byte, len(v))
// 	       copy(val, v)
//     }) 	// This could block while value is fetched from value log.
//          // For key only iteration, set opt.PrefetchValues to false, and don't call
//          // item.Value(func(v []byte)).
//
//     // Remember that both key, val would become invalid in the next iteration of the loop.
//     // So, if you need access to them outside, copy them or parse them.
//   }
//   itr.Close()
// TODO: Move this usage to README.
func (txn *Txn) NewIterator(opt IteratorOptions) *Iterator {
	tables, decr := txn.kv.getMemTables()
	defer decr()
	txn.kv.vlog.incrIteratorCount()
	var iters []y.Iterator
	for i := 0; i < len(tables); i++ {
		iters = append(iters, tables[i].NewUniIterator(opt.Reverse))
	}
	iters = txn.kv.lc.appendIterators(iters, opt.Reverse) // This will increment references.
	res := &Iterator{
		txn:    txn,
		iitr:   y.NewMergeIterator(iters, opt.Reverse),
		opt:    opt,
		readTs: txn.readTs,
	}
	return res
}
func (kv *KV) NewTransaction(update bool) (*Txn, error) {
	txn := &Txn{
		update:        update,
		gs:            kv.txnState,
		kv:            kv,
		readTs:        kv.txnState.readTs(),
		pendingWrites: make(map[string]*Entry),
	}

	return txn, nil
}

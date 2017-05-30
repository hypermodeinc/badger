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
	"sort"
	"sync"

	"github.com/dgraph-io/badger/table"
	"github.com/dgraph-io/badger/y"
	"github.com/pkg/errors"
)

type levelHandler struct {
	// Guards tables, totalSize.
	sync.RWMutex

	// For level >= 1, tables are sorted by key ranges, which do not overlap.
	// For level 0, tables are sorted by time.
	// For level 0, newest table are at the back. Compact the oldest one first, which is at the front.
	tables    []*table.Table
	totalSize int64

	// The following are initialized once and const.
	level        int
	maxTotalSize int64
	kv           *KV
}

func (s *levelHandler) getTotalSize() int64 {
	s.RLock()
	defer s.RUnlock()
	return s.totalSize
}

// initTables replaces s.tables with given tables. This is done during loading.
func (s *levelHandler) initTables(tables []*table.Table) {
	s.Lock()
	defer s.Unlock()

	s.tables = tables
	s.totalSize = 0
	for _, t := range tables {
		s.totalSize += t.Size()
	}

	if s.level == 0 {
		// Key range will overlap. Just sort by fileID in ascending order
		// because newer tables are at the end of level 0.
		sort.Slice(s.tables, func(i, j int) bool {
			return s.tables[i].ID() < s.tables[j].ID()
		})
	} else {
		// Sort tables by keys.
		sort.Slice(s.tables, func(i, j int) bool {
			return bytes.Compare(s.tables[i].Smallest(), s.tables[j].Smallest()) < 0
		})
	}
}

// deleteTables remove tables idx0, ..., idx1-1.
func (s *levelHandler) deleteTables(toDel []*table.Table) {
	s.Lock()
	defer s.Unlock()

	toDelMap := make(map[uint64]struct{})
	for _, t := range toDel {
		toDelMap[t.ID()] = struct{}{}
	}
	// Make a copy as iterators might be keeping a slice of tables.
	var newTables []*table.Table
	for _, t := range s.tables {
		_, found := toDelMap[t.ID()]
		if !found {
			newTables = append(newTables, t)
			continue
		}
		s.totalSize -= t.Size()
		t.DecrRef()
	}
	s.tables = newTables
}

// replaceTables will replace tables[left:right] with newTables. Note this EXCLUDES tables[right].
func (s *levelHandler) replaceTables(newTables []*table.Table) {
	s.Lock()
	defer s.Unlock()

	// Need to re-search the range of tables in this level to be replaced as
	// other goroutines might be changing it as well.
	y.AssertTrue(len(newTables) > 0)

	// Increase totalSize first.
	for _, tbl := range newTables {
		s.totalSize += tbl.Size()
		tbl.IncrRef()
	}

	left, right := s.overlappingTables(
		newTables[0].Smallest(), newTables[len(newTables)-1].Biggest())

	// Update totalSize and reference counts.
	for i := left; i < right; i++ {
		s.totalSize -= s.tables[i].Size()
		s.tables[i].DecrRef()
	}

	// To be safe, just make a copy. TODO: Be more careful and avoid copying.
	numDeleted := right - left
	numAdded := len(newTables)
	tables := make([]*table.Table, len(s.tables)-numDeleted+numAdded)
	y.AssertTrue(left == copy(tables, s.tables[:left]))
	t := tables[left:]
	y.AssertTrue(numAdded == copy(t, newTables))
	t = t[numAdded:]
	y.AssertTrue(len(s.tables[right:]) == copy(t, s.tables[right:]))
	s.tables = tables
}

// pickCompactTables returns a range of tables to be compacted away.
func (s *levelHandler) pickCompactTables() (int, int) {
	s.RLock() // Not really necessary.
	defer s.RUnlock()

	if s.level == 0 {
		// For now, for level 0, we return all the tables.
		// Note that during compaction, s.tables might grow longer. This is fine. The indices into
		// s.tables remain valid because these new tables are appended to the back of s.tables.
		return 0, len(s.tables)
	}

	// For other levels, pick the largest table.
	var idx int
	mx := s.tables[0].Size()
	for i := 1; i < len(s.tables); i++ {
		size := s.tables[i].Size()
		if size > mx {
			mx = size
			idx = i
		}
	}
	return idx, idx + 1
}

func newLevelHandler(kv *KV, level int) *levelHandler {
	return &levelHandler{
		level: level,
		kv:    kv,
	}
}

// tryAddLevel0Table returns true if ok and no stalling.
func (s *levelHandler) tryAddLevel0Table(t *table.Table) bool {
	y.AssertTrue(s.level == 0)
	// Need lock as we may be deleting the first table during a level 0 compaction.
	s.Lock()
	defer s.Unlock()
	if len(s.tables) > s.kv.opt.NumLevelZeroTablesStall {
		return false
	}

	s.tables = append(s.tables, t)
	t.IncrRef()
	s.totalSize += t.Size()

	y.Printf("Num level 0 tables increased from %d to %d\n", len(s.tables)-1, len(s.tables))
	return true
}

func (s *levelHandler) numTables() int {
	s.RLock()
	defer s.RUnlock()
	return len(s.tables)
}

func (s *levelHandler) close() error {
	s.RLock()
	defer s.RUnlock()
	for _, t := range s.tables {
		if err := t.Close(); err != nil {
			return errors.Wrap(err, "levelHandler.Close")
		}
	}
	return nil
}

// getTableForKey acquires a read-lock to access s.tables. It returns a list of tableHandlers.
func (s *levelHandler) getTableForKey(key []byte) ([]*table.Table, func() error) {
	s.RLock()
	defer s.RUnlock()

	if s.level == 0 {
		// For level 0, we need to check every table. Remember to make a copy as s.tables may change
		// once we exit this function, and we don't want to lock s.tables while seeking in tables.
		// CAUTION: Reverse the tables.
		out := make([]*table.Table, 0, len(s.tables))
		for i := len(s.tables) - 1; i >= 0; i-- {
			out = append(out, s.tables[i])
			s.tables[i].IncrRef()
		}
		return out, func() error {
			for _, t := range out {
				if err := t.DecrRef(); err != nil {
					return err
				}
			}
			return nil
		}
	}
	// For level >= 1, we can do a binary search as key range does not overlap.
	idx := sort.Search(len(s.tables), func(i int) bool {
		return bytes.Compare(s.tables[i].Biggest(), key) >= 0
	})
	if idx >= len(s.tables) {
		// Given key is strictly > than every element we have.
		return nil, func() error { return nil }
	}
	tbl := s.tables[idx]
	tbl.IncrRef()
	return []*table.Table{tbl}, tbl.DecrRef
}

// get returns value for a given key. If not found, return nil.
func (s *levelHandler) get(key []byte) (y.ValueStruct, error) {
	tables, decr := s.getTableForKey(key)

	for _, th := range tables {
		if th.DoesNotHave(key) {
			continue
		}

		it := th.NewIterator(false)
		defer it.Close()

		it.Seek(key)
		if !it.Valid() {
			continue
		}
		if bytes.Equal(key, it.Key()) {
			return it.Value(), decr()
		}
	}
	return y.ValueStruct{}, decr()
}

// appendIterators appends iterators to an array of iterators, for merging.
// Note: This obtains references for the table handlers. Remember to close these iterators.
func (s *levelHandler) appendIterators(iters []y.Iterator, reversed bool) []y.Iterator {
	s.RLock()
	defer s.RUnlock()

	if s.level == 0 {
		// Remember to add in reverse order!
		// The newer table at the end of s.tables should be added first as it takes precedence.
		return appendIteratorsReversed(iters, s.tables, reversed)
	}
	return append(iters, table.NewConcatIterator(s.tables, reversed))
}

// overlappingTables returns the tables that intersect with key range.
// Returns a half-interval.
// This function should already have acquired a read lock.
func (s *levelHandler) overlappingTables(begin, end []byte) (int, int) {
	left := sort.Search(len(s.tables), func(i int) bool {
		return bytes.Compare(begin, s.tables[i].Biggest()) <= 0
	})
	right := sort.Search(len(s.tables), func(i int) bool {
		return bytes.Compare(end, s.tables[i].Smallest()) < 0
	})
	return left, right
}

/*
 * Copyright (C) 2017 Dgraph Labs, Inc. and Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package y

import "expvar"

var (
	// These are cumulative
	NumReads        *expvar.Int
	NumWrites       *expvar.Int
	NumBytesRead    *expvar.Int
	NumBytesWritten *expvar.Int
	NumLSMGets      *expvar.Map
	NumLSMBloomHits *expvar.Map
	NumGets         *expvar.Map
	NumPuts         *expvar.Map
	NumMemtableGets *expvar.Map
	LSMSize         *expvar.Map
	VlogSize        *expvar.Map
)

// these variables are global and would have cummulative values for all kv stores.
func init() {
	NumReads = expvar.NewInt("badger_disk_reads_total")
	NumWrites = expvar.NewInt("badger_disk_writes_total")
	NumBytesRead = expvar.NewInt("badger_read_bytes")
	NumBytesWritten = expvar.NewInt("badger_written_bytes")
	NumLSMGets = expvar.NewMap("badger_lsm_level_gets_total")
	NumLSMBloomHits = expvar.NewMap("badger_lsm_bloom_hits_total")
	NumGets = expvar.NewMap("badger_gets_total")
	NumPuts = expvar.NewMap("badger_puts_total")
	NumMemtableGets = expvar.NewMap("badger_memtable_gets_total")
	LSMSize = expvar.NewMap("badger_lsm_size")
	VlogSize = expvar.NewMap("badger_vlog_size")
}

/*
 * Copyright 2023 Dgraph Labs, Inc. and Contributors
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

// Important: Do NOT import the "testing" package, as otherwise, that
// will pull in imports into the production class that we do not want.

// TODO: Consider using this with specific compilation tags so that it only
//       shows up when performing testing (e.g., specify build tag=unit).
//       We are not yet ready to do that, as it may impact customer usage as
//       well as requiring us to update the CI build flags. Moreover, the
//       current model does not actually incur any significant cost.
//       If we do this, we will also want to introduce a parallel file that
//       overrides some of these structs and functions with empty contents.

// testOnlyOptions specifies an extension to the type Options that we want to
// use only in the context of testing.
type testOnlyOptions struct {
	// syncChan is used to listen for specific messages related to activities
	// that can occur in a DB instance. Currently, this is only used in
	// testing activities.
	syncChan chan string

	// onCloseDiscardCapture will be populated by a DB instance during the
	// process of performing the Close operation. Currently, we only consider
	// using this during testing.
	onCloseDiscardCapture map[uint64]uint64
}

// withSyncChan returns a new Options value with syncChan set to the given value.
// If not specified, any operations that would otherwise occur with the syncChan
// will be silently skipped.
func (opt Options) withSyncChan(ch chan string) Options {
	opt.syncChan = ch
	return opt
}

// withOnCloseDiscardCapture makes a shallow copy of the map c to
// opt.onCloseDiscardCapture. When we later perform DB.Close(), we make sure to
// copy the contents of the DB.discardStats to the map c.
func (opt Options) withOnCloseDiscardCapture(c map[uint64]uint64) Options {
	opt.onCloseDiscardCapture = c
	return opt
}

// testOnlyDBExtensions specifies an extension to the type DB that we want to
// use only in the context of testing.
type testOnlyDBExtensions struct {
	syncChan chan string
}

// setSyncChan is a trivial setter for db.testOnlyDbExtensions.syncChan.
// Strictly speaking, this has little value for us, except that it
// can isolate the test-specific behaviors of a production Badger system
// to this single file.
func (db *DB) setSyncChan(ch chan string) {
	db.syncChan = ch
}

// logToSyncChan sends a message to the DB's syncChan. Note that we expect
// that the DB never closes this channel; the responsibility for
// allocating and closing the channel belongs to the test module.
// if db.syncChan is nil or has never been initialized, ths will be
// silently ignored.
func (db *DB) logToSyncChan(msg string) {
	if db.syncChan != nil {
		db.syncChan <- msg
	}
}

// captureDiscardStats will copy the contents of the discardStats file
// maintained by vlog to the onCloseDiscardCapture map specified by
// db.opt. Of couse, if db.opt.onCloseDiscardCapture is nil (as expected
// for a production system as opposed to a test system), this is a no-op.
func (db *DB) captureDiscardStats() {
	if db.opt.onCloseDiscardCapture != nil {
		db.vlog.discardStats.Lock()
		db.vlog.discardStats.Iterate(func(id, val uint64) {
			db.opt.onCloseDiscardCapture[id] = val
		})
		db.vlog.discardStats.Unlock()
	}
}

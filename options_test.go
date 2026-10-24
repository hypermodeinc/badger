/*
 * SPDX-FileCopyrightText: © 2017-2025 Istari Digital, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package badger

import (
	"reflect"
	"testing"
	"time"

	"github.com/dgraph-io/badger/v4/options"
)

func TestOptions(t *testing.T) {
	t.Run("default options", func(t *testing.T) {
		// copy all the default options over to a big SuperFlag string
		defaultSuperFlag := generateSuperFlag(DefaultOptions(""))
		// fill an empty Options with values from the SuperFlag
		generated := Options{}.FromSuperFlag(defaultSuperFlag)
		// make sure they're equal
		if !optionsEqual(DefaultOptions(""), generated) {
			t.Fatal("generated default SuperFlag != default Options")
		}
		// check that values are overwritten properly
		overwritten := DefaultOptions("").FromSuperFlag("numgoroutines=1234")
		if overwritten.NumGoroutines != 1234 {
			t.Fatal("Option value not overwritten by SuperFlag value")
		}
	})

	t.Run("special flags", func(t *testing.T) {
		o1 := DefaultOptions("")
		o1.NamespaceOffset = 10
		o1.Compression = options.ZSTD
		o1.ZSTDCompressionLevel = 2
		o1.NumGoroutines = 20

		o2 := DefaultOptions("")
		o2.NamespaceOffset = 10
		o2 = o2.FromSuperFlag("compression=zstd:2; numgoroutines=20;")

		// make sure they're equal
		if !optionsEqual(o1, o2) {
			t.Fatal("generated superFlag != expected options")
		}
	})
}

func TestCompactorSchedulingOptions(t *testing.T) {
	def := DefaultOptions("")
	if def.CompactorCheckInterval != 50*time.Millisecond {
		t.Fatalf("default CompactorCheckInterval = %v, want 50ms", def.CompactorCheckInterval)
	}
	if def.CompactorInitialDelay != 0 {
		t.Fatalf("default CompactorInitialDelay = %v, want 0 (legacy random stagger)",
			def.CompactorInitialDelay)
	}

	configured := def.
		WithCompactorCheckInterval(2 * time.Second).
		WithCompactorInitialDelay(3 * time.Second)
	if configured.CompactorCheckInterval != 2*time.Second {
		t.Fatalf("configured CompactorCheckInterval = %v, want 2s",
			configured.CompactorCheckInterval)
	}
	if configured.CompactorInitialDelay != 3*time.Second {
		t.Fatalf("configured CompactorInitialDelay = %v, want 3s",
			configured.CompactorInitialDelay)
	}
	if got := configured.compactorCheckInterval(); got != 2*time.Second {
		t.Fatalf("compactorCheckInterval() = %v, want 2s", got)
	}
	if got := configured.compactorInitialDelay(); got != 3*time.Second {
		t.Fatalf("compactorInitialDelay() = %v, want 3s", got)
	}

	if got := (Options{}).compactorCheckInterval(); got != 50*time.Millisecond {
		t.Fatalf("zero compactorCheckInterval() = %v, want the 50ms default", got)
	}
	for i := 0; i < 100; i++ {
		if got := def.compactorInitialDelay(); got < 0 || got >= time.Second {
			t.Fatalf("default compactorInitialDelay() = %v, want a value in [0, 1s)", got)
		}
	}

	for _, tc := range []struct {
		interval time.Duration
		want     int
	}{
		{interval: 50 * time.Millisecond, want: 200},
		{interval: 2 * time.Second, want: 5},
		{interval: 30 * time.Second, want: 1},
	} {
		if got := compactorLmaxTicks(tc.interval); got != tc.want {
			t.Fatalf("compactorLmaxTicks(%v) = %d, want %d", tc.interval, got, tc.want)
		}
	}

	invalidInterval := DefaultOptions("")
	invalidInterval.CompactorCheckInterval = -time.Millisecond
	if err := checkAndSetOptions(&invalidInterval); err == nil {
		t.Fatal("checkAndSetOptions accepted a negative CompactorCheckInterval")
	}

	invalidDelay := DefaultOptions("")
	invalidDelay.CompactorInitialDelay = -time.Millisecond
	if err := checkAndSetOptions(&invalidDelay); err == nil {
		t.Fatal("checkAndSetOptions accepted a negative CompactorInitialDelay")
	}
}

// optionsEqual just compares the values of two Options structs
func optionsEqual(o1, o2 Options) bool {
	o1v := reflect.ValueOf(&o1).Elem()
	o2v := reflect.ValueOf(&o2).Elem()
	for i := 0; i < o1v.NumField(); i++ {
		if o1v.Field(i).CanInterface() {
			kind := o1v.Field(i).Kind()
			// compare values
			switch kind {
			case reflect.Bool:
				if o1v.Field(i).Bool() != o2v.Field(i).Bool() {
					return false
				}
			case reflect.Int, reflect.Int64:
				if o1v.Field(i).Int() != o2v.Field(i).Int() {
					return false
				}
			case reflect.Uint32, reflect.Uint64:
				if o1v.Field(i).Uint() != o2v.Field(i).Uint() {
					return false
				}
			case reflect.Float64:
				if o1v.Field(i).Float() != o2v.Field(i).Float() {
					return false
				}
			case reflect.String:
				if o1v.Field(i).String() != o2v.Field(i).String() {
					return false
				}
			}
		}
	}
	return true
}

/*
 * SPDX-FileCopyrightText: © Hypermode Inc. <hello@hypermode.com>
 * SPDX-License-Identifier: Apache-2.0
 */

package cmd

import (
	"errors"
	"fmt"
	"math"

	"github.com/spf13/cobra"

	"github.com/dgraph-io/badger/v4"
	"github.com/dgraph-io/badger/v4/options"
)

var flattenCmd = &cobra.Command{
	Use:   "flatten",
	Short: "Flatten the LSM tree.",
	Long: `
This command would compact all the LSM tables into one level.
`,
	RunE: flatten,
}

var fo = struct {
	keyPath         string
	numWorkers      int
	numVersions     int
	compressionType uint32
}{}

func init() {
	RootCmd.AddCommand(flattenCmd)
	flattenCmd.Flags().IntVarP(&fo.numWorkers, "num-workers", "w", 1,
		"Number of concurrent compactors to run. More compactors would use more"+
			" server resources to potentially achieve faster compactions.")
	flattenCmd.Flags().IntVarP(&fo.numVersions, "num_versions", "", 0,
		"Option to configure the maximum number of versions per key. "+
			"Values <= 0 will be considered to have the max number of versions.")
	flattenCmd.Flags().StringVar(&fo.keyPath, "encryption-key-file", "",
		"Path of the encryption key file.")
	flattenCmd.Flags().Uint32VarP(&fo.compressionType, "compression", "", 1,
		"Option to configure the compression type in output DB. "+
			"0 to disable, 1 for Snappy, and 2 for ZSTD.")
}

func flatten(cmd *cobra.Command, args []string) error {
	if fo.numVersions <= 0 {
		// Keep all versions.
		fo.numVersions = math.MaxInt32
	}
	encKey, err := getKey(fo.keyPath)
	if err != nil {
		return err
	}
	if fo.compressionType > 2 {
		return errors.New(
			"compression value must be one of 0 (disabled), 1 (Snappy), or 2 (ZSTD)")
	}
	opt := badger.DefaultOptions(sstDir).
		WithValueDir(vlogDir).
		WithNumVersionsToKeep(fo.numVersions).
		WithNumCompactors(0).
		WithBlockCacheSize(100 << 20).
		WithIndexCacheSize(200 << 20).
		WithCompression(options.CompressionType(fo.compressionType)).
		WithEncryptionKey(encKey)
	fmt.Printf("Opening badger with options = %+v\n", opt)
	db, err := badger.Open(opt)
	if err != nil {
		return err
	}
	defer db.Close()

	return db.Flatten(fo.numWorkers)
}

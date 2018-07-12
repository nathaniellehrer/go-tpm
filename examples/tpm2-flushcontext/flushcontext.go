// Copyright (c) 2018, Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Flushes an object from the TPM.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var (
	tpmPath = flag.String(
		"tpm-path",
		"/dev/tpm0",
		"Path to the TPM device (character device or a Unix socket).")
	flushHandleFlag = flag.String(
		"flush-handle",
		"",
		"The object at this handle is flushed. Value must be in hex.")
)

func main() {
	flag.Parse()
	var errors []error
	flushContext(&errors)
	for _, err := range errors {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
	}
	if len(errors) > 0 {
		os.Exit(1)
	}
}

func flushContext(errors *[]error) {
	var flushHandle uint32
	if _, err := fmt.Sscanf(*flushHandleFlag, "%x", &flushHandle); err != nil {
		*errors = append(*errors, fmt.Errorf("invalid flag 'flush-handle': %s", err))
		return
	}

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		*errors = append(*errors, fmt.Errorf("can't open TPM %q: %s", *tpmPath, err))
		return
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			*errors = append(
				*errors, fmt.Errorf("unable to close connection to TPM: %s", err))
		}
	}()

	err = tpm2.FlushContext(rwc, tpmutil.Handle(flushHandle))
	if err != nil {
		*errors = append(*errors, fmt.Errorf("unable to flush object: %s", err))
		return
	}
}

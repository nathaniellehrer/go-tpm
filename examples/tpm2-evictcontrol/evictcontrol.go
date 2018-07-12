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
	objectHandleFlag = flag.String(
		"object-handle",
		"",
		"The object at this handle is evicted. Value must be in hex.")
	persistentHandleFlag = flag.String(
		"persistent-handle",
		"",
		"The persistent handle. Value must be in hex.")
)

func main() {
	flag.Parse()
	var errors []error
	evictControl(&errors)
	for _, err := range errors {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
	}
	if len(errors) > 0 {
		os.Exit(1)
	}
}

func evictControl(errors *[]error) {
	var objectHandle uint32
	if _, err := fmt.Sscanf(*objectHandleFlag, "%x", &objectHandle); err != nil {
		*errors = append(*errors, fmt.Errorf("invalid flag 'object-handle': %s", err))
		return
	}

	var persistentHandle uint32
	if _, err := fmt.Sscanf(*persistentHandleFlag, "%x", &persistentHandle); err != nil {
		*errors = append(*errors, fmt.Errorf("invalid flag 'persistent-handle': %s", err))
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

	err = tpm2.EvictControl(
		rwc, "" /*ownerAuth*/, tpm2.HandleOwner,
		tpmutil.Handle(objectHandle), tpmutil.Handle(persistentHandle))
	if err != nil {
		*errors = append(*errors, fmt.Errorf("Unable to evict object: %s\n", err))
	}
}

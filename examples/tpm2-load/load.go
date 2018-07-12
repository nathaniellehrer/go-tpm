// Copyright (c) 2018, Ian Haken. All rights reserved.
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

// Loads an object into the tpm.
// Outputs the handle of the object in hex.
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var (
	tpmPath = flag.String(
		"tpm-path",
		"/dev/tpm0",
		"Path to the TPM device (character device or a Unix socket).")
	parentHandleFlag = flag.String(
		"parent-handle",
		"",
		"The handle of the parent key. Value must be in hex.")
	parentPassword = flag.String(
		"parent-password",
		"",
		"The password of the parent.")
	privatePath = flag.String(
		"private-path",
		"",
		"The file path from which to read the private portion of the object.")
	publicPath = flag.String(
		"public-path",
		"",
		"The file path from which to read the public portion of the object.")
)

func main() {
	flag.Parse()
	var errors []error
	load(&errors)
	for err := range errors {
		fmt.Fprintf(os.Stderr, "%s\n", err)
	}
	if len(errors) > 0 {
		os.Exit(1)
	}
}

func load(errors *[]error) {
	flag.Parse()

	var parentHandle uint32
	if _, err := fmt.Sscanf(*parentHandleFlag, "%x", &parentHandle); err != nil {
		*errors = append(*errors, fmt.Errorf("invalid flag 'parent-handle': %s", err))
		return
	}

	inPrivate, err := ioutil.ReadFile(*privatePath)
	if err != nil {
		*errors = append(
			*errors, fmt.Errorf("Couldn't read from file %q: %s", *privatePath, err))
		return
	}

	inPublic, err := ioutil.ReadFile(*publicPath)
	if err != nil {
		*errors = append(
			*errors, fmt.Errorf("Couldn't read from file %q: %s", *publicPath, err))
		return
	}

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		*errors = append(*errors, fmt.Errorf("Can't open TPM at %q: %s", *tpmPath, err))
		return
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			*errors = append(
				*errors, fmt.Errorf("Unable to close connection to TPM: %s", err))
		}
	}()

	handle, _, err := tpm2.Load(
		rwc, tpmutil.Handle(parentHandle), *parentPassword, inPublic, inPrivate)
	if err != nil {
		*errors = append(*errors, fmt.Errorf("Unable to load data: %s", err))
		return
	}
	fmt.Fprintf(os.Stdout, "%x\n", handle)

}

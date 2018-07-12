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

// Unseals data that was sealed with a password and bound to a PCR.
// The unsealed (unencrypted) data is written out to the specified path.
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
	pcr = flag.Int(
		"pcr",
		-1,
		"Pcr to seal data to. Ignored if -1; otherwise, must be within [0, 23].")
	objectHandleFlag = flag.String(
		"object-handle",
		"",
		"The handle of the object key. Value must be in hex.")
	objectPassword = flag.String(
		"object-password",
		"",
		"The password of the object.")
	privatePath = flag.String(
		"private-path",
		"",
		"The file path to which to write the private portion of the object.")
)

func main() {
	flag.Parse()
	var errors []error
	unseal(&errors)
	for err := range errors {
		fmt.Fprintf(os.Stderr, "%s\n", err)
	}
	if len(errors) > 0 {
		os.Exit(1)
	}
}

func unseal(errors *[]error) {
	if *pcr < -1 || *pcr > 23 {
		*errors = append(*errors, fmt.Errorf("Invalid flag 'pcr': out of range"))
	}

	var objectHandle uint32
	if _, err := fmt.Sscanf(*objectHandleFlag, "%x", &objectHandle); err != nil {
		*errors = append(*errors, fmt.Errorf("invalid flag 'object-handle': %s", err))
		return
	}

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		*errors = append(*errors, fmt.Errorf("Can't open TPM %q: %s", *tpmPath, err))
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			*errors = append(
				*errors, fmt.Errorf("Unable to close connection to TPM: %s", err))
		}
	}()

	pcrSelection := tpm2.PCRSelection{}
	if *pcr != -1 {
		pcrSelection = tpm2.PCRSelection{
			Hash: tpm2.AlgSHA256,
			PCRs: []int{*pcr},
		}
	}

	// FYI, this is not a very secure session.
	sessHandle, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,                                        /*tpmKey*/
		tpm2.HandleNull,                                        /*bindKey*/
		[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, /*nonceCaller*/
		[]byte{}, /*secret*/
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		*errors = append(*errors, fmt.Errorf("Unable to start session: %s", err))
	}
	defer func() {
		if err := tpm2.FlushContext(rwc, sessHandle); err != nil {
			*errors = append(
				*errors, fmt.Errorf("Unable to flush session: %s", err))
		}
	}()

	err = tpm2.PolicyPCR(rwc, sessHandle, []byte{} /*expectedDigest*/, pcrSelection)
	if err != nil {
		*errors = append(*errors, fmt.Errorf("Unable to bind PCRs to auth policy: %s", err))
	}

	err = tpm2.PolicyPassword(rwc, sessHandle)
	if err != nil {
		*errors = append(
			*errors, fmt.Errorf("Unable to require password for auth policy: %s", err))
	}

	outPrivate, err := tpm2.UnsealWithSession(
		rwc, sessHandle, tpmutil.Handle(objectHandle), *objectPassword)
	if err != nil {
		*errors = append(*errors, fmt.Errorf("Unable to unseal data: %s", err))
	}

	err = ioutil.WriteFile(*privatePath, outPrivate, 0600)
	if err != nil {
		*errors = append(
			*errors, fmt.Errorf("Couldn't write to file %q: %s", *privatePath, err))
	}
}

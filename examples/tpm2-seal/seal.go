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

// Seals data under a parent, with a password, and bound to a PCR.
// The sealed (encrypted) data is written out to the specified path.
// To unseal the encrypted data, the parent must be loaded, the password given,
// and the PCR in the expected state.
package main

import (
	"encoding/hex"
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
	parentHandleFlag = flag.String(
		"parent-handle",
		"",
		"The handle of the parent key. Value must be in hex.")
	parentPassword = flag.String(
		"parent-password",
		"",
		"The password of the parent.")
	objectPassword = flag.String(
		"object-password",
		"",
		"The password of the object.")
	data = flag.String(
		"data",
		"",
		"The hex encoded bytes to seal. Must not exceed 128 bytes.")
	privatePath = flag.String(
		"private-path",
		"",
		"The file path to which to write the private portion of the object.")
	publicPath = flag.String(
		"public-path",
		"",
		"The file path to which to write the public portion of the object.")
)

func main() {
	flag.Parse()
	var errors []error
	seal(&errors)
	for _, err := range errors {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
	}
	if len(errors) > 0 {
		os.Exit(1)
	}
}

func seal(errors *[]error) {
	if *pcr < 0 || *pcr > 23 {
		*errors = append(*errors, fmt.Errorf("invalid flag 'pcr': out of range"))
		return
	}

	var parentHandle uint32
	if _, err := fmt.Sscanf(*parentHandleFlag, "%x", &parentHandle); err != nil {
		*errors = append(*errors, fmt.Errorf("invalid flag 'parent-handle': %s", err))
		return
	}

	dataBytes, err := hex.DecodeString(*data)
	if err != nil {
		*errors = append(*errors, fmt.Errorf("invalid flag 'data': %s", err))
		return
	}
	if len(dataBytes) > 128 {
		*errors = append(*errors, fmt.Errorf("invalid flag 'data': exceeds 128 bytes"))
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

	pcrSelection := tpm2.PCRSelection{
		Hash: tpm2.AlgSHA256,
		PCRs: []int{*pcr},
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
		*errors = append(*errors, fmt.Errorf("unable to start session: %s", err))
	}
	defer func() {
		if err := tpm2.FlushContext(rwc, sessHandle); err != nil {
			*errors = append(
				*errors, fmt.Errorf("unable to flush session: %s", err))
		}
	}()

	err = tpm2.PolicyPCR(rwc, sessHandle, []byte{} /*expectedDigest*/, pcrSelection)
	if err != nil {
		*errors = append(*errors, fmt.Errorf("unable to bind PCRs to auth policy: %s", err))
		return
	}

	err = tpm2.PolicyPassword(rwc, sessHandle)
	if err != nil {
		*errors = append(
			*errors, fmt.Errorf("unable to require password for auth policy: %s", err))
		return
	}

	objectAuthPolicy, err := tpm2.PolicyGetDigest(rwc, sessHandle)
	if err != nil {
		*errors = append(*errors, fmt.Errorf("unable to get policy digest: %s", err))
		return
	}

	outPrivate, outPublic, err := tpm2.Seal(
		rwc,
		tpmutil.Handle(parentHandle),
		*parentPassword,
		*objectPassword,
		objectAuthPolicy,
		dataBytes)
	if err != nil {
		*errors = append(*errors, fmt.Errorf("unable to seal data: %v", err))
		return
	}

	err = ioutil.WriteFile(*privatePath, outPrivate, 0600)
	if err != nil {
		*errors = append(
			*errors, fmt.Errorf("couldn't write to file %q: %s", *privatePath, err))
		return
	}

	err = ioutil.WriteFile(*publicPath, outPublic, 0600)
	if err != nil {
		*errors = append(
			*errors, fmt.Errorf("couldn't write to file %q: %s", *publicPath, err))
		return
	}
}

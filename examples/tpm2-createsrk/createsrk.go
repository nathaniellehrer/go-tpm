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

// Creates a storage root key and outputs its handle in hex.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/google/go-tpm/tpm2"
)

var (
	tpmPath = flag.String(
		"tpm-path",
		"/dev/tpm0",
		"Path to the TPM device (character device or a Unix socket).")

	// Default EK template defined in:
	// https://trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf
	// Shared SRK template based off of EK template and specified in:
	// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
	srkTemplate = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagDecrypt |
			tpm2.FlagNoDA,
		AuthPolicy: []byte{},
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:    2048,
			Exponent:   0,
			ModulusRaw: make([]byte, 256),
		},
	}
)

func main() {
	flag.Parse()
	var errors []error
	createsrk(&errors)
	for _, err := range errors {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
	}
	if len(errors) > 0 {
		os.Exit(1)
	}
}

func createsrk(errors *[]error) {
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

	objectHandle, _, err := tpm2.CreatePrimary(
		rwc, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", srkTemplate)
	if err != nil {
		*errors = append(*errors, fmt.Errorf("can't create primary key: %s", err))
		return
	}
	fmt.Fprintf(os.Stdout, "%x\n", objectHandle)
}

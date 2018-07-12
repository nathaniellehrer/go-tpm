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
//
// TODO(nlehrer): This package should be private but I'm not sure how to make that happen.
package util

import (
	"fmt"
	"os"
)

func ParseHex32Flag(flagName string, flag *string) (uint32, error) {
	var val uint32
	if *flag == "" {
		return 0, fmt.Errorf("Flag '%v' missing value.", flagName)
	}
	_, err := fmt.Sscanf(*flag, "%x", &val)
	if err != nil {
		return 0, fmt.Errorf("Can't parse flag '%v': %v", flagName, err)
	}
	return val, nil
}

func ExitWithErrorIf(cond bool, err error) {
	if cond {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

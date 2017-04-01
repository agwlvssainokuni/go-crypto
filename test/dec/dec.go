/*
 * Copyright 2017 agwlvssainokuni
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

package main

import (
	"io/ioutil"
	"os"

	"github.com/agwlvssainokuni/go-crypto/aescbc"
)

func main() {
	keyfile := os.Args[1]
	if key, err := ioutil.ReadFile(keyfile); err != nil {
		println(err.Error())
		return
	} else if dec, err := aescbc.NewAESCBCPKCS7ivDecrypter(key); err != nil {
		println(err.Error())
		return
	} else if src, err := ioutil.ReadAll(os.Stdin); err != nil {
		println(err.Error())
		return
	} else if dst, err := dec.Decrypt(src); err != nil {
		println(err.Error())
		return
	} else {
		os.Stdout.Write(dst)
	}
}

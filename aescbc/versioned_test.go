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

package aescbc

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewAESCBCPKCS7ivVer_1(t *testing.T) {
	numOfTrial := 5
	maxSize := 512

	wd, err := os.Getwd()
	if err != nil {
		t.Errorf("failed to os.Getwd() %s", err.Error())
		return
	}
	keydir := filepath.Join(wd, "test", "versioned_1-2")
	pwdfile := filepath.Join(keydir, "pwd.yaml")

	enc, err := NewAESCBCPKCS7ivVerEncrypter(keydir, pwdfile)
	if err != nil {
		t.Errorf("failed to create encrypter %s", err.Error())
		return
	}

	dec, err := NewAESCBCPKCS7ivVerDecrypter(keydir, pwdfile)
	if err != nil {
		t.Errorf("failed to create decrypter %s", err.Error())
		return
	}

	for i := 0; i < numOfTrial; i++ {
		for size := 0; size <= maxSize; size++ {
			encdeccompare(t, size, enc, dec)
		}
	}
}

func TestNewAESCBCPKCS7ivVer_2(t *testing.T) {
	numOfTrial := 5
	maxSize := 512

	wd, err := os.Getwd()
	if err != nil {
		t.Errorf("failed to os.Getwd() %s", err.Error())
		return
	}
	keydir := filepath.Join(wd, "test", "versioned_1-2")
	pwdfile := filepath.Join(keydir, "pwd.yaml")

	enc, dec, err := NewAESCBCPKCS7ivVerEncDec(keydir, pwdfile)
	if err != nil {
		t.Errorf("failed to create encrypter/decrypter %s", err.Error())
		return
	}

	for i := 0; i < numOfTrial; i++ {
		for size := 0; size <= maxSize; size++ {
			encdeccompare(t, size, enc, dec)
		}
	}
}

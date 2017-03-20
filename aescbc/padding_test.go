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
	"crypto/rand"
	"testing"
)

func TestPaddingByPKCS7(t *testing.T) {
	blockSize := 16
	maxLen := 1024
	for i := 1; i < maxLen; i++ {

		src := make([]byte, i)
		rand.Read(src)

		mid := addPaddingByPKCS7(blockSize, src)
		if len(mid)%16 != 0 {
			t.Errorf("Padded size is %d", len(mid))
		}
		for i, b := range src {
			if b != mid[i] {
				t.Errorf("Mid mismatch at %d, %x and %x", i, b, mid[i])
			}
		}

		dst, err := removePaddingByPKCS7(blockSize, mid)
		if err != nil {
			t.Errorf("Error %s", err.Error())
		}
		if len(src) != len(dst) {
			t.Errorf("Data size src %d and dst %d", len(src), len(dst))
		}
		for i, b := range src {
			if b != dst[i] {
				t.Errorf("Dst mismatch at %d, %x and %x", i, b, dst[i])
			}
		}
	}
}

func TestPaddingByPKCS7_ErrorCase(t *testing.T) {
	blockSize := 16
	maxLen := 256 - blockSize
	for i := 1; i < maxLen; i++ {

		src := make([]byte, i)
		rand.Read(src)

		mid := addPaddingByPKCS7(blockSize, src)

		for j := 1; j < blockSize; j++ {
			if _, err := removePaddingByPKCS7(blockSize, mid[:len(mid)-j]); err == nil {
				t.Errorf("Should fail")
			}
		}

		padSize := mid[len(mid)-1]
		mid[len(mid)-1] = byte(len(mid) + 1)
		if _, err := removePaddingByPKCS7(blockSize, mid); err == nil {
			t.Errorf("Should fail")
		}

		mid[len(mid)-1] = padSize
		mid[len(mid)-int(padSize)] = padSize + 1
		if _, err := removePaddingByPKCS7(blockSize, mid); err == nil {
			t.Errorf("Should fail")
		}
	}
}

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
	"crypto/aes"
	"crypto/rand"
	"testing"
)

func TestAESCBCPKCS7_1(t *testing.T) {
	numOfTrial := 5
	maxSize := 512

	for i := 0; i < numOfTrial; i++ {

		key := make([]byte, 16)
		if n, err := rand.Read(key); n != 16 || err != nil {
			t.Error("failed to create key")
			return
		}

		cipher, err := aes.NewCipher(key)
		if err != nil {
			t.Error("failed to create cipher")
			return
		}

		for size := 0; size <= maxSize; size++ {

			iv := make([]byte, 16)
			if n, err := rand.Read(iv); n != 16 || err != nil {
				t.Error("failed to create iv")
				return
			}

			enc := NewCBCPKCS7Encrypter(cipher, iv)
			dec := NewCBCPKCS7Decrypter(cipher, iv)

			encdeccompare(t, size, enc, dec)
		}
	}
}

func TestAESCBCPKCS7_2(t *testing.T) {
	numOfTrial := 5
	maxSize := 512

	for i := 0; i < numOfTrial; i++ {

		key := make([]byte, 16)
		if n, err := rand.Read(key); n != 16 || err != nil {
			t.Error("failed to create key")
			return
		}

		for size := 0; size <= maxSize; size++ {

			iv := make([]byte, 16)
			if n, err := rand.Read(iv); n != 16 || err != nil {
				t.Error("failed to create iv")
				return
			}

			enc, err := NewAESCBCPKCS7Encrypter(key, iv)
			if err != nil {
				t.Error("failed to create encrypter")
				return
			}
			dec, err := NewAESCBCPKCS7Decrypter(key, iv)
			if err != nil {
				t.Error("failed to create decrypter")
				return
			}

			encdeccompare(t, size, enc, dec)
		}
	}
}

func TestAESCBCPKCS7_3(t *testing.T) {
	numOfTrial := 5
	maxSize := 512

	for i := 0; i < numOfTrial; i++ {

		key := make([]byte, 16)
		if n, err := rand.Read(key); n != 16 || err != nil {
			t.Error("failed to create key")
			return
		}

		for size := 0; size <= maxSize; size++ {

			iv := make([]byte, 16)
			if n, err := rand.Read(iv); n != 16 || err != nil {
				t.Error("failed to create iv")
				return
			}

			enc, dec, err := NewAESCBCPKCS7EncDec(key, iv)
			if err != nil {
				t.Error("failed to create encrypter")
				return
			}

			encdeccompare(t, size, enc, dec)
		}
	}
}

func TestAESCBCPKCS7_ErrorCase(t *testing.T) {
	numOfTrial := 5

	for i := 0; i < numOfTrial; i++ {

		key15 := make([]byte, 15)
		if n, err := rand.Read(key15); n != 15 || err != nil {
			t.Error("failed to create key15")
			return
		}
		key17 := make([]byte, 17)
		if n, err := rand.Read(key17); n != 17 || err != nil {
			t.Error("failed to create key17")
			return
		}
		iv := make([]byte, 16)
		if n, err := rand.Read(iv); n != 16 || err != nil {
			t.Error("failed to create iv")
			return
		}

		if _, err := NewAESCBCPKCS7Encrypter(key15, iv); err == nil {
			t.Error("Should fail")
			return
		}
		if _, err := NewAESCBCPKCS7Decrypter(key15, iv); err == nil {
			t.Error("Should fail")
			return
		}
		if _, _, err := NewAESCBCPKCS7EncDec(key15, iv); err == nil {
			t.Error("Should fail")
			return
		}

		if _, err := NewAESCBCPKCS7Encrypter(key17, iv); err == nil {
			t.Error("Should fail")
			return
		}
		if _, err := NewAESCBCPKCS7Decrypter(key17, iv); err == nil {
			t.Error("Should fail")
			return
		}
		if _, _, err := NewAESCBCPKCS7EncDec(key17, iv); err == nil {
			t.Error("Should fail")
			return
		}
	}
}

func TestAESCBCPKCS7iv_1(t *testing.T) {
	numOfTrial := 5
	maxSize := 512

	for i := 0; i < numOfTrial; i++ {

		key := make([]byte, 16)
		if n, err := rand.Read(key); n != 16 || err != nil {
			t.Error("failed to create key")
			return
		}

		cipher, err := aes.NewCipher(key)
		if err != nil {
			t.Error("failed to create cipher")
			return
		}

		for size := 0; size <= maxSize; size++ {

			enc := NewCBCPKCS7ivEncrypter(cipher)
			dec := NewCBCPKCS7ivDecrypter(cipher)

			encdeccompare(t, size, enc, dec)
		}
	}
}

func TestAESCBCPKCS7iv_2(t *testing.T) {
	numOfTrial := 5
	maxSize := 512

	for i := 0; i < numOfTrial; i++ {

		key := make([]byte, 16)
		if n, err := rand.Read(key); n != 16 || err != nil {
			t.Error("failed to create key")
			return
		}

		enc, err := NewAESCBCPKCS7ivEncrypter(key)
		if err != nil {
			t.Error("failed to create encrypter")
			return
		}
		dec, err := NewAESCBCPKCS7ivDecrypter(key)
		if err != nil {
			t.Error("failed to create decrypter")
			return
		}

		for size := 0; size <= maxSize; size++ {
			encdeccompare(t, size, enc, dec)
		}
	}
}

func TestAESCBCPKCS7iv_3(t *testing.T) {
	numOfTrial := 5
	maxSize := 512

	for i := 0; i < numOfTrial; i++ {

		key := make([]byte, 16)
		if n, err := rand.Read(key); n != 16 || err != nil {
			t.Error("failed to create key")
			return
		}

		enc, dec, err := NewAESCBCPKCS7ivEncDec(key)
		if err != nil {
			t.Error("failed to create encrypter")
			return
		}

		for size := 0; size <= maxSize; size++ {
			encdeccompare(t, size, enc, dec)
		}
	}
}

func TestAESCBCPKCS7iv_ErrorCase(t *testing.T) {
	numOfTrial := 5

	for i := 0; i < numOfTrial; i++ {

		key15 := make([]byte, 15)
		if n, err := rand.Read(key15); n != 15 || err != nil {
			t.Error("failed to create key15")
			return
		}
		key17 := make([]byte, 17)
		if n, err := rand.Read(key17); n != 17 || err != nil {
			t.Error("failed to create key17")
			return
		}
		iv := make([]byte, 16)
		if n, err := rand.Read(iv); n != 16 || err != nil {
			t.Error("failed to create iv")
			return
		}

		if _, err := NewAESCBCPKCS7ivEncrypter(key15); err == nil {
			t.Error("Should fail")
			return
		}
		if _, err := NewAESCBCPKCS7ivDecrypter(key15); err == nil {
			t.Error("Should fail")
			return
		}
		if _, _, err := NewAESCBCPKCS7ivEncDec(key15); err == nil {
			t.Error("Should fail")
			return
		}

		if _, err := NewAESCBCPKCS7ivEncrypter(key17); err == nil {
			t.Error("Should fail")
			return
		}
		if _, err := NewAESCBCPKCS7ivDecrypter(key17); err == nil {
			t.Error("Should fail")
			return
		}
		if _, _, err := NewAESCBCPKCS7ivEncDec(key17); err == nil {
			t.Error("Should fail")
			return
		}
	}
}

func encdeccompare(t *testing.T, size int, enc Encrypter, dec Decrypter) bool {

	src := make([]byte, size)
	if n, err := rand.Read(src); n != size || err != nil {
		t.Error("failed to create source data")
		return false
	}
	c := enc.Encrypt(src)
	dst, err := dec.Decrypt(c)
	if err != nil {
		t.Error("failed to decrypt")
		return false
	}

	if len(src) != len(dst) {
		t.Error("size mismatch")
		return false
	}

	for i, b := range src {
		if b != dst[i] {
			t.Error("data mismatch at %d", i)
			return false
		}
	}

	return true
}

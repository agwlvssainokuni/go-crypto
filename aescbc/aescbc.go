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
	"crypto/cipher"
	"crypto/rand"
)

type Encrypter interface {
	Encrypt(src []byte) []byte
	doEncrypt(dst, src []byte)
	calcDstSizeToEnc(src []byte) int
}

type Decrypter interface {
	Decrypt(src []byte) ([]byte, error)
	doDecrypt(dst, src []byte) (int, error)
	calcDstSizeToDec(src []byte) int
}

type cbcpkcs7 struct {
	bm cipher.BlockMode
}

type cbcpkcs7iv struct {
	b cipher.Block
}

func encryptMain(x Encrypter, src []byte) []byte {
	dst := make([]byte, x.calcDstSizeToEnc(src))
	x.doEncrypt(dst, src)
	return dst
}

func decryptMain(x Decrypter, src []byte) ([]byte, error) {
	dst := make([]byte, x.calcDstSizeToDec(src))
	if dstSize, err := x.doDecrypt(dst, src); err != nil {
		return nil, err
	} else {
		return dst[:dstSize], nil
	}
}

func (x *cbcpkcs7) Encrypt(src []byte) []byte {
	return encryptMain(x, src)
}

func (x *cbcpkcs7) doEncrypt(dst, src []byte) {
	fillPaddingByPKCS7(x.bm.BlockSize(), dst, src)
	x.bm.CryptBlocks(dst, dst)
}

func (x *cbcpkcs7) calcDstSizeToEnc(src []byte) int {
	return calcDstSizeForPaddingByPKCS7(x.bm.BlockSize(), src)
}

func (x *cbcpkcs7) Decrypt(src []byte) ([]byte, error) {
	return decryptMain(x, src)
}

func (x *cbcpkcs7) doDecrypt(dst, src []byte) (int, error) {
	x.bm.CryptBlocks(dst, src)
	return verifyPaddingByPKCS7(x.bm.BlockSize(), dst)
}

func (x *cbcpkcs7) calcDstSizeToDec(src []byte) int {
	return len(src)
}

func (x *cbcpkcs7iv) Encrypt(src []byte) []byte {
	return encryptMain(x, src)
}

func (x *cbcpkcs7iv) doEncrypt(dst, src []byte) {
	if n, err := rand.Read(dst[:x.b.BlockSize()]); n != x.b.BlockSize() || err != nil {
		panic("failed to generate IV")
	}
	fillPaddingByPKCS7(x.b.BlockSize(), dst[x.b.BlockSize():], src)
	bm := cipher.NewCBCEncrypter(x.b, dst[:x.b.BlockSize()])
	bm.CryptBlocks(dst[x.b.BlockSize():], dst[x.b.BlockSize():])
}

func (x *cbcpkcs7iv) calcDstSizeToEnc(src []byte) int {
	return calcDstSizeForPaddingByPKCS7(x.b.BlockSize(), src) + x.b.BlockSize()
}

func (x *cbcpkcs7iv) Decrypt(src []byte) ([]byte, error) {
	return decryptMain(x, src)
}

func (x *cbcpkcs7iv) doDecrypt(dst, src []byte) (int, error) {
	bm := cipher.NewCBCDecrypter(x.b, src[:x.b.BlockSize()])
	bm.CryptBlocks(dst, src[x.b.BlockSize():])
	return verifyPaddingByPKCS7(x.b.BlockSize(), dst)
}

func (x *cbcpkcs7iv) calcDstSizeToDec(src []byte) int {
	return len(src) - x.b.BlockSize()
}

func NewCBCPKCS7Encrypter(b cipher.Block, iv []byte) Encrypter {
	return &cbcpkcs7{cipher.NewCBCEncrypter(b, iv)}
}

func NewCBCPKCS7Decrypter(b cipher.Block, iv []byte) Decrypter {
	return &cbcpkcs7{cipher.NewCBCDecrypter(b, iv)}
}

func NewAESCBCPKCS7Encrypter(key, iv []byte) (Encrypter, error) {
	if b, err := aes.NewCipher(key); err != nil {
		return nil, err
	} else {
		return &cbcpkcs7{cipher.NewCBCEncrypter(b, iv)}, nil
	}
}

func NewAESCBCPKCS7Decrypter(key, iv []byte) (Decrypter, error) {
	if b, err := aes.NewCipher(key); err != nil {
		return nil, err
	} else {
		return &cbcpkcs7{cipher.NewCBCDecrypter(b, iv)}, nil
	}
}

func NewAESCBCPKCS7EncDec(key, iv []byte) (Encrypter, Decrypter, error) {
	if b, err := aes.NewCipher(key); err != nil {
		return nil, nil, err
	} else {
		return &cbcpkcs7{cipher.NewCBCEncrypter(b, iv)}, &cbcpkcs7{cipher.NewCBCDecrypter(b, iv)}, nil
	}
}

func NewCBCPKCS7ivEncrypter(b cipher.Block) Encrypter {
	return &cbcpkcs7iv{b}
}

func NewCBCPKCS7ivDecrypter(b cipher.Block) Decrypter {
	return &cbcpkcs7iv{b}
}

func NewAESCBCPKCS7ivEncrypter(key []byte) (Encrypter, error) {
	if b, err := aes.NewCipher(key); err != nil {
		return nil, err
	} else {
		return &cbcpkcs7iv{b}, nil
	}
}

func NewAESCBCPKCS7ivDecrypter(key []byte) (Decrypter, error) {
	if b, err := aes.NewCipher(key); err != nil {
		return nil, err
	} else {
		return &cbcpkcs7iv{b}, nil
	}
}

func NewAESCBCPKCS7ivEncDec(key []byte) (Encrypter, Decrypter, error) {
	if b, err := aes.NewCipher(key); err != nil {
		return nil, nil, err
	} else {
		return &cbcpkcs7iv{b}, &cbcpkcs7iv{b}, nil
	}
}

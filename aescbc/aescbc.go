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
}

type Decrypter interface {
	Decrypt(src []byte) ([]byte, error)
}

type cbcpkcs7 struct {
	bm cipher.BlockMode
}

type cbcpkcs7iv struct {
	b cipher.Block
}

func (x *cbcpkcs7) Encrypt(src []byte) []byte {
	dst := addPaddingByPKCS7(x.bm.BlockSize(), src)
	x.bm.CryptBlocks(dst, dst)
	return dst
}

func (x *cbcpkcs7) Decrypt(src []byte) ([]byte, error) {
	dst := make([]byte, len(src))
	x.bm.CryptBlocks(dst, src)
	return removePaddingByPKCS7(x.bm.BlockSize(), dst)
}

func (x *cbcpkcs7iv) Encrypt(src []byte) []byte {
	padded := addPaddingByPKCS7(x.b.BlockSize(), src)
	dst := make([]byte, len(padded)+x.b.BlockSize())
	if n, err := rand.Read(dst[:x.b.BlockSize()]); n != x.b.BlockSize() || err != nil {
		panic("failed to generate IV")
	}
	bm := cipher.NewCBCEncrypter(x.b, dst[:x.b.BlockSize()])
	bm.CryptBlocks(dst[x.b.BlockSize():], padded)
	return dst
}

func (x *cbcpkcs7iv) Decrypt(src []byte) ([]byte, error) {
	padded := make([]byte, len(src)-x.b.BlockSize())
	bm := cipher.NewCBCDecrypter(x.b, src[:x.b.BlockSize()])
	bm.CryptBlocks(padded, src[x.b.BlockSize():])
	return removePaddingByPKCS7(x.b.BlockSize(), padded)
}

func NewPKCS7Encrypter(bm cipher.BlockMode) Encrypter {
	return &cbcpkcs7{bm}
}

func NewPKCS7Decrypter(bm cipher.BlockMode) Decrypter {
	return &cbcpkcs7{bm}
}

func NewCBCPKCS7Encrypter(b cipher.Block, iv []byte) Encrypter {
	return NewPKCS7Encrypter(cipher.NewCBCEncrypter(b, iv))
}

func NewCBCPKCS7Decrypter(b cipher.Block, iv []byte) Decrypter {
	return NewPKCS7Decrypter(cipher.NewCBCDecrypter(b, iv))
}

func NewAESCBCPKCS7Encrypter(key, iv []byte) (Encrypter, error) {
	if b, err := aes.NewCipher(key); err != nil {
		return nil, err
	} else {
		return NewCBCPKCS7Encrypter(b, iv), nil
	}
}

func NewAESCBCPKCS7Decrypter(key, iv []byte) (Decrypter, error) {
	if b, err := aes.NewCipher(key); err != nil {
		return nil, err
	} else {
		return NewCBCPKCS7Decrypter(b, iv), nil
	}
}

func NewAESCBCPKCS7EncDec(key, iv []byte) (Encrypter, Decrypter, error) {
	if b, err := aes.NewCipher(key); err != nil {
		return nil, nil, err
	} else {
		return NewCBCPKCS7Encrypter(b, iv), NewCBCPKCS7Decrypter(b, iv), nil
	}
}

func NewCBCPKCS7IVEncrypter(b cipher.Block) Encrypter {
	return &cbcpkcs7iv{b}
}

func NewCBCPKCS7IVDecrypter(b cipher.Block) Decrypter {
	return &cbcpkcs7iv{b}
}

func NewAESCBCPKCS7IVEncrypter(key []byte) (Encrypter, error) {
	if b, err := aes.NewCipher(key); err != nil {
		return nil, err
	} else {
		return NewCBCPKCS7IVEncrypter(b), nil
	}
}

func NewAESCBCPKCS7IVDecrypter(key []byte) (Decrypter, error) {
	if b, err := aes.NewCipher(key); err != nil {
		return nil, err
	} else {
		return NewCBCPKCS7IVDecrypter(b), nil
	}
}

func NewAESCBCPKCS7IVEncDec(key []byte) (Encrypter, Decrypter, error) {
	if b, err := aes.NewCipher(key); err != nil {
		return nil, nil, err
	} else {
		return NewCBCPKCS7IVEncrypter(b), NewCBCPKCS7IVDecrypter(b), nil
	}
}

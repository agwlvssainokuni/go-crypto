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
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"io"
	"io/ioutil"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/go-yaml/yaml"
)

var (
	KeyVersion      = uint32(0)
	PrivkeyFilename = "privkey.pem"
	AeskeyFilename  = "key.bin"
)

type versioned struct {
	encdec map[uint32]*cbcpkcs7iv
}

func (x *versioned) Encrypt(src []byte) []byte {
	return encryptMain(x, src)
}

func (x *versioned) doEncrypt(dst, src []byte) {
	binary.BigEndian.PutUint32(dst[:4], KeyVersion)
	x.encdec[KeyVersion].doEncrypt(dst[4:], src)
}

func (x *versioned) calcDstSizeToEnc(src []byte) int {
	return x.encdec[KeyVersion].calcDstSizeToEnc(src) + 4
}

func (x *versioned) Decrypt(src []byte) ([]byte, error) {
	return decryptMain(x, src)
}

func (x *versioned) doDecrypt(dst, src []byte) (int, error) {
	version := binary.BigEndian.Uint32(src[:4])
	return x.encdec[version].doDecrypt(dst, src[4:])
}

func (x *versioned) calcDstSizeToDec(src []byte) int {
	version := binary.BigEndian.Uint32(src[:4])
	return x.encdec[version].calcDstSizeToDec(src[4:])
}

func NewAESCBCPKCS7ivVerEncrypter(topdir, pwdfile string) (Encrypter, error) {
	if encdec, err := loadCryptoMap(topdir, pwdfile); err != nil {
		return nil, err
	} else {
		return &versioned{encdec}, nil
	}
}

func NewAESCBCPKCS7ivVerDecrypter(topdir, pwdfile string) (Decrypter, error) {
	if encdec, err := loadCryptoMap(topdir, pwdfile); err != nil {
		return nil, err
	} else {
		return &versioned{encdec}, nil
	}
}

func NewAESCBCPKCS7ivVerEncDec(topdir, pwdfile string) (Encrypter, Decrypter, error) {
	if encdec, err := loadCryptoMap(topdir, pwdfile); err != nil {
		return nil, nil, err
	} else {
		return &versioned{encdec}, &versioned{encdec}, nil
	}
}

func loadCryptoMap(topdir, pwdfile string) (map[uint32]*cbcpkcs7iv, error) {
	if keymap, err := loadAesKeyMap(topdir, pwdfile); err != nil {
		return nil, err
	} else {
		encdec := make(map[uint32]*cbcpkcs7iv)
		for vr, key := range keymap {
			if b, err := aes.NewCipher(key); err != nil {
				return nil, err
			} else {
				encdec[vr] = &cbcpkcs7iv{b}
			}
		}
		return encdec, nil
	}
}

func loadAesKeyMap(topdir, pwdfile string) (map[uint32][]byte, error) {
	if pwdmap, err := loadPasswdMap(pwdfile); err != nil {
		return nil, err
	} else {
		rng := rand.Reader
		aeskeymap := make(map[uint32][]byte)
		for vr, pw := range pwdmap {
			basedir := filepath.Join(topdir, strconv.FormatUint(uint64(vr), 10))
			if prvkey, err := loadPrivateKey(filepath.Join(basedir, PrivkeyFilename), pw); err != nil {
				return nil, err
			} else if aeskey, err := loadAesKey(filepath.Join(basedir, AeskeyFilename), prvkey, rng); err != nil {
				return nil, err
			} else {
				aeskeymap[vr] = aeskey
			}
		}
		return aeskeymap, nil
	}
}

func loadPasswdMap(pwdfile string) (map[uint32]string, error) {

	if data, err := ioutil.ReadFile(pwdfile); err != nil {
		return nil, err
	} else {

		var pwdmap map[uint32]string
		if strings.HasSuffix(pwdfile, ".json") {
			err = json.Unmarshal(data, &pwdmap)
			if err != nil {
				return nil, err
			}
		} else {
			err = yaml.Unmarshal(data, &pwdmap)
			if err != nil {
				return nil, err
			}
		}

		return pwdmap, nil
	}
}

func loadPrivateKey(prvkeyfile, passwd string) (*rsa.PrivateKey, error) {

	data, err := ioutil.ReadFile(prvkeyfile)
	if err != nil {
		return nil, err
	}

	var der []byte
	if blk, _ := pem.Decode(data); blk == nil {
		return nil, err
	} else if x509.IsEncryptedPEMBlock(blk) {
		der, err = x509.DecryptPEMBlock(blk, []byte(passwd))
		if err != nil {
			return nil, err
		}
	} else {
		der = blk.Bytes
	}

	prvkey, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return nil, err
	}

	return prvkey, nil
}

func loadAesKey(aeskeyfile string, prvkey *rsa.PrivateKey, rng io.Reader) ([]byte, error) {

	data, err := ioutil.ReadFile(aeskeyfile)
	if err != nil {
		return nil, err
	}

	aeskey, err := rsa.DecryptPKCS1v15(rng, prvkey, data)
	if err != nil {
		return nil, err
	}

	return aeskey, nil
}

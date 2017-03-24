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

type versionedEncrypter struct {
	encrypterMap map[uint32]Encrypter
}

type versionedDecrypter struct {
	decrypterMap map[uint32]Decrypter
}

func (km *versionedEncrypter) Encrypt(src []byte) []byte {
	b := km.encrypterMap[KeyVersion].Encrypt(src)
	dst := make([]byte, len(b)+4)
	binary.BigEndian.PutUint32(dst[:4], KeyVersion)
	copy(dst[4:], b)
	return dst
}

func (km *versionedDecrypter) Decrypt(src []byte) ([]byte, error) {
	return km.decrypterMap[binary.BigEndian.Uint32(src[:4])].Decrypt(src[4:])
}

func NewAESCBCPKCS7ivVerEncrypter(topdir string, passwdFile string) (Encrypter, error) {
	if pwdmap, err := loadPasswdMap(passwdFile); err != nil {
		return nil, err
	} else if keymap, err := loadKeyMap(topdir, pwdmap); err != nil {
		return nil, err
	} else {
		encMap := make(map[uint32]Encrypter)
		for vr, key := range keymap {
			if b, err := aes.NewCipher(key); err != nil {
				return nil, err
			} else {
				encMap[vr] = NewCBCPKCS7ivEncrypter(b)
			}
		}
		return &versionedEncrypter{encMap}, nil
	}
}

func NewAESCBCPKCS7ivVerDecrypter(topdir string, passwdFile string) (Decrypter, error) {
	if pwdmap, err := loadPasswdMap(passwdFile); err != nil {
		return nil, err
	} else if keymap, err := loadKeyMap(topdir, pwdmap); err != nil {
		return nil, err
	} else {
		decMap := make(map[uint32]Decrypter)
		for vr, key := range keymap {
			if b, err := aes.NewCipher(key); err != nil {
				return nil, err
			} else {
				decMap[vr] = NewCBCPKCS7ivDecrypter(b)
			}
		}
		return &versionedDecrypter{decMap}, nil
	}
}

func NewAESCBCPKCS7ivVerEncDec(topdir string, passwdFile string) (Encrypter, Decrypter, error) {
	if pwdmap, err := loadPasswdMap(passwdFile); err != nil {
		return nil, nil, err
	} else if keymap, err := loadKeyMap(topdir, pwdmap); err != nil {
		return nil, nil, err
	} else {
		encMap := make(map[uint32]Encrypter)
		decMap := make(map[uint32]Decrypter)
		for vr, key := range keymap {
			if b, err := aes.NewCipher(key); err != nil {
				return nil, nil, err
			} else {
				encMap[vr] = NewCBCPKCS7ivEncrypter(b)
				decMap[vr] = NewCBCPKCS7ivDecrypter(b)
			}
		}
		return &versionedEncrypter{encMap}, &versionedDecrypter{decMap}, nil
	}
}

func loadPasswdMap(file string) (map[uint32]string, error) {

	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	var passwd map[uint32]string
	if strings.HasSuffix(file, ".json") {
		err = json.Unmarshal(data, &passwd)
		if err != nil {
			return nil, err
		}
	} else {
		err = yaml.Unmarshal(data, &passwd)
		if err != nil {
			return nil, err
		}
	}

	return passwd, nil
}

func loadKeyMap(topdir string, passwd map[uint32]string) (map[uint32][]byte, error) {

	rng := rand.Reader
	keymap := make(map[uint32][]byte)
	for vr, pw := range passwd {

		basedir := filepath.Join(topdir, strconv.FormatUint(uint64(vr), 10))

		privkey, err := loadPrivateKey(filepath.Join(basedir, PrivkeyFilename), pw)
		if err != nil {
			return nil, err
		}

		data, err := ioutil.ReadFile(filepath.Join(basedir, AeskeyFilename))
		if err != nil {
			return nil, err
		}

		key, err := rsa.DecryptPKCS1v15(rng, privkey, data)
		if err != nil {
			return nil, err
		}

		keymap[vr] = key
	}

	return keymap, nil
}

func loadPrivateKey(file string, passwd string) (*rsa.PrivateKey, error) {

	data, err := ioutil.ReadFile(file)
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

	privkey, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return nil, err
	}

	return privkey, nil
}

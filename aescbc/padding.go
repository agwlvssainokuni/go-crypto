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
	"fmt"
)

func addPaddingByPKCS7(blockSize int, src []byte) []byte {
	dstSize := (len(src)/blockSize + 1) * blockSize
	padSize := dstSize - len(src)
	dst := make([]byte, dstSize)
	copy(dst, src)
	for i := len(src); i < len(dst); i++ {
		dst[i] = byte(padSize)
	}
	return dst
}

func removePaddingByPKCS7(blockSize int, src []byte) ([]byte, error) {
	if len(src)%blockSize != 0 {
		return nil, fmt.Errorf("Invalid data size %d for blockSize %d", len(src), blockSize)
	}
	padSize := int(src[len(src)-1])
	if len(src) < padSize {
		return nil, fmt.Errorf("Invalid padding 0x%x for data size %d", padSize, len(src))
	}
	dstSize := len(src) - padSize
	for i, b := range src[dstSize:] {
		if b != byte(padSize) {
			return nil, fmt.Errorf("Invalid padding 0x%x (at %dth)", b, i)
		}
	}
	return src[:dstSize], nil
}

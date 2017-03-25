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
	dst := make([]byte, calcDstSizeForPaddingByPKCS7(blockSize, src))
	fillPaddingByPKCS7(blockSize, dst, src)
	return dst
}

func fillPaddingByPKCS7(blockSize int, dst, src []byte) {
	copy(dst, src)
	padding := byte(len(dst) - len(src))
	for i := len(src); i < len(dst); i++ {
		dst[i] = padding
	}
}

func calcDstSizeForPaddingByPKCS7(blockSize int, src []byte) int {
	return (len(src)/blockSize + 1) * blockSize
}

func removePaddingByPKCS7(blockSize int, src []byte) ([]byte, error) {
	if dstSize, err := verifyPaddingByPKCS7(blockSize, src); err != nil {
		return nil, err
	} else {
		return src[:dstSize], nil
	}
}

func verifyPaddingByPKCS7(blockSize int, src []byte) (int, error) {
	if len(src)%blockSize != 0 {
		return -1, fmt.Errorf("Invalid data size %d for blockSize %d", len(src), blockSize)
	}
	padding := src[len(src)-1]
	if len(src) < int(padding) {
		return -1, fmt.Errorf("Invalid padding 0x%x for data size %d", padding, len(src))
	}
	dstSize := len(src) - int(padding)
	for i, b := range src[dstSize:] {
		if b != padding {
			return -1, fmt.Errorf("Invalid padding 0x%x (at %dth)", b, i)
		}
	}
	return dstSize, nil
}

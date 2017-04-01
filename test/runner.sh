#!/bin/bash
#
# Copyright 2017 agwlvssainokuni
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

basedir=$(cd $(dirname ${BASH_SOURCE[0]}); pwd)

num_of_trial=1
max_size=256

# (0) ビルドする。
cd ${basedir}
pushd dec; go build -o cmd; popd
pushd enc; go build -o cmd; popd

# (1) OpenSSLで暗号化しGoで復号する。
for ((i=0; i < ${num_of_trial}; i++))
do
    openssl rand 16 -out key.bin
    key=$(od -t x1 -v key.bin | head -1 | tail -c +12 | sed -e 's/ //g;')
    for ((size=0; size <= ${max_size}; size++))
    do
        # 元電文を形成する。
        openssl rand ${size} -out src.bin
        # OpenSSL暗号化に向けIVを形成する。
        openssl rand 16 -out mid.bin
        iv=$(od -t x1 -v mid.bin | head -1 | tail -c +12 | sed -e 's/ //g;')
        # OpenSSLで暗号化する。電文形式は「IV(16B)+暗号文」。
        cat src.bin | openssl aes-128-cbc -e -K ${key} -iv ${iv} >> mid.bin
        # Goで復号する。
        ./dec/cmd key.bin < mid.bin > dst.bin
        # 元電文と復号電文を比較する。
        diff -u <(od -t x1 -v src.bin) <(od -t x1 -v dst.bin)
    done
done

# (2) Goで暗号化しOpenSSLで復号する。
for ((i=0; i < ${num_of_trial}; i++))
do
    openssl rand 16 -out key.bin
    key=$(od -t x1 -v key.bin | head -1 | tail -c +12 | sed -e 's/ //g;')
    for ((size=0; size <= ${max_size}; size++))
    do
        # 元電文を形成する。
        openssl rand ${size} -out src.bin
        # Goで暗号化する。電文形式は「IV(16B)+暗号文」。
        ./enc/cmd key.bin < src.bin > mid.bin
        # OpenSSL復号に向けIVを抽出する。(先頭16B)
        iv=$(head -c +16 mid.bin | od -t x1 -v | head -1 | tail -c +12 | sed -e 's/ //g;')
        # OpenSSLで復号する。(先頭のIVの次から)
        tail -c +17 mid.bin | openssl aes-128-cbc -d -K ${key} -iv ${iv} -out dst.bin
        # 元電文と復号電文を比較する。
        diff -u <(od -t x1 -v src.bin) <(od -t x1 -v dst.bin)
    done
done

# (3) 後片付けする。
rm -f dec/cmd enc/cmd key.bin src.bin mid.bin dst.bin

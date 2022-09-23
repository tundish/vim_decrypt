#!/usr/bin/env python3
# encoding: utf-8

# Tool for decrypting vim (blowfish2) encrypted files.
# Copyright (C) 2020 Gertjan van Zwieten

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

import getpass
import hashlib
import operator
import struct
import sys


def blowfish(key):
    try:
        from Crypto.Cipher import Blowfish
    except ImportError:
        try:
            from Cryptodome.Cipher import Blowfish
        except ImportError:
            try:
                import blowfish
            except ImportError:
                raise Exception("failed to import cryptographic module")
            return blowfish.Cipher(key, byte_order="little").encrypt_block
    bf = Blowfish.new(key, mode=Blowfish.MODE_ECB)
    swapendian = lambda data: struct.pack("<2L", *struct.unpack(">2L", data))
    return lambda data: swapendian(bf.encrypt(swapendian(data)))


def decrypt(f, pw=None, encoding="utf8"):
    if isinstance(f, str):
        with open(f, "rb") as f:
            return decrypt(f, pw, encoding)
    if f.read(12) != b"VimCrypt~03!":
        raise Exception("not a blowfish2-encoded vimcrypt file")
    salt = f.read(8)
    if pw is None:
        pw = getpass.getpass()
    for i in range(1000):
        pw = hashlib.sha256(pw.encode() + salt).hexdigest()
    cipher = blowfish(hashlib.sha256(pw.encode() + salt).digest())
    block0 = f.read(8)
    block1 = f.read(8)
    decrypted = bytearray()
    while block1:
        decrypted.extend(map(operator.xor, cipher(block0), block1))
        block0 = block1
        block1 = f.read(8)
    return decrypted.decode(encoding)


def run():
    if len(sys.argv) > 2:
        sys.exit("usage: vimdecrypt [path]")

    print(vimdecrypt.decrypt(sys.argv[1] if len(sys.argv) == 2 else sys.stdin.buffer))


if __name__ == "__main__":
    run()

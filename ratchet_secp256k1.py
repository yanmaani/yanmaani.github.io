#!/usr/bin/env python3
import ecdsa
import hmac
import sys

# Copyright (C) 2021 by yanmaani <yanmaani@cock.li>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

H = 2**31

def point(p, curve=ecdsa.SECP256k1):
    return p * curve.generator

def ser_32(i):
    return i.to_bytes(4, byteorder='big')

def ser_256(p):
    return p.to_bytes(32, byteorder='big')

def ser_P(P, curve=ecdsa.SECP256k1):
    return ecdsa.VerifyingKey.from_public_point(P, curve).to_string("compressed")

def parse_256(p):
    return int.from_bytes(p, byteorder='big')

def CKDpriv(k_par, c_par, i):
    n = ecdsa.SECP256k1.order
    h = hmac.HMAC(key=c_par, digestmod='sha512')
    if i >= 2**31:
        h.update(b'\x00' + ser_256(k_par) + ser_32(i))
    else:
        h.update(ser_P(point(k_par)) + ser_32(i))
    I = h.digest()
    I_L = I[:32]
    I_R = I[32:]
    k_i = (parse_256(I_L) + k_par) % n
    c_i = I_R
    if parse_256(I_L) >= n or k_i == 0:
        return CKDpriv(k_par, c_par, i+1)
    return k_i, c_i

def CKDpub(K_par, c_par, i):
    n = ecdsa.SECP256k1.order
    h = hmac.HMAC(key=c_par, digestmod='sha512')
    if i >= 2**31:
        raise Exception('cannot derive')
    else:
        h.update(ser_P(K_par) + ser_32(i))
    I = h.digest()
    I_L = I[:32]
    I_R = I[32:]
    K_i = point(parse_256(I_L)) + K_par
    c_i = I_R
    if parse_256(I_L) >= n or K_i == ecdsa.ellipticcurve.INFINITY:
        return CKDpub(K_par, c_par, i+1)
    return K_i, c_i

def master(S):
    n = ecdsa.SECP256k1.order
    h = hmac.HMAC(key=b'Bitcoin seed', digestmod='sha512')
    h.update(bytes.fromhex(S))
    I = h.digest()
    I_L = I[:32]
    I_R = I[32:]
    k_master = parse_256(I_L)
    c_master = I_R
    if parse_256(I_L) == 0 or parse_256(I_L) >= n:
        raise Exception('Invalid seed')
    return k_master, c_master

def test():
    seed_hex = "000102030405060708090a0b0c0d0e0f"
    k, c = master(seed_hex)
    k, c = CKDpriv(k, c, H+0)
    k, c = CKDpriv(k, c, 1)
    k, c = CKDpriv(k, c, H+2)
    k, c = CKDpriv(k, c, 2)
    k, c = CKDpriv(k, c, 1000000000)
    k_hex = k.to_bytes(32, byteorder='big').hex()
    c_hex = c.hex()
    assert(k_hex == '471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8')
    assert(c_hex == 'c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e')

def ratchet(sk):
    h = hmac.HMAC(key=b'probably unsafe', digestmod='sha512')
    k = sk.privkey.secret_multiplier
    h.update(ser_256(k))
    c = h.digest()
    k, c = CKDpriv(k, c, H)
    return ecdsa.SigningKey.from_secret_exponent(k, curve=ecdsa.SECP256k1)

def main():
    keypath = sys.argv[1]
    itercnt = int(sys.argv[2])

    with open(keypath) as f:
        sk = ecdsa.SigningKey.from_pem(f.read())
        assert(sk.curve == ecdsa.SECP256k1)

    for i in range(itercnt):
        sk = ratchet(sk)

    print(sk.to_pem().decode('utf-8'))
    return 0

test()
main()

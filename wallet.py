#1 private key to WIF
#2 Generate new private key using the ECDSA algorithm and the curve used in Bitcoin
#3 public key from private
#4 private to adress
#5 Sign message with private key

import os
import random
import ecdsa
import hashlib
import base58
import codecs
import binascii


alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def gen_privkey(mnemocic="hello"):
    m = hashlib.sha256()
    m.update(bytes(mnemocic.encode()))
    return m.hexdigest()


def gen_rand_privkey():  #2
    bits = random.getrandbits(256)
    bits_hex = hex(bits)
    private_key = bits_hex[2:]
    return private_key


def sha256(arg):
    byte_array = bytearray.fromhex(arg)
    m = hashlib.sha256()
    m.update(byte_array)
    return m.hexdigest()


def ripemd160(x):
    d = hashlib.new("ripemd160")
    d.update(x)
    return d


def b58encode(hex_string):
    num = int(hex_string, 16)
    encode = ""
    base_count = len(alphabet)
    while num > 0:
        num, res = divmod(num,base_count)
        encode = alphabet[res] + encode
    return encode


def b58decode(v):
    if not isinstance(v, str):
        v = v.decode('ascii')
    decimal = 0
    for char in v:
        decimal = decimal * 58 + alphabet.index(char)
    return hex(decimal)[2:]


def privekey_to_wif(private_static): #1
    priv_add_x80 = "80" + private_static
    first_sha256 = sha256(priv_add_x80)
    seconf_sha256 = sha256(first_sha256)
    first_4_bytes = seconf_sha256[0:8]
    resulting_hex = priv_add_x80 + first_4_bytes
    result_wif = b58encode(resulting_hex)
    return result_wif

# 3

def uncompressed_pubkey(private_key):
    private_key_bytes = codecs.decode(private_key, 'hex')
    # Get ECDSA public key
    key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
    key_bytes = key.to_string()
    key_hex = codecs.encode(key_bytes, 'hex') #uncompresset pubkey
    key_hex = b'04' + key_hex
    print("your uncompressed key: " + key_hex.decode())
    return key_hex


def key_compressor(un_key):
    ret = un_key[2:66]
    last_byte = int(un_key[128:130], 16) % 2
    if last_byte == 1:
        ret = b'03' + ret
    else:
        ret = b'02' + ret
    return ret


def get_public(private_key):
    un_key = uncompressed_pubkey(private_key)
    comp_key = key_compressor(un_key)
    return comp_key.decode()


def private_to_addr(private_key): #4
    pub_key = get_public(private_key)
    public_key_bytes = codecs.decode(pub_key, 'hex')
    sha256_bpk = hashlib.sha256(public_key_bytes)
    sha256_bpk_digest = sha256_bpk.digest()
    ripemd160_bpk = hashlib.new('ripemd160')
    ripemd160_bpk.update(sha256_bpk_digest)
    ripemd160_bpk_digest = ripemd160_bpk.digest()
    ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest, 'hex')
    ripemd160_bpk_hex = b'00' + ripemd160_bpk_hex
    sha256_nbpk = hashlib.sha256(binascii.unhexlify(ripemd160_bpk_hex)).hexdigest()
    sha256_2_nbpk = hashlib.sha256(binascii.unhexlify(sha256_nbpk)).hexdigest()
    checksum = sha256_2_nbpk[:8]
    address_hex = ripemd160_bpk_hex.decode() + checksum
    leading_zeros = len(address_hex) - len(address_hex.lstrip('0'))
    b58_string=  b58encode(address_hex)
    ones = leading_zeros // 2
    for one in range(ones):
        b58_string = '1' + b58_string
    print(b58_string)
    return b58_string

def sign_message(priv_key, message): #5
    message_to_sign = bytes(message, 'utf-8')
    sign_key = ecdsa.SigningKey.from_string(codecs.decode(priv_key, 'hex'), ecdsa.SECP256k1)
    verify_key = sign_key.get_verifying_key()
    signature = sign_key.sign(message_to_sign)
    assert verify_key.verify(signature, message_to_sign)
    return signature, verify_key

# print(sign_message("2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824", "asd"))

# private_to_addr("2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824")
# private_to_addr(bytes("60cf347dbc59d31c1358c8e5cf5e45b822ab85b79cb32a9f3d98184779a9efc2".encode()))

# def get_uncompressed_pubkey(private_key):
#     sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
import random
import binascii
import ecdsa
import hashlib
import sys
import json

from base58 import b58encode
def secret_to_address(secret, legacy=False):
    pubk_pair = from_secret_pubk_point(secret)
    compressed_pubk, pubk = _pubk_to_compressed_pubk(*pubk_pair)
    address = _pubk_to_address(pubk) if legacy else _pubk_to_address(compressed_pubk)

    return address


def from_secret_pubk_point(secret):
    CURVE = ecdsa.SECP256k1

    sk = ecdsa.SigningKey.from_secret_exponent(secret, curve=CURVE)
    pubk_vk = sk.verifying_key  # the point
    pubk = binascii.b2a_hex(pubk_vk.to_string()).decode('ascii')

    pubk_x = pubk[:64]
    pubk_y = pubk[64:]

    return pubk_x, pubk_y


def _pubk_to_compressed_pubk(pubk_x, pubk_y):
    EVEN_PREFIX = '02'
    UNEVEN_PREFIX = '03'
    LEGACY_PREFIX = '04'
    y_parity = ord(bytearray.fromhex(pubk_y[-2:])) % 2
    prefix = EVEN_PREFIX if y_parity==0 else UNEVEN_PREFIX
    compressed_pubk = prefix + pubk_x

    pubk = LEGACY_PREFIX + pubk_x + pubk_y

    return compressed_pubk, pubk


def _pubk_to_address(pubk):
    pubk_array = bytearray.fromhex(pubk)

    sha = hashlib.sha256()  
    sha.update(pubk_array)
    rip = hashlib.new('ripemd160')
    rip.update(sha.digest())
    if sys.argv[1]=="bitcoin":
        PREFIX='00'
    elif sys.argv[1]=="dogecoin":
        PREFIX = '1E'
    key_hash = PREFIX + rip.hexdigest()
    sha = hashlib.sha256()
    sha.update(bytearray.fromhex(key_hash))
    checksum = sha.digest()
    sha = hashlib.sha256()
    sha.update(checksum)
    checksum = sha.hexdigest()[0:8]
    address_hex = key_hash + checksum
    
    bs = bytes(bytearray.fromhex(address_hex))
    address = b58encode(bs).decode('utf-8')

    return address


def secret_to_wif(secret):
    if sys.argv[1]=="bitcoin":
        PREFIX="00"
    elif sys.argv[1]=="dogecoin":
        PREFIX = "9e"
        
    hex_string = hex(secret)[2:].zfill(64)
    pre_hash = PREFIX + hex_string

    hash_1 = hashlib.sha256(binascii.unhexlify(pre_hash)).hexdigest()
    hash_2 = hashlib.sha256(binascii.unhexlify(hash_1)).hexdigest()
    checksum = hash_2[:8]

    pre_hash_checksum = pre_hash + checksum
    from_hex_string = int(pre_hash_checksum, 16)
    def _get(idx):
        ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        m = 58**idx
        idx = from_hex_string // m % 58
        return ALPHABET[idx]
    IDXS = range(51)  # sufficiently long
    wif_str = "".join(map(_get, IDXS))

    # Reverse
    rev_wif_str = wif_str[::-1].lstrip('1')

    return rev_wif_str
if __name__ == "__main__":
        if int(sys.argv[2])<16 and int(sys.argv[2])>0:
            data = []
            for i in range(int(sys.argv[2])):
                random_number = random.randint(1, 115792089237316195423570985008687907852837564279074904382605163141518161494336)
                PRIVATE_KEYS = [random_number]

                for secret in PRIVATE_KEYS:
                    wif = secret_to_wif(secret)

                    address_legacy = secret_to_address(secret, True)
                    address = secret_to_address(secret)
                    item = {"privk": wif, "address": address_legacy}
                    data.append(item)
                    json_data = json.dumps(data, indent=2)
            print(json_data)

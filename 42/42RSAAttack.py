import hashlib
import re
from binascii import unhexlify
from Cryptodome.Util.number import getPrime


def greatest_common_divisor(a, b):
    while a != 0 and b != 0:
        if a > b:
            a = a % b
        else:
            b = b % a
    return a + b


def inversion_by_mod(a, n):
    res = 0
    r = n
    candidate = 1
    next_r = a

    while next_r != 0:
        quotient = r // next_r
        res, candidate = candidate, res - quotient * candidate
        r, next_r = next_r, r - quotient * next_r

    return res + n


class RSA:
    def __init__(self, key_length):
        self.e = 3
        euler = 0

        while greatest_common_divisor(self.e, euler) != 1:
            p, q = getPrime(key_length // 2), getPrime(key_length // 2)
            euler = (p - 1) // greatest_common_divisor((p - 1), (q - 1)) * (q - 1)
            self.n = p * q

        self.mod = inversion_by_mod(self.e, euler)

    def encrypt(self, binary_data):
        int_data = int.from_bytes(binary_data, byteorder='big')
        return pow(int_data, self.e, self.n)

    def decrypt(self, encrypted_int_data):
        int_data = pow(encrypted_int_data, self.mod, self.n)
        return int_to_bytes(int_data)


def int_to_bytes(number):
    return number.to_bytes((number.bit_length() + 7) // 8, 'big')


def cube_sqrt(n):
    left = 0
    right = n

    while left < right:
        mid = (left + right) // 2
        if mid ** 3 < n:
            left = mid + 1
        else:
            right = mid

    return left


STANDARD_BLOCK = b'\x00\x01\xff+?\x00.{15}(.{20})'
asn1_sha1 = b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14'
garbage_symbol = b'\x00'


def forge_signature(message, key_length):
    encoded_message = unhexlify(hashlib.sha1(message).hexdigest())

    block = b'\x00\x01\xff\x00' + asn1_sha1 + encoded_message
    block += ((key_length // 8) - len(block)) * garbage_symbol

    forged_sig = cube_sqrt(int.from_bytes(block, byteorder='big'))

    return int_to_bytes(forged_sig)


class RSAWithDigitalSignature(RSA):

    def sign(self, message):
        return self.decrypt(int.from_bytes(message, byteorder='big'))

    def verify_signature(self, encrypted_signature, message):
        signature = garbage_symbol + int_to_bytes(self.encrypt(encrypted_signature))

        r = re.compile(STANDARD_BLOCK, re.DOTALL)
        m = r.match(signature)
        if not m:
            return False
        else:
            hashed = m.group(1)
            return hashed == unhexlify(hashlib.sha1(message).hexdigest())


def main():
    rsa_key_length = 1024
    message = b'hello world'

    forged_signature = forge_signature(message, rsa_key_length)
    assert RSAWithDigitalSignature(rsa_key_length).verify_signature(forged_signature, message)


if __name__ == '__main__':
    main()

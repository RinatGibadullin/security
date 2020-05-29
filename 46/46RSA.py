from base64 import b64decode
from Cryptodome.Util.number import getPrime
from decimal import *
from math import ceil, log


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


class OracleOfParity(RSA):

    def is_parity_odd(self, encrypted_int_data):
        return pow(encrypted_int_data, self.mod, self.n) % 2


def binary_search(multiplier, rsa_parity_oracle, left, right, encrypt_data):
    left = Decimal(left)
    right = Decimal(right)
    log_2 = int(ceil(log(rsa_parity_oracle.n, 2)))

    getcontext().prec = log_2

    for i in range(0, log_2):
        encrypt_data = (encrypt_data * multiplier) % rsa_parity_oracle.n
        mid = (left + right) / 2
        if rsa_parity_oracle.is_parity_odd(encrypt_data):
            left = mid
        else:
            right = mid

    return right


def int_to_bytes(number):
    return number.to_bytes((number.bit_length() + 7) // 8, 'big')


def oracle_of_parity_attack(encrypt_data, rsa_parity_oracle):
    multiplier = pow(2, rsa_parity_oracle.e, rsa_parity_oracle.n)

    left = 0
    right = rsa_parity_oracle.n

    decrypt_data = int(binary_search(multiplier, rsa_parity_oracle, left, right, encrypt_data))
    return int_to_bytes(decrypt_data)


def main():
    task_data = b64decode(
        "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="
    )
    oracle_of_parity = OracleOfParity(1024)

    encrypt_task_data = oracle_of_parity.encrypt(task_data)
    oracle_of_parity.decrypt(encrypt_task_data)

    input_text_result = oracle_of_parity_attack(encrypt_task_data, oracle_of_parity)

    assert input_text_result == task_data


if __name__ == '__main__':
    main()

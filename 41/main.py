from RSAClass import RSA, mod_inv, int_to_bytes
from random import randint


def unpadded_message_recovery(ciphertext, rsa_server):
    e, n = rsa_server.get_public_key()

    while True:
        s = randint(2, n - 1)
        if s % n > 1:
            break

    new_ciphertext = (pow(s, e, n) * ciphertext) % n

    new_plaintext = rsa_server.decrypt(new_ciphertext)
    int_plaintext = int.from_bytes(new_plaintext, byteorder='big')

    r = (int_plaintext * mod_inv(s, n)) % n

    return int_to_bytes(r)


class RSAServer:

    def __init__(self, rsa):
        self._rsa = rsa
        self._decrypted = set()

    def get_public_key(self):
        return self._rsa.e, self._rsa.n

    def decrypt(self, data):
        if data in self._decrypted:
            raise Exception("This ciphertext has already been decrypted")
        self._decrypted.add(data)
        return self._rsa.decrypt(data)


def main():
    plaintext = b"Hello world!"
    rsa = RSA(1024)
    ciphertext = rsa.encrypt(plaintext)
    rsa_server = RSAServer(rsa)

    recovered_plaintext = unpadded_message_recovery(ciphertext, rsa_server)
    assert recovered_plaintext == plaintext


if __name__ == '__main__':
    main()
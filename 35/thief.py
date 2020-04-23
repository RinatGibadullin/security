from random import randint


class Thief:

    def __init__(self, name, prime):

        self.name = name

        self.g = 1
        self.p = prime

        self.private_key = prime
        self.public_key = pow(self.g, self.private_key, self.p)

    def generate_secret_key(self, public_key_from_client):

        self.secret_key = hex(pow(public_key_from_client, self.private_key, self.p))[2:]

        return self.secret_key
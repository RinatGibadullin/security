from random import randint


class Thief:

    def __init__(self, name, generator, prime):

        self.name = name

        self.g = generator
        self.p = prime

        self.private_key = prime
        self.public_key = self.p

    def generate_secret_key(self, public_key_from_client):

        self.secret_key = hex(pow(public_key_from_client, self.private_key, self.p))[2:]

        return self.secret_key
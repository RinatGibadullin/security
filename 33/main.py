from Cryptodome.Util.number import getStrongPrime
from random import randint
from client import Client

if __name__ == "__main__":
    p = getStrongPrime(512)
    g = randint(2, p - 2)

    a = Client('Alice', g, p)
    b = Client('Bob', g, p)

    print('Connection established between %s and %s!\n' % (a.name, b.name))

    print('p = %d\ng = %d\n' % (p, g))

    print('%s -> %s ~ %d' % (b.name, a.name, b.public_key))

    a.generate_secret_key(b.public_key)

    print('%s -> %s ~ %d\n' % (a.name, b.name, a.public_key))

    b.generate_secret_key(a.public_key)

    if a.secret_key == b.secret_key:
        print(a.secret_key + '\n')
        print('Shared secret established!\n')
    else:
        print('Shared secrets are different!\n')

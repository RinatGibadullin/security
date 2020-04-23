from client import Client
from thief import Thief

if __name__ == "__main__":
    # p = getStrongPrime(512)
    # g = randint(2, p - 2)
    p = int("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)
    g = 2

    a = Client('Alice', g, p)
    m = Thief('Mitm', a.g, a.p)
    b = Client('Bob', m.g, m.p)
    b.generate_secret_key(m.public_key)
    a.generate_secret_key(m.public_key)
    print('Connection established between %s and %s!\n' % (a.name, b.name))

    print('p = %d\ng = %d\n' % (p, g))

    print('%s(Public key from %s) = %d' % (a.name, b.name, m.public_key))

    print('%s(Public key from %s) = %d\n' % (b.name, a.name, m.public_key))

    if a.secret_key == b.secret_key:
        print('Shared secret established!')
        print('SECRET KEY = %s\n' % a.secret_key)
    else:
        print('Shared secrets are different!\n')
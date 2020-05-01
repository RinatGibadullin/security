import math

from Cryptodome.Util.number import getStrongPrime


def encrypt(base, n, e):
    if n == 1:
        return 0
    c = 1
    for i in range(0, e):
        c = (c * base) % n

    return c


def decrypt(base, n, d):
    if n == 1:
        return 0
    c = 1
    for i in range(0, d):
        c = (c * base) % n

    return c


def extended_euclid(e, et):
    control = False
    i = 1
    while not control:
        if (e * i) % et == 1:
            control = True
        else:
            i += 1
    return i


def main():
    p, q, d = int(getStrongPrime(512)), int(getStrongPrime(512)), 0

    n = p * q
    et = (p - 1) * (q - 1)
    e = 3
    print("p:", p)
    print("q:", q)
    print("n:", n)
    print("et:", et)
    print("e:", e)

    enc = encrypt(42, n, e)
    print(enc)

    d = extended_euclid(e, et)
    print("d:", d)
    print(decrypt(enc, n, d))


if __name__ == "__main__":
    main()

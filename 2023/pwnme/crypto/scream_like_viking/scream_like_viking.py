from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
from Crypto.Util.Padding import pad

e = 17
p = getPrime(512)
q = getPrime(512)
N = p * q

def encrypt(m):
    assert 0 <= m < N
    c = pow(bytes_to_long(pad(long_to_bytes(m), 50)), e, N)
    return int(c)

def encrypt_flag():
    with open("/flag.txt", "rb") as f:
        flag = f.read()
    c = pow(bytes_to_long(pad(flag, 50)), e, N)
    return c

def main():
    try:
        while True:
            print("Enter your option (Encrypt or Flag) > ", end='')
            cmd = (input().strip())
            if cmd == "Encrypt":
                print("Enter your integer to encrypt > ", end='')
                m = int(input())
                c = encrypt(m)
                print(str(c) + '\n')
            elif cmd == "Flag":
                c = encrypt_flag()
                print("Flag cipher for you: " + str(c) + '\n')
                return
    except Exception as e:
        print("An error occured:\n", e)

if __name__ == "__main__":
    main()

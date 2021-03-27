from pwn import xor
import binascii

X = b"Hey Sariel apa kau membawa pesannya?"
Y = binascii.unhexlify(b"82ef4cccc87afe8a4cf235c26d2723fcbeb470e10fa7bd7f1ce23d9755772b285844f9b2")
flag = binascii.unhexlify(b"aecd6386fa5cb99573f353d37e2877d88d970aca3fa6e62f08b14b81664122006e0cd6cf54100a378d49fa5ebf5c35afcdf993400dba2ec756af3b965dac76d645adf80a")

key = xor(X,Y)
print(xor(key,flag))
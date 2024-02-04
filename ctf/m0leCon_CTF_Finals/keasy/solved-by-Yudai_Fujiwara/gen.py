from ptrlib import *

shellcode = nasm(open("shellcode.S").read(), bits=64)
s = ", ".join(map(lambda c: f"0x{c:02x}", shellcode))
print(s)

buf = open("template.c").read().replace("####SHELLCODE####", s)
open("exploit.c", "w").write(buf)


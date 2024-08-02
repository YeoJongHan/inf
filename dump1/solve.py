from pwn import *
import string

context.binary = "./chall"
context.log_level = 'CRITICAL'

flag = b'grey{wasnt'

chars = b"_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"
chars = ("_"+string.printable).encode()
while flag[-1] != ord('}'):
    for ch in chars:
        print(f"Trying {bytes([ch])}")
        p = gdb.debug("./chall", gdbscript=f"break *0x401c48", api=True)
        testflag = (flag + bytes([ch])).ljust(0x27, b'A') + b'}'
        p.gdb.execute('interrupt')
        p.gdb.continue_and_wait()
        p.sendline(testflag)
        for _ in range(len(flag)):
            p.gdb.continue_and_wait()

        p.gdb.continue_and_wait()
        own = p.gdb.parse_and_eval("$r8").const_value() & 0xff
        target = p.gdb.parse_and_eval("$rcx").const_value() & 0xff

        if own == target:
            flag += bytes([ch])
            print(f"Found: {flag}")
            p.gdb.quit()
            break
        p.gdb.quit()
print(flag)
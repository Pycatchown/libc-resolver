# libc-resolver

A python wrapper of the awesome project https://github.com/niklasb/libc-database, a project made to determine a libc library from its runtime addresses.

This wrapper is made for pwntools exploit development, all credits for the search engine goes to niklasb.

# How to use

Clone the project and add the folder to your PYTHONPATH env variable, then simply import the module and do:
```python
from libc_resolver import libc_resolve

libc = libc_resolve({"_IO_2_1_stdin_": 0x7fa30311a8c0})
print(libc.symbols["system"])
```

## Practical exemple

s

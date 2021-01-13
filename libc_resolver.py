from pwn import ELF, log
import config
import libcdb_wrapper
import re


def libc_resolve(dict_sym_addr, choice=0):
    if len(dict_sym_addr) <= 1:
        log.warning_once("[libc-resolver]: No reliable result is guaranteed without at least two symbols")
    result = libcdb_wrapper.find(dict_sym_addr)
    log.info("Found:\n%s" % result)
    regex_lib_names = r"\((.*)\)"
    libs = re.findall(regex_lib_names, result, re.MULTILINE)
    if len(libs) > 1:
        log.warning("[libc-resolver]: %d libraries are compatible, default choice is %d" % (len(libs), choice + 1))
    libc = ELF(config.db_path + libs[choice] + ".so")
    libc.address = list(dict_sym_addr.values())[0] - libc.symbols[list(dict_sym_addr.keys())[0]]
    return (libc)

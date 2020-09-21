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
    return (ELF(config.db_path + libs[choice] + ".so"))
    
if __name__ == "__main__":
    libc_resolve({"_IO_2_1_stdin_": 0x7fa30311a8c0})
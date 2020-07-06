# File: composer
# Author: Nicolas Fischer
# Program: Python 3.8
# Ext: py
# Licensed under GPU GPLv3 and later.
# -----------------------

import os, shutil, hashlib

VERSION = input("Version: ")

WORK_DIR = os.path.dirname(__file__)
CIS_PATH = os.path.join(WORK_DIR, "cis_win.py")
COMPOSE_DIR = os.path.join(WORK_DIR, "compose")
COMPOSE_CIS_PATH = os.path.join(COMPOSE_DIR, "cis_win-%s.py"%VERSION)
COMPOSED_EXE_PATH = os.path.join(COMPOSE_DIR, "dist", "cis_win-%s.exe"%VERSION)
BIN_PATH = os.path.join(WORK_DIR, "bin", "cis_win-%s.exe"%VERSION)
HASH_PATH = os.path.join(WORK_DIR, "bin", "cis_win-%s-hashes.txt"%VERSION)

os.mkdir(COMPOSE_DIR)
shutil.copyfile(CIS_PATH, COMPOSE_CIS_PATH)

os.system('cd %s && pyinstaller -F "%s"' %(COMPOSE_DIR, COMPOSE_CIS_PATH))

shutil.copyfile(COMPOSED_EXE_PATH, BIN_PATH)
shutil.rmtree(COMPOSE_DIR, True)

hashes = {"md5" : None, "sha1" : None, "sha256" : None, "sha512" : None, "sha3_256" : None, "sha3_512" : None}
for hash in hashes.keys():
    hashes[hash] = hashlib.new(hash)

with open(BIN_PATH, "rb") as file:
    read_file = file.read()
    for hash in hashes.values():
        hash.update(read_file)

for hash in hashes.keys():
    hashes[hash] = hashes[hash].hexdigest()

with open(HASH_PATH, "w+") as file:
    for hash, val in hashes.items():
        file.write("%s: %s\n" %(hash, val))

# File: composer
# Author: Nicolas Fischer
# Program: Python 3.8
# Ext: py
# Licensed under GPU GPLv3 and later.
# -----------------------

import os, shutil

VERSION = input("Version: ")

WORK_DIR = os.path.dirname(__file__)
CIS_PATH = os.path.join(WORK_DIR, "cis_win.py")
COMPOSE_DIR = os.path.join(WORK_DIR, "compose")
COMPOSE_CIS_PATH = os.path.join(COMPOSE_DIR, "cis_win-%s.py"%VERSION)
COMPOSED_EXE_PATH = os.path.join(COMPOSE_DIR, "dist", "cis_win-%s.exe"%VERSION)
BIN_PATH = os.path.join(WORK_DIR, "bin", "cis_win-%s.exe"%VERSION)

os.mkdir(COMPOSE_DIR)
shutil.copyfile(CIS_PATH, COMPOSE_CIS_PATH)

os.system('cd %s && pyinstaller -F "%s"' %(COMPOSE_DIR, COMPOSE_CIS_PATH))

shutil.copyfile(COMPOSED_EXE_PATH, BIN_PATH)
shutil.rmtree(COMPOSE_DIR, True)

# File: registry
# Author: Nicolas Fischer registry-program@licolas.net
# Program: Python 3.8
# Ext: py
# Licenced under GPU GLP v3. See LICENCE file for information.
# -----------------------

import winreg
from winreg import *#, HKEY_LOCAL_MACHINE, HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_USERS, HKEY_CURRENT_CONFIG

reg = ConnectRegistry(None, HKEY_CURRENT_USER)
key = r"NKey"

# Source: https://stackoverflow.com/a/5227427

key = OpenKey(reg, key)
for i in range(1024):
    # try:
        subkey_name = EnumKey(key, i)
        print(subkey_name)
        subkey = OpenKey(key, subkey_name)
        val = QueryValueEx(subkey, "DisplayName")
        print(val)
    # except EnvironmentError:
        # break

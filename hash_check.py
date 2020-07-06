# File: hash_check
# Author: Nicolas Fischer hash_check-program@licolas.net
# Program: Python 3.8
# Ext: py
# Licenced under GPU GLP v3. See LICENCE file for information.
# -----------------------

import os, csv, datetime, hashlib

__version__ = "0.1.0"

WORK_DIR = os.path.dirname(__file__)
OUT_PATH = os.path.join(WORK_DIR, "out.csv")

with open(OUT_PATH, "r", newline = "") as file:
    out_csv = csv.reader(file, delimiter=",")

    header_hash = hashlib.new('sha3_256')
    body_hash = hashlib.new("sha512")

    for row in out_csv:
        # print(row)
        if row[0] == "Output file version:":
            header_hash.update(bytes(str(row[1]), "ascii") + bytes(row[3], "ascii") + bytes(row[5], "utf-8"))
        elif row[0] == "User:":
            header_hash.update(bytes(row[1], "utf-8") + bytes(row[3], "utf-8"))
        elif row [0] == "Computer:":
            header_hash.update(bytes(row[1], "utf-16") + bytes(row[3], "utf-16"))
        elif row[0] == "Validity code:":
            print("Validity code match:", header_hash.hexdigest().upper() == row[1].upper())
        elif row[0] in ('DISCLAIMER:', '---------------', 'Number'):
            continue
        elif row[0] == 'Compliance integrity:':
            print('Compliance integrity match:', body_hash.hexdigest().upper() == row[1].upper())
        else:
            rev_row = row.copy()
            rev_row.reverse()
            for item in rev_row:
                if item in ("True", "False"):
                    body_hash.update(bytes(item.lower(), "utf-8"))
                    break

input()

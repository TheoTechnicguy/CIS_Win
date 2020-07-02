# File: cis_win
# Author: Nicolas Fischer
# Program: Python 3.8
# Ext: py
# -----------------------

import logging
logging.basicConfig(filename=__file__+'.log', level=logging.DEBUG, format='%(levelname)s at %(asctime)s: %(message)s', filemode = 'w', datefmt='%d/%m/%Y %I:%M:%S %p')

logging.info('Started')
logging.debug('Importing')
from logging import info as linfo, warning as lwarn, critical as lfatal, debug as ldb
import os, ctypes, sys, configparser, csv
from time import sleep
from ahk import AHK
from tkinter import Tk
from threading import Thread
Thread(target=input).start()
ldb('Done Importing')

ldb("Setting constants")
__version__ = "0.0.0.5"

GPO_DIR = os.path.join("C:\\", "GPO")
PATH_INF = os.path.join(GPO_DIR, "group-policy.inf")
PATH_INI = os.path.join(GPO_DIR, "group-policy.ini")
PATH_LOG = os.path.join(GPO_DIR, "group-policy.log")
CONFIG_FILE = os.path.join(os.path.dirname(__file__), "config.csv")
OUT_FILE = os.path.join(os.path.dirname(__file__), "out.csv")

if not os.path.exists(CONFIG_FILE):
    with open(CONFIG_FILE, "w+") as file:
        config_csv = csv.writer(file, delimiter=",")
        config_csv.writerow(["Section", "Number", "Key", "Min_val", "Max_val"])
        config_csv.writerow(["Note:", "Version:", __version__, "", "Max_val is excluded --> min=0 max=5 = 0-1-2-3-4. Use (-)999999 for (-)infinity."])
    raise Exception("Configuration file generated. Please fill.")

POLICIES = {}
with open(CONFIG_FILE, "r") as file:
    config_csv = csv.reader(file, delimiter=",")
    for row in config_csv:
        if not row:
            continue

        if row[0] == "Note:" and row[2].strip() != __version__:
            raise Exception("Configuration file is depreciated. Please back it up and delete it so it can be regenerated. Current version: %s - File version %s"%(row[2].strip(), __version__))
        elif row[0] == "Note:" and row[2] == __version__:
            break
# print(PASSWORD_POLICY)
# raise Exception()

ldb("Done constants")

ldb("Setting functions")
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False
ldb("Done functions")

if is_admin():
    if os.path.exists(GPO_DIR):
        linfo("Deleting existing folder")
        for file in os.listdir(GPO_DIR):
            ldb("Deleting %s", os.path.join(GPO_DIR, file))
            os.remove(os.path.join(GPO_DIR, file))
        ldb("Deleting folder")
        os.rmdir(GPO_DIR)

    linfo("Creating folder")
    os.mkdir(GPO_DIR)

    linfo("Running group-policy export command")
    os.system(r'secedit /export /cfg "%s" /log "%s"'%(PATH_INF, PATH_LOG))
    linfo(" --- Contents of %s ---", PATH_LOG)
    ldb("Parsing %s", PATH_LOG)
    with open(PATH_LOG, "r") as file:
        for line in file:
            linfo(line)
    linfo(" --- END contents of %s ---", PATH_LOG)

    # linfo("Clearing clipboard")
    # clp = Tk()
    # clp.withdraw()
    # clp.clipboard_clear()
    # clp.update()
    # clp.destroy()
    # sleep(1)

    linfo("Rewriting %s to %s", PATH_INF, PATH_INI)
    os.system(os.path.join(os.path.dirname(__file__), "GP-Get.exe"))

    linfo("Getting configparser")
    policy_file = configparser.ConfigParser()
    config_file = policy_file.read(PATH_INI)
    ldb("Config file %s has sections %s", config_file, policy_file.sections())

    linfo("Fetching policies")

    with open(OUT_FILE, "w+") as out_file, open(CONFIG_FILE, "r") as config_file:
        out_csv = csv.writer(out_file, delimiter=",")
        config_csv = csv.reader(config_file, delimiter=",")
        out_csv.writerow(["Number", "Policy", "Current_val", "Min_val", "Max_val", "Compliant"])
        out_csv.writerow(["Note:", "Version:", __version__, "", "Max value excluede. Used (-)999999 for (-)infinity."])

        for config_row in config_csv:
            if not config_row:
                continue
            if config_row[0] in ("Section", "Note:", "Comment"):
                continue

            ldb("Fetching policy %s of value %s - should be %s", config_row[2], policy_file[config_row[0]][config_row[2]], range(int(config_row[3]), int(config_row[4])))

            out_csv.writerow([config_row[1], config_row[2], policy_file[config_row[0]][config_row[2]], config_row[3], config_row[4], int(policy_file[config_row[0]][config_row[2]]) in range(int(config_row[3]), int(config_row[4]))])

    print("Done")
else:
    # Re-run the program with admin rights
    # ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv[1:]), None, 1)
    print("This program requires access to the GPO and thus FULL administrator rights. Please run this program with FULL administrator rights.")
    raise

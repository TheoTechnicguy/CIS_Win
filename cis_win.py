# File: cis_win
# Author: Nicolas Fischer
# Program: Python 3.8
# Ext: py
# Licensed under GPU GPLv3 and later.
# -----------------------

import logging
logging.basicConfig(filename=__file__+'.log', level=logging.DEBUG, format='%(levelname)s at %(asctime)s: %(message)s', filemode = 'w', datefmt='%d/%m/%Y %I:%M:%S %p')

logging.info('Started')
logging.debug('Importing')
from logging import info as linfo, warning as lwarn, critical as lfatal, debug as ldb
import os, ctypes, sys, configparser, csv, datetime, getpass, socket
from time import sleep
from ahk import AHK
from tkinter import Tk
from threading import Thread
Thread(target=input).start()
ldb('Done Importing')

ldb("Setting constants")
__version__ = "0.0.0.7"

GPO_DIR = os.path.join("C:\\", "GPO")
PATH_INF = os.path.join(GPO_DIR, "group-policy.inf")
PATH_INI = os.path.join(GPO_DIR, "group-policy.ini")
PATH_LOG = os.path.join(GPO_DIR, "group-policy.log")
CONFIG_FILE = os.path.join(os.path.dirname(__file__), "config.csv")
OUT_FILE = os.path.join(os.path.dirname(__file__), "out.csv")

SUPPORTED_TYPES = {"int" : int, "float" : float, "bool" : bool, "None" : type(None), "str" : str, "list" : list}

ROW_DICT_TEMPLATE = {
    "number": None,
    "section" : None,
    "policy" : None,
    "user_key" : None,
    "type" : None,
    "min_val" : None,
    "max_val" : None,
    "exact_val" : None
}

ldb("Creating classes")
class ImplementationError(Exception):
    """Error class for my program"""

    def __init__(self, msg = None):
        if not msg:
            msg = "This feature is not implemented yet."
        super().__init__(msg)


if not os.path.exists(CONFIG_FILE):
    with open(CONFIG_FILE, "w+", newline = "") as file:
        config_csv = csv.writer(file, delimiter=",")
        config_csv.writerows([["Version:", __version__],
        ["Note:", "Max_val is excluded --> min=0 max=5 = 0-1-2-3-4."],
        ["Number","Section", "Key", "User_key", "Type", "Min_val", "Max_val", "Exact_val"],
        ["-"*15]*8])
    raise Exception("Configuration file generated. Please fill.")

POLICIES = {}
with open(CONFIG_FILE, "r") as file:
    config_csv = csv.reader(file, delimiter=",")
    for row in config_csv:
        if not row:
            continue

        if row[0].startswith("Version:") and row[1] != __version__:
            raise Exception("Configuration file is depreciated. Please back it up and delete it so it can be regenerated. Current version: %s - File version %s"%(__version__, row[2].strip()))
        elif row[0].startswith("Version:") and row[1] == __version__:
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
    linfo("Setting dictionnary")

    with open(OUT_FILE, "w+", newline = "") as out_file, open(CONFIG_FILE, "r", newline = "") as config_file:
        out_csv = csv.writer(out_file, delimiter=",")
        config_csv = csv.reader(config_file, delimiter=",")
        out_csv.writerow(["Output file version:", __version__, "Execution time:", datetime.datetime.now(), "Time stamp:", datetime.datetime.timestamp(datetime.datetime.now())])
        out_csv.writerow(["User:", getpass.getuser(), "Domain", os.environ["userdomain"]])
        out_csv.writerow(["Computer:", socket.gethostname(),"IP:", socket.gethostbyname(socket.gethostname())])
        out_csv.writerow(["Note:", "Max value excluede."])
        out_csv.writerow(["-"*15]*6)
        out_csv.writerow(["Number", "Policy", "Current_val", "Min_val", "Max_val", "Exact_val", "Compliant"])

        for config_row in config_csv:
            if not config_row:
                continue
            if config_row[0] in ("Number", "Note:", "Comment", "Version:", "-"*15):
                continue

            row_dict = ROW_DICT_TEMPLATE.copy()

            for pos in range(len(config_row)):
                row_dict[list(ROW_DICT_TEMPLATE.keys())[pos]] = config_row[pos]

            if row_dict["type"].lower().strip() not in SUPPORTED_TYPES.keys():
                raise TypeError("%s is not a member of known types %s"%(row_dict["type"], tuple(SUPPORTED_TYPES.keys())))
            else:
                row_dict["type"] = SUPPORTED_TYPES[row_dict["type"]]
                # print(row_dict["type"])

            if not row_dict["user_key"]:
                row_dict["user_key"] = row_dict["section"]+"/"+row_dict["policy"]
            # print(row_dict["exact_val"], type(row_dict["exact_val"]), bool(row_dict["exact_val"]))
            to_csv = [row_dict["number"], row_dict["user_key"], policy_file[row_dict["section"]][row_dict["policy"]], row_dict["min_val"],     row_dict["max_val"], row_dict["exact_val"]]

            ldb("Inintial to_csv: %s", to_csv)

            linfo("%s is %s", row_dict["user_key"], row_dict["type"])
            if not row_dict["min_val"] and not row_dict["max_val"] and row_dict["exact_val"]: # Exact values
                if row_dict["type"] == int:
                    to_csv.append(int(policy_file[row_dict["section"]][row_dict["policy"]]) == int(row_dict["exact_val"])) # compliance

                elif row_dict["type"] == float:
                    to_csv.append(float(policy_file[row_dict["section"]][row_dict["policy"]]) == float(row_dict["exact_val"]))

                elif row_dict["type"] == type(None):
                    to_csv.append(not policy_file[row_dict["section"]][row_dict["policy"]]) # compliance

                elif row_dict["type"] == str:
                    to_csv.append(policy_file[row_dict["section"]][row_dict["policy"]].lower().strip() == row_dict["exact_val"].lower().strip()) # compliance

                elif row_dict["type"] == list:
                    values = row_dict["exact_val"].split(",")
                    for pos in range(len(values)):
                        values[pos] = values[pos].strip().lower()

                    raise ImplementationError()

            elif row_dict["min_val"] and row_dict["max_val"] and not row_dict["exact_val"]: # range
                if row_dict["type"] == int:
                    to_csv.append(int(policy_file[row_dict["section"]][row_dict["policy"]]) in range(int(row_dict["min_val"]),                       int(row_dict["max_val"])))

                elif row_dict["type"] == float:
                    raise ImplementationError()

                else:
                    raise TypeError("Cannot evaluate a range with type %s"%row_dict["type"])

            elif row_dict["min_val"] and not row_dict["max_val"] and not row_dict["exact_val"]: # minimum
                if row_dict["type"] == int:
                    to_csv.append(int(policy_file[row_dict["section"]][row_dict["policy"]]) >= int(row_dict["min_val"])) # compliance

                else:
                    raise ImplementationError()

            elif row_dict["min_val"] and row_dict["max_val"] and not row_dict["exact_val"]:
                if row_dict["type"] == int:
                    to_csv.append(int(policy_file[row_dict["section"]][row_dict["policy"]]) < int(row_dict["min_val"])) # compliance

                else:
                    raise ImplementationError()

            else:
                raise Exception("Inconsistent data. Verify config file at number %s"%row_dict["number"])

            linfo("Writing %s", to_csv)
            out_csv.writerow(to_csv)
    print("Done")
else:
    # Re-run the program with admin rights
    # NOTE: Cannot rerun beacuse of "advanced" admin management
    # ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv[1:]), None, 1)
    print("This program requires access to the GPO and thus FULL administrator rights. Please run this program with FULL administrator rights.")
    raise

# File: cis_win
# Author: Nicolas Fischer
# Program: Python 3.8
# Ext: py
# Licensed under GPU GPLv3 and later.
# -----------------------

import logging
logging.basicConfig(filename=__file__+'.log', level=logging.DEBUG, format='%(levelname)s at %(asctime)s: %(message)s', filemode = 'w', datefmt='%d/%m/%Y %I:%M:%S %p')

logging.info('Started')
logging.info('Starting imports')
from logging import info as linfo, warning as lwarn, critical as lfatal, debug as ldb
import os, ctypes, sys, csv, datetime, getpass, socket
from time import sleep
from threading import Thread
from xml.etree import ElementTree as ET
ldb('Done Importing')

linfo("Starting threads")
# Thread(target=input).start()
lwarn("Thread input_keep_alive intentionally commented!")
ldb("Done threads")

ldb("Setting constants")
__version__ = "0.0.0.9"
linfo("Current SW version: %s", __version__)

WORK_DIR = os.path.dirname(__file__)
CONFIG_PATH = os.path.join(WORK_DIR, "config.csv")
OUT_PATH = os.path.join(WORK_DIR, "out.csv")
XML_PATH = os.path.join(WORK_DIR, "group-policy.xml")
GENERATION_COMMAND = 'gpresult /F /X "%s"'%XML_PATH

STUPID_NAMESPACE = {
    "rsop" : "http://www.microsoft.com/GroupPolicy/Rsop",
    "settings" : "http://www.microsoft.com/GroupPolicy/Settings",
    "registry" : "http://www.microsoft.com/GroupPolicy/Settings/Registry",
    "security" : "http://www.microsoft.com/GroupPolicy/Settings/Security"
}

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
ldb("Done constants")

ldb("Creating classes")
class ImplementationError(Exception):
    """Error class for my program"""

    def __init__(self, msg = None):
        if not msg:
            msg = "This feature is not implemented yet."
        super().__init__(msg)

class AdminError(Exception):
    """Error class for my program"""

    def __init__(self, msg = None):
        if not msg:
            msg = "This program requires access to the GPO and thus FULL administrator rights. Please run this program with FULL administrator rights."
        super().__init__(msg)
ldb("Done classes")

# ldb("Setting functions")
# ldb("Done functions")

ldb("Starting config fetching")
if not os.path.exists(CONFIG_PATH):
    with open(CONFIG_PATH, "w+", newline = "") as file:
        config_csv = csv.writer(file, delimiter=",")
        config_csv.writerows([["Version:", __version__],
        ["Note:", "Max_val is excluded --> min=0 max=5 = 0-1-2-3-4."],
        ["Number","Section", "Policy_name", "User_key", "Type", "Min_val", "Max_val", "Exact_val"],
        ["-"*15]*8])
    raise Exception("Configuration file generated. Please fill.")

with open(CONFIG_PATH, "r") as file:
    config_csv = csv.reader(file, delimiter=",")
    for row in config_csv:
        if not row:
            continue

        if row[0].startswith("Version:") and row[1] != __version__:
            raise Exception("Configuration file is depreciated. Please back it up and delete it so it can be regenerated. Current version: %s - File version %s"%(__version__, row[2].strip()))
        elif row[0].startswith("Version:") and row[1] == __version__:
            break
ldb("Done config fetching")

linfo("Cleaning up")
for path in (OUT_PATH,):# XML_PATH):
    try:
        os.remove(path)
    except:
        pass
    else:
        lwarn("Deleted %s", path)
lwarn("Cleanup of group-policy.xml intentionally commented!")

try:
    ctypes.windll.shell32.IsUserAnAdmin()
except:
    raise AdminError()

linfo("Running group-policy export command %s", GENERATION_COMMAND)
# os.system(GENERATION_COMMAND)
lwarn("XML regeneration intentionally commented!")

linfo("Initializing xml file at %s"%XML_PATH)
xml_file = ET.parse(XML_PATH)
xml_root = xml_file.getroot()

linfo("Opening file out at %s"%OUT_PATH)
with open(OUT_PATH, "w+", newline = "") as out_file, open(CONFIG_PATH, "r", newline = "") as config_file:
    out_csv = csv.writer(out_file, delimiter=",")
    config_csv = csv.reader(config_file, delimiter=",")
    out_csv.writerows(
        [["Output file version:", __version__, "Execution time:", datetime.datetime.now(), "XML execution time:", xml_root.find("rsop:ReadTime", STUPID_NAMESPACE).text],
        ["User:", getpass.getuser(), "Domain:", os.environ["userdomain"]],
        ["Computer:", socket.gethostname(), "IP:", socket.gethostbyname(socket.gethostname())],
        ["Note:", "Max value excluede."],
        ["-"*15]*6,
        ["Number", "Policy", "Current_val", "Min_val", "Max_val", "Exact_val", "Compliant"]]
    )
    ldb("Written Heading")

    for config_row in config_csv:
        ldb("Current config_row: %s", config_row)
        if not config_row or config_row[0] in ("Number", "Note:", "Comment", "Version:", "-"*15):
            continue

        ldb("Copying template & filling")
        row_dict = ROW_DICT_TEMPLATE.copy()
        for pos in range(len(config_row)):
            row_dict[list(ROW_DICT_TEMPLATE.keys())[pos]] = config_row[pos]
        ldb("Current row_dict: %s", row_dict)
        linfo("Current policy: %s", row_dict["policy"])

        ldb("Analizing ending of section: %s", row_dict["section"])
        if not row_dict["section"].endswith("/*"):
            if not row_dict["section"].endswith("*") and row_dict["section"].endswith("/"):
                row_dict["section"] += "*"
            # if not row_dict["section"].endswith(":"):
                # row_dict["section"] += ":"
            # elif not row_dict["section"].endswith("security"):
                # row_dict["section"] += "security:"
            elif not row_dict["section"].endswith("/"):
                row_dict["section"] += "/*"
        ldb("Current section: >>>%s<<<", row_dict["section"])

        ldb("Getting xml value")
        # ldb("xml_root.findall: %s", xml_root.findall(row_dict["section"], STUPID_NAMESPACE))
        next_is_value = False
        for item in xml_root.findall(row_dict["section"], STUPID_NAMESPACE):
            item_tag = item.tag.split("}")[-1]
            ldb("Current item: %s", item_tag)
            if item_tag not in ("Name", "SettingNumber", "SettingBoolean"):
                continue

            if "Name" in item_tag and item.text == row_dict["policy"]:
                ldb("Found policy %s", item.text)
                next_is_value = True
            elif next_is_value and "Setting" in item_tag:
                ldb("Getting value")
                policy_value = item.text
                tag_type_str = item_tag[len("Setting"):]
                if tag_type_str.lower().strip() == "number":
                    ldb("Policy value is a number: %s", policy_value)
                    policy_value = int(policy_value)
                elif tag_type_str.lower().strip() == "boolean":
                    ldb("Policy value is a boolean: %s", policy_value)
                    if policy_value.title() == "True":
                        policy_value = True
                    else:
                        policy_value = False
                break
        ldb("Current policy_value %s has %s", policy_value, type(policy_value))

        if row_dict["type"].lower().strip() not in SUPPORTED_TYPES.keys():
            lfatal("%s is not a member of known types %s", row_dict["type"], tuple(SUPPORTED_TYPES.keys()))
            raise TypeError("%s is not a member of known types %s"%(row_dict["type"], tuple(SUPPORTED_TYPES.keys())))
        else:
            row_dict["type"] = SUPPORTED_TYPES[row_dict["type"]]
            ldb("Current row_dict['type']: %s", row_dict["type"])

        if not row_dict["user_key"]:
            row_dict["user_key"] = row_dict["policy"]

        to_csv = [row_dict["number"], row_dict["user_key"], policy_value, row_dict["min_val"], row_dict["max_val"], row_dict["exact_val"]]
        ldb("Inintial to_csv: %s", to_csv)

        linfo("%s is %s", row_dict["user_key"], row_dict["type"])
        if not row_dict["min_val"] and not row_dict["max_val"] and row_dict["exact_val"]: # Exact values
            if row_dict["type"] == int:
                to_csv.append(int(policy_value) == int(row_dict["exact_val"])) # compliance

            elif row_dict["type"] == float:
                to_csv.append(float(policy_value) == float(row_dict["exact_val"]))

            elif row_dict["type"] == type(None):
                to_csv.append(not policy_value) # compliance

            elif row_dict["type"] == str:
                to_csv.append(policy_value.lower().strip() == row_dict["exact_val"].lower().strip()) # compliance

            elif row_dict["type"] == list:
                values = row_dict["exact_val"].split(",")
                for pos in range(len(values)):
                    values[pos] = values[pos].strip().lower()

                raise ImplementationError()

        elif row_dict["min_val"] and row_dict["max_val"] and not row_dict["exact_val"]: # range
            if row_dict["type"] == int:
                to_csv.append(int(policy_value) in range(int(row_dict["min_val"]),                       int(row_dict["max_val"])))

            elif row_dict["type"] == float:
                raise ImplementationError()

            else:
                raise TypeError("Cannot evaluate a range with type %s"%row_dict["type"])

        elif row_dict["min_val"] and not row_dict["max_val"] and not row_dict["exact_val"]: # minimum
            if row_dict["type"] == int:
                to_csv.append(int(policy_value) >= int(row_dict["min_val"])) # compliance

            else:
                raise ImplementationError()

        elif row_dict["min_val"] and row_dict["max_val"] and not row_dict["exact_val"]:
            if row_dict["type"] == int:
                to_csv.append(int(policy_value) < int(row_dict["min_val"])) # compliance

            else:
                raise ImplementationError()

        else:
            raise Exception("Inconsistent data. Verify config file at number %s"%row_dict["number"])

        linfo("Writing %s", to_csv)
        out_csv.writerow(to_csv)
print("Done")

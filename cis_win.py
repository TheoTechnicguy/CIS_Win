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
import os, ctypes, sys, csv, datetime, getpass, socket, stat, hashlib
from time import sleep
from threading import Thread
from xml.etree import ElementTree as ET
ldb('Done Importing')

linfo("Starting threads")
# Thread(target=input).start()
lwarn("Thread input_keep_alive intentionally commented!")
ldb("Done threads")

ldb("Setting constants")
__version__ = "0.1.1"
__cfg_version__ = "0.1.0"
linfo("Current SW version: %s", __version__)
linfo("Current config version: %s", __cfg_version__)

WORK_DIR = os.path.dirname(__file__)
CONFIG_PATH = os.path.join(WORK_DIR, "config.csv")
OUT_PATH = os.path.join(WORK_DIR, "out.csv")
XML_PATH = os.path.join(WORK_DIR, "group-policy.xml")
GENERATION_COMMAND = 'gpresult /F /X "%s"'%XML_PATH

STUPID_NAMESPACE = {
    "rsop" : "http://www.microsoft.com/GroupPolicy/Rsop",
    "settings" : "http://www.microsoft.com/GroupPolicy/Settings",
    "registry" : "http://www.microsoft.com/GroupPolicy/Settings/Registry",
    "security" : "http://www.microsoft.com/GroupPolicy/Settings/Security",
    "type" : "http://www.microsoft.com/GroupPolicy/Types"
}

SUPPORTED_TYPES = {"int" : int, "float" : float, "bool" : bool, "none" : type(None), "str" : str, "list" : list, "print": "print"}

ROW_DICT_TEMPLATE = {
    "number": None,
    "section" : "",
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
    """Error class for my program.
    Is raised when a function or method or script part is call but not implemented"""

    def __init__(self, msg = None):
        if not msg:
            msg = "This feature is not implemented yet."
        super().__init__(msg)

class AdminError(Exception):
    """Error class for my program.
    Is raised when the program has no administrator rights"""

    def __init__(self, msg = None):
        if not msg:
            msg = "This program requires access to the GPO and thus FULL administrator rights. Please run this program with FULL administrator rights."
        super().__init__(msg)

class ConfigError(Exception):
    """Error class for my program.
    Is raised when error in relation to the config file"""

    def __init__(self, msg):
        super().__init__(msg)

ldb("Done classes")

# ldb("Setting functions")
# ldb("Done functions")

ldb("Starting config fetching")
if not os.path.exists(CONFIG_PATH):
    with open(CONFIG_PATH, "w+", newline = "") as file:
        config_csv = csv.writer(file, delimiter=",")
        config_csv.writerows([["Version:", __cfg_version__],
        ["Note:", "Max_val is excluded --> min=0 max=5 = 0-1-2-3-4."],
        ["Number","Section", "Policy_name", "Human_readable_policy_name", "Type", "Min_val", "Max_val", "Exact_val"],
        ["-"*15]*8])
    lfatal(ConfigError("Configuration file generated. Please fill."))
    raise ConfigError("Configuration file generated. Please fill.")

with open(CONFIG_PATH, "r") as file:
    config_csv = csv.reader(file, delimiter=",")
    for row in config_csv:
        if not row:
            continue

        if row[0].startswith("Version:") and row[1] != __cfg_version__:
            lfatal(ConfigError("Configuration file is depreciated. Please back it up and delete it so it can be regenerated. Current version: %s - File version: %s"%(__cfg_version__, row[1].strip())))
            raise ConfigError("Configuration file is depreciated. Please back it up and delete it so it can be regenerated. Current version: %s - File version %s"%(__cfg_version__, row[1].strip()))
        elif row[0].startswith("Version:") and row[1] == __cfg_version__:
            break
ldb("Done config fetching")

linfo("Cleaning up")
for path in (OUT_PATH,):# XML_PATH):
    ldb("Cleaning %s", path)
    try:
        os.chmod(path, stat.S_IWUSR)
        os.remove(path)
    except FileNotFoundError:
        pass
    except Exception as e:
        lfatal(Exception(e))
    else:
        lwarn("Deleted %s", path)
lwarn("Cleanup of group-policy.xml intentionally commented!")

try:
    ctypes.windll.shell32.IsUserAnAdmin()
except:
    raise AdminError()

linfo("Running group-policy export command '%s'", GENERATION_COMMAND)
# os.system(GENERATION_COMMAND)
lwarn("XML regeneration intentionally commented!")
linfo("Changing %s to read_only", XML_PATH)
os.chmod(XML_PATH, stat.S_IRUSR)

linfo("Initializing xml file at %s"%XML_PATH)
xml_file = ET.parse(XML_PATH)
xml_root = xml_file.getroot()

linfo("Opening file out at %s"%OUT_PATH)
with open(OUT_PATH, "w+", newline = "") as out_file, open(CONFIG_PATH, "r", newline = "") as config_file:
    out_csv = csv.writer(out_file, delimiter=",")
    config_csv = csv.reader(config_file, delimiter=",")
    out_csv.writerows([
        ["Output file version:", __version__, "Execution time:", datetime.datetime.now(), "XML execution time:", xml_root.find("rsop:ReadTime", STUPID_NAMESPACE).text],
        ["User:", getpass.getuser(), "Domain:", os.environ["userdomain"]],
        ["Computer:", socket.gethostname(), "IP:", socket.gethostbyname(socket.gethostname())],
        ["Note:", "Max value excluede. A Current_val of None might mean 'policy not found in export file'."],
        ["Validity code:", hashlib.sha3_256(
            bytes(__version__, "ascii") + bytes(str(datetime.datetime.now()), "ascii") +
            bytes(str(xml_root.find("rsop:ReadTime", STUPID_NAMESPACE).text), "utf-8") +
            bytes(getpass.getuser(), "utf-8") + bytes(os.environ["userdomain"], "utf-8") +
            bytes(socket.gethostname(), "utf-16") + bytes(socket.gethostbyname(socket.gethostname()), "utf-16")
        ).hexdigest().upper(), "Note: THIS FILE IS ONLY VALID IN READ-ONLY MODE AND CORRECT VALIDITY CODE."],
        ["DISCLAIMER:", "THE CONTENTS OF THIS FILE ONLY REFLECT THE GPO STATE OF THE PC AT EXECUTION TIME."],
        ["-"*15]*6,
        ["Number", "Policy", "Current_val", "Min_val", "Max_val", "Exact_val", "Compliant"]
    ])
    ldb("Written Heading")
    hash = hashlib.new("sha512")

    for config_row in config_csv:
        linfo(" --- New config row ---")
        ldb("Current config_row: %s", config_row)
        if not config_row or config_row[0] in ("Number", "Note:", "Comment", "Version:", "-"*15):
            continue

        ldb("Copying template & filling")
        row_dict = ROW_DICT_TEMPLATE.copy()
        row_dict_keys = list(row_dict.keys())
        for pos in range(len(config_row)):
            ldb("Setting row_dict['%s'] to %s from config_row[%i]", list(ROW_DICT_TEMPLATE.keys())[pos], config_row[pos], pos)
            if not config_row[pos]:
                row_dict[row_dict_keys[pos]] = ROW_DICT_TEMPLATE[row_dict_keys[pos]]
            else:
                row_dict[row_dict_keys[pos]] = config_row[pos]
        ldb("Current row_dict: %s", row_dict)
        linfo("Current policy: %s", row_dict["policy"])

        ldb("Analizing ending of section: %s", row_dict["section"])
        if not row_dict["section"].endswith("/"):
            if row_dict["section"].endswith("*"):
                row_dict["section"] = row_dict["section"][:-1]
            if not row_dict["section"].endswith("/"):
                row_dict["section"] += "/"
        ldb("Current section: >>>%s<<<", row_dict["section"])

        if str(row_dict["type"]).lower().strip() not in SUPPORTED_TYPES.keys():
            lfatal("%s is not a member of known types %s", row_dict["type"], tuple(SUPPORTED_TYPES.keys()))
            raise TypeError("%s is not a member of known types %s"%(row_dict["type"], tuple(SUPPORTED_TYPES.keys())))
        else:
            ldb("Current row_dict['type']: %s", row_dict["type"])
            row_dict["type"] = SUPPORTED_TYPES[str(row_dict["type"]).lower().strip()]

        if row_dict["type"] == "print": # add user key row to output file if type is print:
            # if row_dict["exact_val"] == None:
                # row_dict["exact_val"] = "This is a place-holder line and exists only for consistency."
            out_csv.writerow([row_dict["number"], row_dict["user_key"], row_dict["exact_val"]])
            continue
        elif row_dict["type"] == bool:
            ldb("Converting boolean %s", row_dict["exact_val"])
            if row_dict["exact_val"].title().strip() == "True":
                row_dict["exact_val"] = True
            else:
                row_dict["exact_val"] = False
            ldb("Current row_dict['exact_val']: %s", row_dict["exact_val"])
        elif row_dict["type"] == list:
            list_values = {}
            if row_dict["exact_val"]:
                list_values["exact_val"] = None
            if row_dict["min_val"]:
                list_values["min_val"] = None
            if row_dict["max_val"]:
                list_values["max_val"] = None
            for list_item in tuple(list_values.keys()):
                ldb("Converting list %s in row_dict['%s']", row_dict[list_item], list_item)
                list_values[list_item] = row_dict[list_item].split(",")
                for pos in range(len(list_values[list_item])):
                    list_values[list_item][pos] = list_values[list_item][pos].lower().strip()
                list_values[list_item].sort()
                ldb("Current values: %s", list_values[list_item])

        if not row_dict["user_key"]:
            row_dict["user_key"] = row_dict["policy"]

        ldb("Getting xml value")
        next_is_value = False
        policy_values = []
        for item in xml_root.findall(row_dict["section"], STUPID_NAMESPACE):
            item_tag = item.tag.split("}")[-1]
            # if item_tag not in ("Name", "SettingNumber", "SettingBoolean", "Member"):
            #     continue
            ldb(f"Current item: {item_tag!s:15}"+"next_is_value: %s", next_is_value)
            if "Name" in item_tag and item.text == row_dict["policy"]:
                ldb("Found policy %s", item.text)
                next_is_value = True
            elif "Name" in item_tag and policy_values:
                ldb("Breaking")
                break
            elif next_is_value and "Setting" in item_tag:
                policy_value = item.text
                tag_type_str = item_tag[len("Setting"):]
                if tag_type_str.lower().strip() == "number":
                    ldb("Policy value is a number: %s", policy_value)
                    policy_values.append(int(policy_value))
                elif tag_type_str.lower().strip() == "string":
                    ldb("Policy value is a string: %s", policy_value)
                    policy_values.append(str(policy_value).lower().strip())
                elif tag_type_str.lower().strip() == "boolean":
                    ldb("Policy value is a boolean: %s", policy_value)
                    if policy_value.title() == "True":
                        policy_values.append(True)
                    else:
                        policy_values.append(False)
                ldb("After adding value Current policy_values: %s", policy_values)
            elif next_is_value and "Member" in item_tag:
                ldb("Getting Members: %s", item.tag)
                for name in item:
                    ldb(f"Current name .tag: {name.tag!s:15} .text: {name.text!s}")
                    policy_values.append(name.text.lower().strip())

        ldb("Current policy_values: %s length: %i", policy_values, len(policy_values))
        if len(policy_values) == 0:
            policy_values = None
        elif len(policy_values) == 1:
            policy_values = policy_values[0]
        else:
            policy_values.sort()
        ldb("Current policy_values %s is %s", policy_values, type(policy_values))

        to_csv = [row_dict["number"], row_dict["user_key"], str(policy_values).title(), row_dict["min_val"], row_dict["max_val"], row_dict["exact_val"]]
        if isinstance(policy_values, list):
            to_csv[2] = ", ".join(policy_values).title()
        ldb("Inintial to_csv: %s", to_csv)

        linfo("%s is %s where min: %s max: %s exact: %s", row_dict["user_key"], row_dict["type"], bool(row_dict["min_val"]), bool(row_dict["max_val"]), bool(row_dict["exact_val"]))

        if row_dict["type"] != type(None) and policy_values == None: # Policy expected but not found:
            lwarn("Expected policy %s not found!", row_dict["policy"])
            to_csv[2] = "This policy could not be found!"
            to_csv.append(False)

        elif row_dict["min_val"] == None and row_dict["max_val"] == None and str(row_dict["exact_val"]): # Exact value(s):
            ldb("In exact value")
            if row_dict["type"] == int:
                to_csv.append(int(policy_values) == int(row_dict["exact_val"])) # compliance

            elif row_dict["type"] == float:
                to_csv.append(float(policy_values) == float(row_dict["exact_val"]))

            elif row_dict["type"] == type(None):
                to_csv.append(not policy_values) # compliance

            elif row_dict["type"] == str:
                to_csv.append(policy_values == row_dict["exact_val"].lower().strip()) # compliance:

            elif row_dict["type"] == list:
                try:
                    list_values["exact_val"]
                except KeyError:
                    raise ConfigError("Could not find any data in exact_val")

                if not isinstance(policy_values, list):
                    policy_values = [policy_values]
                if not isinstance(list_values["exact_val"], list):
                    list_values["exact_val"] = [list_values["exact_val"]]

                ldb("list(list_values['exact_val']): %s list(policy_values): %s", list(list_values["exact_val"]), list(policy_values))
                to_csv.append(list(list_values["exact_val"]) == list(policy_values))

            elif row_dict["type"] == bool:
                to_csv.append(policy_values == row_dict["exact_val"])

            else:
                lfatal(ImplementationError())
                raise ImplementationError()


        elif str(row_dict["min_val"]) and row_dict["max_val"] == None and row_dict["exact_val"] == None: # minimum:
            ldb("In min value")
            if row_dict["type"] == int:
                to_csv.append(int(policy_values) >= int(row_dict["min_val"])) # compliance

            elif row_dict["type"] == float:
                to_csv.append(float(policy_values) >= float(row_dict["min_val"])) # compliance

            elif row_dict["type"] == list:
                try:
                    list_values["min_val"]
                except KeyError:
                    raise ConfigError("Could not find any data in min_val")

                if not isinstance(policy_values, list):
                    policy_values = [policy_values]
                if not isinstance(list_values["min_val"], list):
                    list_values["min_val"] = [list_values["min_val"]]

                for value in list_values["min_val"]:
                    if value not in policy_values:
                        compliant = False
                        break
                else:
                    compliant = True
                to_csv.append(compliant)

            else:
                lfatal(ImplementationError())
                raise ImplementationError()

        elif row_dict["min_val"] == None and str(row_dict["max_val"]) and row_dict["exact_val"] == None: # maximum:
            ldb("In max value")
            if row_dict["type"] == int:
                to_csv.append(int(policy_values) < int(row_dict["min_val"])) # compliance

            elif row_dict["type"] == float:
                to_csv.append(float(policy_values) < float(row_dict["min_val"])) # compliance

            elif row_dict["type"] == list:
                try:
                    list_values["max_val"]
                except KeyError:
                    raise ConfigError("Could not find any data in max_val")

                if not isinstance(policy_values, list):
                    policy_values = [policy_values]
                if not isinstance(list_values["max_val"], list):
                    list_values["max_val"] = [list_values["max_val"]]

                for value in policy_value:
                    if value not in list_values["max_val"]:
                        compliant = False
                        break
                else:
                    compliant = True
                to_csv.append(compliant)

            else:
                lfatal(ImplementationError())
                raise ImplementationError()

        elif str(row_dict["min_val"]) and str(row_dict["max_val"]) and row_dict["exact_val"] == None: # range:
            ldb("In range")
            if row_dict["type"] == int:
                to_csv.append(int(policy_values) in range(int(row_dict["min_val"]), int(row_dict["max_val"])))

            elif row_dict["type"] == list:
                try:
                    list_values["min_val"]
                    list_values["max_val"]
                except KeyError:
                    raise ConfigError("Could not find any data in min_val or max_val")

                if not isinstance(policy_values, list):
                    policy_values = [policy_values]
                if not isinstance(list_values["max_val"], list):
                    list_values["max_val"] = [list_values["max_val"]]
                if not isinstance(list_values["min_val"], list):
                    list_values["min_val"] = [list_values["min_val"]]

                for value in list_values["min_val"]:
                    if value not in policy_values:
                        compliant = False
                        break
                else:
                    for value in policy_value:
                        if value not in list_values["max_val"]:
                            compliant = False
                            break
                    else:
                        compliant = True
                to_csv.append(compliant)

            else:
                raise TypeError("Cannot evaluate a range with type %s"%row_dict["type"])
        else:
            lfatal("Inconsistent data. Verify config file at number %s"%row_dict["number"])
            linfo("row_dict: %s", row_dict)
            raise ConfigError("Inconsistent data. Verify config file at number %s"%row_dict["number"])

        linfo("Writing %s", to_csv)
        out_csv.writerow(to_csv)
        to_csv.reverse()
        for item in to_csv:
            if isinstance(item, bool):
                hash.update(bytes(str(item).lower(), "utf-8"))
                break
    out_csv.writerow(["Compliance integrity:", hash.hexdigest().upper()])
linfo("Changing %s to read_only", OUT_PATH)
os.chmod(OUT_PATH, stat.S_IRUSR)

linfo("Cleaning up")
# os.remove(XML_PATH)
lwarn("XML_PATH clean up intentionally commented!")

linfo("Exiting")
print("Done")

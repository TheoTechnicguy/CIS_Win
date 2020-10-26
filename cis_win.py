# File: cis_win
# Author: Theo Technicguy cis_win-program@licolas.net
# Program: Python 3.8
# Ext: py
# Licensed under GPU GPLv3 and later.
# -----------------------

import logging
import os
import ctypes
import csv
import datetime
import getpass
import socket
import stat
import hashlib
import winreg
import argparse
from xml.etree import ElementTree as ET
from winreg import (
    HKEY_LOCAL_MACHINE,
    HKEY_CLASSES_ROOT,
    HKEY_CURRENT_USER,
    HKEY_USERS,
    HKEY_CURRENT_CONFIG,
)

logging.basicConfig(
    filename=__file__ + ".log",
    level=logging.DEBUG,
    format="At %(asctime)s: %(name)s - %(levelname)s: %(message)s",
    filemode="w",
    datefmt="%d/%m/%Y %I:%M:%S %p",
    encoding="UTF-8",
)

logging.info("Started")

logging.info("Starting threads")
# Thread(target=input).start()
logging.warning("Thread input_keep_alive intentionally commented!")
logging.debug("Done threads")

logging.debug("Setting constants")
__version__ = "0.1.5"
__cfg_version__ = "0.1.3"
logging.info("Current SW version: %s", __version__)
logging.info("Current config version: %s", __cfg_version__)

WORK_DIR = os.path.dirname(__file__)
OUT_PATH = os.path.join(WORK_DIR, "out.csv")
XML_PATH = os.path.join(WORK_DIR, "group-policy.xml")
GENERATION_COMMAND = 'gpresult /F /X "%s"' % XML_PATH
REGISTRY = {
    "HKEY_CLASSES_ROOT": winreg.ConnectRegistry(None, HKEY_CLASSES_ROOT),
    "HKEY_CURRENT_USER": winreg.ConnectRegistry(None, HKEY_CURRENT_USER),
    "HKEY_LOCAL_MACHINE": winreg.ConnectRegistry(None, HKEY_LOCAL_MACHINE),
    "HKEY_USERS": winreg.ConnectRegistry(None, HKEY_USERS),
    "HKEY_CURRENT_CONFIG": winreg.ConnectRegistry(None, HKEY_CURRENT_CONFIG),
}

STUPID_NAMESPACE = {
    "rsop": "http://www.microsoft.com/GroupPolicy/Rsop",  # root
    "settings": "http://www.microsoft.com/GroupPolicy/Settings",  # root 2
    "type": "http://www.microsoft.com/GroupPolicy/Types",  # root 3
    "script": "http://www.microsoft.com/GroupPolicy/Settings/Scripts",  # q1 & q6
    "win-reg": "http://www.microsoft.com/GroupPolicy/Settings/Windows/Registry",  # q2 & q8
    "pub-key": "http://www.microsoft.com/GroupPolicy/Settings/PublicKey",  # q3 & q12
    "registry": "http://www.microsoft.com/GroupPolicy/Settings/Registry",  # q4 & q5 & q15 & q16
    "audit": "http://www.microsoft.com/GroupPolicy/Settings/Auditing",  # q7
    "file": "http://www.microsoft.com/GroupPolicy/Settings/Files",  # q9
    "security": "http://www.microsoft.com/GroupPolicy/Settings/Security",  # q10 & q11
    "eqos": "http://www.microsoft.com/GroupPolicy/Settings/eqos",  # q13
    "fw": "http://www.microsoft.com/GroupPolicy/Settings/WindowsFirewall",  # q14
}

SUPPORTED_TYPES = {
    "int": int,
    "float": float,
    "bool": bool,
    "none": type(None),
    "str": str,
    "list": list,
    "print": "print",
}
SUPPORTED_SOURCES = ("xml", "registry")

ROW_DICT_TEMPLATE = {
    "number": None,
    "source": "xml",
    "section": "",
    "policy": None,
    "user_key": None,
    "type": None,
    "min_val": None,
    "max_val": None,
    "exact_val": None,
    "default": False,
}
logging.debug("Done constants")

logging.debug("Creating classes")


class ImplementationError(Exception):
    """ImplementationError class.

    Raised when a function or method or script part is call but not implemented
    yet or is a work in progress.
    """

    def __init__(self, msg=None):
        """Initilize ImplementationError class."""
        if not msg:
            msg = "This feature is not implemented yet."
        super().__init__(msg)


class AdminError(Exception):
    """AdminError class.

    Raised when the program has no administrator rights.
    """

    def __init__(self, msg=None):
        """Initilize AdminError class."""
        if not msg:
            msg = (
                "This program requires access to the GPO "
                "and thus FULL administrator rights. "
                "Please run this program with FULL administrator rights."
            )
        super().__init__(msg)


class ConfigError(Exception):
    """ConfigError class.

    Raised when an error occures in relation to the config file.
    """

    def __init__(self, msg):
        """Initilize ConfigError class."""
        super().__init__(msg)


logging.debug("Done setting up classes")

logging.debug("Setting up parser.")

parser = argparse.ArgumentParser()
parser.add_argument("--cfg", type=str, help="Optional config file location.")
args = parser.parse_args()

logging.debug("Done setting up parser.")

logging.debug("Starting config fetching")
if not args.cfg:
    CONFIG_PATH = os.path.join(WORK_DIR, "config.csv")
else:
    if not os.path.exists(args.cfg):
        raise FileNotFoundError("That path does not exist.")
    elif not os.path.isfile(args.cfg):
        raise Exception("That is not a file.")
    elif not os.path.splitext(args.cfg)[-1] == ".csv":
        raise Exception("That is not a csv.")
    else:
        CONFIG_PATH = args.cfg

if not os.path.exists(CONFIG_PATH):
    with open(CONFIG_PATH, "w+", newline="") as file:
        config_csv = csv.writer(file, delimiter=",")
        config_csv.writerows(
            [
                ["Version:", __cfg_version__],
                [
                    "Note:",
                    "Max_val is inclusive --> min=0 max=5 = 0-1-2-3-4-5.",
                    "Default source:",
                    ROW_DICT_TEMPLATE["source"],
                    "Default is_default:",
                    ROW_DICT_TEMPLATE["default"],
                ],
                [
                    "Number",
                    "Source",
                    "Section",
                    "Policy_name",
                    "Human_readable_policy_name",
                    "Type",
                    "Min_val",
                    "Max_val",
                    "Exact_val",
                    "is_default",
                ],
                ["-" * 15] * 8,
            ]
        )
    logging.critical(ConfigError("Configuration file generated. Please fill."))
    raise ConfigError("Configuration file generated. Please fill.")

with open(CONFIG_PATH, "r") as file:
    config_csv = csv.reader(file, delimiter=",")
    for row in config_csv:
        if not row:
            continue

        if row[0].startswith("Version:") and row[1] != __cfg_version__:
            logging.critical(
                ConfigError(
                    "Configuration file is depreciated. "
                    "Please back it up and delete it so it can be "
                    "regenerated. Current version: %s - File version: %s"
                    % (__cfg_version__, row[1].strip())
                )
            )
            raise ConfigError(
                "Configuration file is depreciated. "
                "Please back it up and delete it so it can be "
                "regenerated. Current version: %s - File version: %s"
                % (__cfg_version__, row[1].strip())
            )
        elif row[0].startswith("Version:") and row[1] == __cfg_version__:
            break
logging.debug("Done config fetching")

logging.info("Cleaning up")
for path in (OUT_PATH,):  # XML_PATH):
    logging.debug("Cleaning %s", path)
    try:
        os.chmod(path, stat.S_IWUSR)
        os.remove(path)
    except FileNotFoundError:
        pass
    except Exception as e:
        logging.critical(Exception(e))
    else:
        logging.warning("Deleted %s", path)
logging.warning("Cleanup of group-policy.xml intentionally commented!")

try:
    ctypes.windll.shell32.IsUserAnAdmin()
except Exception:
    raise AdminError()

if not os.path.exists(XML_PATH):
    print("Getting group-policy.xml file. This may take a while...")
    logging.info(
        "Running group-policy export command '%s'", GENERATION_COMMAND
    )
    os.system(GENERATION_COMMAND)
# logging.warning("XML regeneration intentionally commented!")
logging.info("Changing %s to read_only", XML_PATH)
os.chmod(XML_PATH, stat.S_IRUSR)

logging.info("Initializing xml file at %s" % XML_PATH)
xml_file = ET.parse(XML_PATH)
xml_root = xml_file.getroot()

logging.info("Opening file out at %s" % OUT_PATH)
with open(OUT_PATH, "w+", newline="") as out_file, open(
    CONFIG_PATH, "r", newline=""
) as config_file:
    out_csv = csv.writer(out_file, delimiter=",")
    config_csv = csv.reader(config_file, delimiter=",")
    time_now = datetime.datetime.now()
    out_csv.writerows(
        [
            [
                "Output file version:",
                __version__,
                "Execution time:",
                time_now,
                "XML execution time:",
                xml_root.find("rsop:ReadTime", STUPID_NAMESPACE).text,
            ],
            ["User:", getpass.getuser(), "Domain:", os.environ["userdomain"]],
            [
                "Computer:",
                socket.gethostname(),
                "IP:",
                socket.gethostbyname(socket.gethostname()),
            ],
            [
                "Note:",
                "Max value inclusive. A Current_val of None might mean "
                "'policy not found in export file'. Integer values of 0 and 1 "
                "equal to boolean values False and True.",
            ],
            [
                "Validity code:",
                hashlib.sha3_256(
                    bytes(__version__, "ascii")
                    + bytes(str(time_now), "ascii")
                    + bytes(
                        str(
                            xml_root.find(
                                "rsop:ReadTime", STUPID_NAMESPACE
                            ).text
                        ),
                        "utf-8",
                    )
                    + bytes(getpass.getuser(), "utf-8")
                    + bytes(os.environ["userdomain"], "utf-8")
                    + bytes(socket.gethostname(), "utf-16")
                    + bytes(
                        socket.gethostbyname(socket.gethostname()), "utf-16"
                    )
                )
                .hexdigest()
                .upper(),
                "Note: THIS FILE IS ONLY VALID IN READ-ONLY MODE AND CORRECT "
                "VALIDITY CODE.",
            ],
            [
                "DISCLAIMER:",
                "THE CONTENTS OF THIS FILE ONLY REFLECT THE GPO STATE OF THE "
                "PC AT EXECUTION TIME.",
            ],
            ["-" * 15] * 6,
            [
                "Number",
                "Source",
                "Section",
                "Policy",
                "Current_val",
                "Min_val",
                "Max_val",
                "Exact_val",
                "Compliant",
            ],
        ]
    )
    logging.debug("Written Heading")
    hash = hashlib.new("sha512")

    for config_row in config_csv:
        logging.info(" --- New config row ---")
        logging.debug("Current config_row: %s", config_row)
        if not config_row or config_row[0] in (
            "Number",
            "Note:",
            "Comment",
            "Version:",
            "-" * 15,
            "",
        ):
            continue

        logging.debug("Copying template & filling")
        row_dict = ROW_DICT_TEMPLATE.copy()
        row_dict_keys = list(row_dict.keys())
        for pos in range(len(config_row)):
            if len(row_dict_keys) <= pos:
                break
            logging.debug(
                "Setting row_dict['%s'] to %s from config_row[%i]",
                row_dict_keys[pos],
                config_row[pos],
                pos,
            )
            if not config_row[pos]:
                row_dict[row_dict_keys[pos]] = ROW_DICT_TEMPLATE[
                    row_dict_keys[pos]
                ]
            else:
                row_dict[row_dict_keys[pos]] = config_row[pos].strip()

        logging.debug("Current row_dict: %s", row_dict)
        logging.info("Current policy: %s", row_dict["policy"])

        logging.debug("Analizing ending of section: %s", row_dict["section"])
        if not row_dict["section"].endswith("/"):
            if row_dict["section"].endswith("*"):
                row_dict["section"] = row_dict["section"][:-1]
            if not row_dict["section"].endswith("/"):
                row_dict["section"] += "/"
        logging.debug("Current section: >>>%s<<<", row_dict["section"])

        # User input testing
        if str(row_dict["type"]).lower().strip().startswith("!"):
            negation = True
            row_dict["type"] = row_dict["type"][1:]
        else:
            negation = False

        if str(row_dict["type"]).lower().strip() not in SUPPORTED_TYPES.keys():
            logging.critical(
                "%s is not a member of known types %s",
                row_dict["type"],
                tuple(SUPPORTED_TYPES.keys()),
            )
            raise TypeError(
                "%s is not a member of supported types %s"
                % (row_dict["type"], tuple(SUPPORTED_TYPES.keys()))
            )
        else:
            logging.debug("Current row_dict['type']: %s", row_dict["type"])
            row_dict["type"] = SUPPORTED_TYPES[
                str(row_dict["type"]).lower().strip()
            ]

        if str(row_dict["source"]).lower().strip() not in SUPPORTED_SOURCES:
            logging.critical("%s is not a known source.", row_dict["source"])
            raise ConfigError("%s in not a known source." % row_dict["source"])

        if not isinstance(row_dict["default"], bool):
            row_dict["default"] = row_dict["default"].title().strip()
            if row_dict["default"] == "True":
                row_dict["default"] = True
            elif row_dict["default"] == "False":
                row_dict["default"] = False
            else:
                logging.critical("%s is not a boolean.", row_dict["default"])
                raise ConfigError("%s in not a boolean." % row_dict["default"])

        if (
            row_dict["type"] == "print"
        ):  # add user key row to output file if type is print:
            out_csv.writerow(
                [
                    row_dict["number"],
                    row_dict["user_key"],
                    row_dict["exact_val"],
                ]
            )
            continue

        if not row_dict["section"]:
            logging.critical(
                "Section number %s cannot be empty!", row_dict["number"]
            )
            raise ConfigError(
                "Section number %s cannot be empty!" % row_dict["number"]
            )
        if not row_dict["policy"]:
            logging.critical(
                "Policy number %s cannot be empty!", row_dict["number"]
            )
            raise ConfigError(
                "Policy number %s cannot be empty!" % row_dict["number"]
            )
        # END user input testing

        if row_dict["type"] == bool:
            logging.debug("Converting boolean %s", row_dict["exact_val"])
            if row_dict["exact_val"].title().strip() == "True":
                row_dict["exact_val"] = True
            else:
                row_dict["exact_val"] = False
            logging.debug(
                "Current row_dict['exact_val']: %s", row_dict["exact_val"]
            )
        elif row_dict["type"] == list:
            list_values = {}
            if row_dict["exact_val"]:
                list_values["exact_val"] = None
            if row_dict["min_val"]:
                list_values["min_val"] = None
            if row_dict["max_val"]:
                list_values["max_val"] = None
            for list_item in tuple(list_values.keys()):
                logging.debug(
                    "Converting list %s in row_dict['%s']",
                    row_dict[list_item],
                    list_item,
                )
                list_values[list_item] = row_dict[list_item].split(",")
                for pos in range(len(list_values[list_item])):
                    list_values[list_item][pos] = (
                        list_values[list_item][pos].lower().strip()
                    )
                list_values[list_item].sort()
                logging.debug("Current values: %s", list_values[list_item])

        if not row_dict["user_key"]:
            row_dict["user_key"] = row_dict["policy"]

        logging.debug("Getting value from %s", row_dict["source"])
        policy_values = []

        verify = True
        if row_dict["source"] == "registry":
            path = row_dict["section"][:-1].split("\\")[1:]
            if path[0].lower().strip() == "computer":
                path.remove(path[0])
            logging.debug("Current path: %s", path)

            hkey = path[0]
            key = "\\".join(path[1:])
            subkey = row_dict["policy"]
            try:
                registry = REGISTRY[hkey]
                logging.debug(
                    "Current registry: %s %s", registry, REGISTRY[hkey]
                )
            except KeyError:
                logging.critical(ConfigError("Registry %s not found" % hkey))
                raise ConfigError(
                    "Registry %s not found. Verify your config file!" % hkey
                )
            else:
                logging.debug("Looking for %s in %s", key, hkey)
                try:
                    open_key = winreg.OpenKey(registry, key)
                    policy_value = winreg.QueryValueEx(open_key, subkey)[0]
                    open_key.Close()
                except FileNotFoundError:
                    # logging.critical(r"Cannot find policy %s\%s\%s", hkey,
                    #                  key, subkey)
                    # raise ConfigError(r"Cannot find policy %s\%s\%s. Verify
                    #                 spelling in the CF."%(hkey, key, subkey))
                    # Issue #4
                    pass

        else:
            next_is_value = False
            if row_dict["policy"].startswith("fw:"):
                logging.debug(
                    "Looking for fw policy %s",
                    "/".join(
                        (
                            row_dict["section"][:-1],
                            row_dict["policy"],
                            "fw:Value",
                        )
                    ),
                )
                policy_value = xml_root.find(
                    "/".join(
                        (row_dict["section"], row_dict["policy"], "fw:Value")
                    ),
                    STUPID_NAMESPACE,
                ).text

            else:
                for item in xml_root.findall(
                    row_dict["section"], STUPID_NAMESPACE
                ):
                    item_tag = item.tag.split("}")[-1]
                    logging.debug(
                        f"Current item: {item_tag!s:15}" + "next_is_value: %s",
                        next_is_value,
                    )

                    if "Name" in item_tag and item.text == row_dict["policy"]:
                        logging.debug("Found policy %s", item.text)
                        next_is_value = True
                    elif "Name" in item_tag and policy_values:
                        logging.debug("Breaking")
                        break

                    elif next_is_value and "Setting" in item_tag:
                        policy_value = item.text
                        tag_type_str = (
                            item_tag[len("Setting") :].lower().strip()
                        )
                        logging.debug(
                            "After adding value Current policy_values: %s",
                            policy_values,
                        )

                    elif next_is_value and "Member" in item_tag:
                        logging.debug("Getting Members: %s", item.tag)
                        for name in item:
                            logging.debug(
                                f"Current name .tag: {name.tag!s:15} "
                                ".text: {name.text!s}"
                            )
                            policy_values.append(name.text.lower().strip())
                        verify = False

        if not isinstance(policy_value, type(None)) and verify:
            try:
                int(policy_value)
            except ValueError:
                policy_value = str(policy_value)

                if policy_value.title() == "True":
                    policy_value = True
                elif policy_value.title() == "False":
                    policy_value = False
                else:
                    policy_value = str(policy_value)
            else:
                if "." in str(policy_value):
                    policy_value = float(policy_value)
                else:
                    policy_value = int(policy_value)
            finally:
                policy_values.append(policy_value)

        logging.debug(
            "Current policy_values: %s length: %i",
            policy_values,
            len(policy_values),
        )
        if len(policy_values) == 0:
            policy_values = None
        elif len(policy_values) == 1:
            policy_values = policy_values[0]
        else:
            policy_values.sort()
        logging.debug(
            "Current policy_values %s is %s",
            policy_values,
            type(policy_values),
        )

        to_csv = [
            row_dict["number"],
            row_dict["source"],
            row_dict["section"],
            row_dict["user_key"],
            str(policy_values).title(),
            row_dict["min_val"],
            row_dict["max_val"],
            row_dict["exact_val"],
        ]
        if isinstance(policy_values, list):
            to_csv[2] = ", ".join(policy_values).title()
        logging.debug("Inintial to_csv: %s", to_csv)

        logging.info(
            "%s is %s where min: %s max: %s exact: %s",
            row_dict["user_key"],
            row_dict["type"],
            bool(row_dict["min_val"]),
            bool(row_dict["max_val"]),
            bool(row_dict["exact_val"]),
        )

        if (
            type(policy_values) != row_dict["type"]
            and (type(policy_value) != int and row_dict["type"] != bool)
            and (type(policy_value) != bool and row_dict["type"] != int)
        ):
            logging.warning(
                "At CF number %s - Expected type: %s but got %s",
                row_dict["number"],
                row_dict["type"],
                type(policy_values),
            )
            print(
                "Warning! At CF number %s - Expected type: %s but got %s"
                % (row_dict["number"], row_dict["type"], type(policy_values))
            )

        if (
            isinstance(row_dict["type"], type(None)) and policy_values is None
        ):  # Policy expected but not found:
            logging.warning(
                "Expected policy %s not found!", row_dict["policy"]
            )
            to_csv[2] = "None"
            if row_dict["default"]:
                to_csv.append(True)
            else:
                to_csv.append(False)

        elif (
            row_dict["min_val"] is None
            and row_dict["max_val"] is None
            and str(row_dict["exact_val"])
        ):  # Exact value(s):
            logging.debug("In exact value")
            if row_dict["type"] == int:
                to_csv.append(
                    int(policy_values) == int(row_dict["exact_val"])
                )  # compliance

            elif row_dict["type"] == float:
                to_csv.append(
                    float(policy_values) == float(row_dict["exact_val"])
                )

            elif isinstance(row_dict["type"], type(None)):
                to_csv.append(not policy_values)  # compliance

            elif row_dict["type"] == str:
                to_csv.append(
                    policy_values == row_dict["exact_val"].lower().strip()
                )  # compliance:

            elif row_dict["type"] == list:
                try:
                    list_values["exact_val"]
                except KeyError:
                    raise ConfigError("Could not find any data in exact_val")

                if not isinstance(policy_values, list):
                    policy_values = [policy_values]
                if not isinstance(list_values["exact_val"], list):
                    list_values["exact_val"] = [list_values["exact_val"]]

                logging.debug(
                    "list(list_values['exact_val']): %s "
                    "list(policy_values): %s",
                    list(list_values["exact_val"]),
                    list(policy_values),
                )
                to_csv.append(
                    list(list_values["exact_val"]) == list(policy_values)
                )

            elif row_dict["type"] == bool:
                to_csv.append(policy_values == row_dict["exact_val"])

            else:
                logging.critical(ImplementationError())
                raise ImplementationError()

        elif (
            str(row_dict["min_val"])
            and row_dict["max_val"] is None
            and row_dict["exact_val"] is None
        ):  # minimum:
            logging.debug("In min value")
            if row_dict["type"] == int:
                to_csv.append(
                    int(policy_values) >= int(row_dict["min_val"])
                )  # compliance

            elif row_dict["type"] == float:
                to_csv.append(
                    float(policy_values) >= float(row_dict["min_val"])
                )  # compliance

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
                logging.critical(ImplementationError())
                raise ImplementationError()

        elif (
            row_dict["min_val"] is None
            and str(row_dict["max_val"])
            and row_dict["exact_val"] is None
        ):  # maximum:
            logging.debug("In max value")
            if row_dict["type"] == int:
                to_csv.append(
                    int(policy_values) < int(row_dict["min_val"])
                )  # compliance

            elif row_dict["type"] == float:
                to_csv.append(
                    float(policy_values) < float(row_dict["min_val"])
                )  # compliance

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
                logging.critical(ImplementationError())
                raise ImplementationError()

        elif (
            str(row_dict["min_val"])
            and str(row_dict["max_val"])
            and row_dict["exact_val"] is None
        ):  # range:
            logging.debug("In range")
            if row_dict["type"] == int:
                to_csv.append(
                    int(policy_values)
                    in range(
                        int(row_dict["min_val"]), int(row_dict["max_val"]) + 1
                    )
                )

            elif row_dict["type"] == list:
                try:
                    list_values["min_val"]
                    list_values["max_val"]
                except KeyError:
                    raise ConfigError(
                        "Could not find any data in min_val or max_val"
                    )

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
                raise TypeError(
                    "Cannot evaluate a range with type %s" % row_dict["type"]
                )
        else:
            logging.critical(
                "Inconsistent data. Verify config file at number %s"
                % row_dict["number"]
            )
            logging.info("row_dict: %s", row_dict)
            raise ConfigError(
                "Inconsistent data. Verify config file at number %s"
                % row_dict["number"]
            )

        if negation:
            for rev_pos in range(len(rev_pos), 0, -1):
                if isinstance(to_csv[rev_pos], bool):
                    to_csv[rev_pos] = not to_csv[rev_pos]
                    break

        logging.info("Writing %s", to_csv)
        out_csv.writerow(to_csv)
        to_csv.reverse()
        for item in to_csv:
            if isinstance(item, bool):
                hash.update(bytes(str(item).lower(), "utf-8"))
                break
    out_csv.writerow(["Compliance integrity:", hash.hexdigest().upper()])
logging.info("Changing %s to read_only", OUT_PATH)
os.chmod(OUT_PATH, stat.S_IRUSR)

logging.info("Cleaning up")
# os.chmod(XML_PATH, stat.S_IWUSR) # Need to allow writing to delete.
# os.remove(XML_PATH)
logging.warning("XML_PATH clean up intentionally commented!")

logging.info("Exiting")
print("Done")

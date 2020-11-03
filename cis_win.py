# File: cis_win
# Author: Theo Technicguy cis_win-program@licolas.net
# Program: Python 3.8
# Ext: py
# Licensed under GPU GPLv3 and later.
# Copyright (c) 2020 Theo Technicguy All Rights Reserved.
# -----------------------

# ---------- START Setup ----------
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
    # HKEY_CLASSES_ROOT,
    HKEY_CURRENT_USER,
    # HKEY_USERS,
    # HKEY_CURRENT_CONFIG,
)

# Configuration for the log file.
logging.basicConfig(
    filename=__file__ + ".log",
    level=logging.DEBUG,
    format="At %(asctime)s: %(name)s - %(levelname)s: %(message)s",
    filemode="w",
    datefmt="%d/%m/%Y %I:%M:%S %p",
    encoding="UTF-8",
)

logging.info("Started")
# ---------- END Setup ----------

# ---------- START Fix Environement Constants ----------
logging.debug("Setting Fix Constants")
# Define program and config version and write to log file.
__version__ = "0.1.25"
__cfg_version__ = "0.1.3"
logging.info("Current SW version: %s", __version__)
logging.info("Current config version: %s", __cfg_version__)

# Set work directory and file paths.
WORK_DIR = os.path.dirname(__file__)
# ---------- END Fix Environement Constants ----------

# ---------- START Arguments Parsing ----------
# Argument Parser setup.
# Argument Parser = python -V --me
#                           ^  ^^
logging.debug("Setting up parser.")

parser = argparse.ArgumentParser()
parser.add_argument(
    "--config-file",
    type=str,
    help="Config file location. Default is `config.csv`",
    default=os.path.join(WORK_DIR, "config.csv"),
)
parser.add_argument(
    "--output-file",
    type=str,
    help="Output file location. Default is `out.csv`",
    default=os.path.join(WORK_DIR, "out.csv"),
)
parser.add_argument(
    "--gpo-file",
    type=str,
    help="GPO file location. Default is `group-policy.xml`",
    default=os.path.join(WORK_DIR, "group-policy.xml"),
)
parser.add_argument(
    "--no-generate-gpo",
    action="store_true",
    help="Do not generate or delete the group-policy.xml file. ONLY FOR TESTING!",
)
parser.add_argument(
    "--use-time",
    type=str,
    help="Use the time specified for execution time. ONLY FOR TESTING!",
    default=str(datetime.datetime.now()),
)
parser.add_argument(
    "--no-check-admin",
    action="store_false",
    help="Do not check if executed as admin. THIS CAN CREATE PROBLEMS!",
)

args = parser.parse_args()
logging.info("Arguments parsed: %s", args)
logging.debug("Done setting up parser.")
# ---------- END Arguments Parsing ----------

# ---------- START User Input Verification ----------
# Get argements or set variables to default values.
CONFIG_PATH = args.config_file
OUT_PATH = args.output_file
XML_PATH = args.gpo_file

is_dev = args.no_generate_gpo or args.use_time != str(datetime.datetime.now())
if is_dev:
    logging.warning("Running in dev environment.")
# ---------- END User Input Verification ----------

# GPO generation command. Used later...
# COMBAK: Keep as constant or move to cmd?
GENERATION_COMMAND = 'gpresult /F /X "%s"' % XML_PATH

# Set registry dictionnary
# OPTIMIZE: Which do I need? They generate all a memory object!
REGISTRY = {
    # "HKEY_CLASSES_ROOT": winreg.ConnectRegistry(None, HKEY_CLASSES_ROOT),
    "HKEY_CURRENT_USER": winreg.ConnectRegistry(None, HKEY_CURRENT_USER),
    "HKEY_LOCAL_MACHINE": winreg.ConnectRegistry(None, HKEY_LOCAL_MACHINE),
    # "HKEY_USERS": winreg.ConnectRegistry(None, HKEY_USERS),
    # "HKEY_CURRENT_CONFIG": winreg.ConnectRegistry(None, HKEY_CURRENT_CONFIG),
}

# Set XML namespaces dictionnary
STUPID_NAMESPACE = {
    # Roots: Main, Settings (root 2) and Type (root 3)
    "rsop": "http://www.microsoft.com/GroupPolicy/Rsop",
    "settings": "http://www.microsoft.com/GroupPolicy/Settings",
    "type": "http://www.microsoft.com/GroupPolicy/Types",
    # q1 & q6
    "script": "http://www.microsoft.com/GroupPolicy/Settings/Scripts",
    # q2 & q8
    "win-reg": "http://www.microsoft.com/GroupPolicy/Settings/Windows/Registry",
    # q3 & q12
    "pub-key": "http://www.microsoft.com/GroupPolicy/Settings/PublicKey",
    # q4 & q5 & q15 & q16
    "registry": "http://www.microsoft.com/GroupPolicy/Settings/Registry",
    # q7
    "audit": "http://www.microsoft.com/GroupPolicy/Settings/Auditing",
    # q9
    "file": "http://www.microsoft.com/GroupPolicy/Settings/Files",
    # q10 & q11
    "security": "http://www.microsoft.com/GroupPolicy/Settings/Security",
    # q13
    "eqos": "http://www.microsoft.com/GroupPolicy/Settings/eqos",
    # q14
    "fw": "http://www.microsoft.com/GroupPolicy/Settings/WindowsFirewall",
}

# Dictionnary with type conversion.
SUPPORTED_TYPES = {
    "int": int,
    "float": float,
    "bool": bool,
    "none": type(None),
    "str": str,
    "list": list,
    "print": "print",
}

# Tuple of supported sources
SUPPORTED_SOURCES = ("xml", "registry")

# Template for the row dictionnary.
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

EXPORT_VALUES = tuple(
    key
    for key in list(ROW_DICT_TEMPLATE.keys())
    if key not in ("policy", "type")
)
logging.debug("Done setting Fix Constants")
# ---------- END Fix Constants ----------

# Custom Exception Classes.
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

logging.debug("Setting up functions.")


def location_number_like(number: int) -> bool:
    """Check if `number` is a location/version-like number.

    Returns True if `number` is of type x.x.x.x, where x is an int.
    """
    logging.debug(
        f"location like number called with {number}. "
        f"Replaced: {number.replace('.', '')}."
    )
    return number.replace(".", "").isdigit()


logging.debug("Finished setting up functions.")

# Generate configuration file if it does not exist.
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
    # End program and ask configuration file filling.
    logging.critical(ConfigError("Configuration file generated. Please fill."))
    raise ConfigError("Configuration file generated. Please fill.")

with open(CONFIG_PATH, "r") as file:
    read_file = file.read().lower()
    # Find line with version info.
    version_start = read_file.find("version:")
    version_eol = read_file.find("\n", version_start)

    if version_start == -1:
        logging.warning(ConfigError("Could not find version string!"))
        print(ConfigError("Could not find version string!"))

    else:
        # convert locations into line and pretify.
        version_line = read_file[version_start:version_eol]
        version_line = version_line.removeprefix("version:").strip(" \n,.")

        logging.info(f"Config file version: {version_line}")

        # Verify version.
        if version_line < __cfg_version__:
            logging.warning(
                DeprecationWarning(
                    "Configuration file is depreciated. "
                    f"Expected {__cfg_version__} - Got {version_line}"
                )
            )
            print(
                DeprecationWarning(
                    "Configuration file is depreciated. "
                    "Please back it up and delete it so it can be "
                    f"regenerated. Current version: {__cfg_version__} "
                    f"- File version: {version_line}"
                )
            )

logging.debug("Done config fetching")

logging.info("Cleaning up")
# Clean up files.
# COMBAK: Should be at the end of the program: "Clean up"
# XML_PATH is not cleaned up because I need it for development.
# Allow overwriting of output file if it exists.
try:
    os.chmod(OUT_PATH, stat.S_IWUSR)
except FileNotFoundError:
    logging.debug("No output file.")
else:
    logging.info("Changed rights on output file.")

# Verify program being run as administrator.
# Starting Python 3.9, this returns a boolean int.
if args.no_check_admin:
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            raise AdminError()
    except AdminError:
        raise
    except Exception:
        raise AdminError()
else:
    logging.warning("Skipping admin check!")

# Generate GPO XML file if it does not exist.
if args.no_generate_gpo:
    logging.warning("Not Generating new GPO.")
else:
    print("Getting group-policy.xml file. This may take a while...")
    logging.info(
        "Running group-policy export command '%s'", GENERATION_COMMAND
    )
    os.system(GENERATION_COMMAND)

# Change rights to read only (Attempt at tampering minimization).
logging.info("Changing %s to read_only", XML_PATH)
os.chmod(XML_PATH, stat.S_IRUSR)

# Read GPO XML as xml file and select root.
logging.info("Initializing xml file at %s" % XML_PATH)
xml_file = ET.parse(XML_PATH)
xml_root = xml_file.getroot()

# Create output file and read config file.
logging.info("Opening file out at %s" % OUT_PATH)
with open(OUT_PATH, "w+", newline="") as out_file, open(
    CONFIG_PATH, "r", newline=""
) as config_file:
    # Read files as CSV
    out_csv = csv.writer(out_file, delimiter=",")
    config_csv = csv.reader(config_file, delimiter=",")

    # Get current time.
    time_now = args.use_time

    # Write header.
    # OPTIMIZE: Create template file and dwl/copy it. Possible?
    out_csv.writerows(
        [
            [
                "Program version:",
                __version__,
                "Execution time:",
                time_now,
                "XML execution time:",
                xml_root.find("rsop:ReadTime", STUPID_NAMESPACE).text,
                "Development environment" if is_dev else "",
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
                    + bytes("XXX-DEV-XXX", "ascii")
                    if is_dev
                    else b""
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
                "Is_default",
                "Compliant",
            ],
        ]
    )

    # Create Integrity Hash using sha512.
    logging.debug("Written Heading")
    hash = hashlib.new("sha512")

    # Iterate config file rows.
    for config_row in config_csv:
        logging.info(" --- New config row ---")
        logging.debug("Current config_row: %s", config_row)

        # Skip file headers and comments.
        if not location_number_like(config_row[0]):
            logging.debug("Skipping row.")
            continue

        # Fill template with info.
        logging.debug("Copying template & filling")
        row_dict = ROW_DICT_TEMPLATE.copy()
        row_dict_keys = list(row_dict.keys())
        logging.debug(f"row_dict copied from temlate: {row_dict}")

        for pos, value in enumerate(config_row):
            if len(row_dict_keys) <= pos:
                break

            logging.debug(
                "Setting row_dict['%s'] to %s from config_row[%i]",
                row_dict_keys[pos],
                value,
                pos,
            )

            # Use the user's value if it exists and lower values if needed.
            lowered = ("type", "source", "exact_val", "min_val", "max_val")
            if value and row_dict_keys[pos] in lowered:
                row_dict[row_dict_keys[pos]] = value.strip().lower()
            elif value:
                row_dict[row_dict_keys[pos]] = value.strip()

        logging.debug("Current row_dict: %s", row_dict)
        logging.info("Current policy: %s", row_dict["policy"])

        # Add `print` types to output file and start over.
        if row_dict["type"] == "print":
            out_csv.writerow(
                [
                    row_dict["number"],
                    "",  # Source is empty
                    row_dict["user_key"],
                    row_dict["exact_val"],
                ]
            )
            continue

        # If the end of the path is a wildcard `*` or a slash `/`, remove it.
        row_dict["section"] = row_dict["section"].strip(" /\\*")

        # If the type starts with an `!`, negate the result.
        negation = "!" in row_dict["type"]
        row_dict["type"] = row_dict["type"].replace("!", "")

        # Check that the type is supported and convert it. Else raise TypeError
        if str(row_dict["type"]) not in SUPPORTED_TYPES.keys():
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
            row_dict["type"] = SUPPORTED_TYPES[str(row_dict["type"])]

        # Check source is known.
        if str(row_dict["source"]) not in SUPPORTED_SOURCES:
            logging.critical("%s is not a known source.", row_dict["source"])
            raise ConfigError("%s is not a known source." % row_dict["source"])

        # Convert string booleans to booleans
        if not isinstance(row_dict["default"], bool):
            row_dict["default"] = row_dict["default"].title()
            if row_dict["default"] == "True":
                row_dict["default"] = True
            elif row_dict["default"] == "False":
                row_dict["default"] = False
            else:
                logging.critical("%s is not a boolean.", row_dict["default"])
                raise ConfigError("%s in not a boolean." % row_dict["default"])

        # Check that section and policy cells aren't empty.
        for key in ("section", "policy"):
            if not row_dict[key]:
                msg = (
                    f"{key.title()} number {row_dict['number']} "
                    "cannot be empty!"
                )
                logging.critical(msg)
                raise ConfigError(msg)

        # Converting cell values acoording to types.
        if isinstance(row_dict["type"], bool):
            # Boolean convertsion.
            logging.debug("Converting boolean %s", row_dict["exact_val"])
            if row_dict["exact_val"].title() == "True":
                row_dict["exact_val"] = True
            else:
                row_dict["exact_val"] = False
            logging.debug(
                "Current row_dict['exact_val']: %s", row_dict["exact_val"]
            )
        elif isinstance(row_dict["type"], list):
            # WHAAAAAT?
            # COMBAK: Needs comments.
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
                    list_values[list_item][pos] = list_values[list_item][
                        pos
                    ].lower()
                list_values[list_item].sort()
                logging.debug("Current values: %s", list_values[list_item])

        # If there is not humnanly readable policy, use the programmatic one.
        if not row_dict["user_key"]:
            row_dict["user_key"] = row_dict["policy"]

        logging.debug("Getting value from %s", row_dict["source"])
        policy_values = []

        verify = True
        if row_dict["source"] == "registry":
            # WHAAAAAT: just remove the lase `\` if you don't need it...
            # WHAAAAAT: You split it to join it again ?!?
            path = row_dict["section"].lower()
            path = path.replace("computer\\", "")
            logging.debug("Replaced path: %s", path)
            path = path.strip(" /\\")
            path = path.split("\\")
            logging.debug("Split path: %s", path)
            logging.debug("Final path: %s", path)

            # Set HKEY by popping the first elemet of the path
            hkey = path.pop(0).upper()
            # Key path is the joined path
            key = "\\".join(path)
            # Subkey is the policy
            subkey = row_dict["policy"]

            # Attempt to get the registry. Raise ConfigError if it fails.
            # Then get the key but pass if you cannot find it.
            # Issue #4 states that a missing key can mean a default value.
            try:
                registry = REGISTRY[hkey]
                logging.debug("Looking for %s in %s in %s", subkey, key, hkey)
                with winreg.OpenKey(registry, key) as open_key:
                    policy_value = winreg.QueryValueEx(open_key, subkey)[0]
            except KeyError:
                logging.critical(ConfigError("Registry %s not found" % hkey))
                raise ConfigError(
                    "Registry %s not found. Verify your config file!" % hkey
                )
            except FileNotFoundError:
                # Issue #4 - Missing key can mean default value.
                pass

        else:
            # If the source is not registry, the default (XML).
            next_is_value = False

            # Speciality for firewall policies.
            # COMBAK: unify with rest. Wasn't this a hotfix?
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

                # Find the policy in the XML
                policy_value = xml_root.find(
                    "/".join(
                        (row_dict["section"], row_dict["policy"], "fw:Value")
                    ),
                    STUPID_NAMESPACE,
                ).text

            else:
                # For non firewall policies
                # TODO: Learn aboux xml lib. --> Change to lxml?
                for item in xml_root.findall(
                    row_dict["section"] + "/", STUPID_NAMESPACE
                ):
                    # Get item tag
                    item_tag = item.tag.split("}")[-1]
                    # WHAAAAAT: Consistency PLEASE!
                    logging.debug(
                        f"Current item: {item_tag!s:15} "
                        f"next_is_value: {next_is_value}"
                    )

                    # Look if we found the policy.
                    if "Name" in item_tag and item.text == row_dict["policy"]:
                        logging.debug("Found policy %s", item.text)
                        next_is_value = True
                    elif "Name" in item_tag and policy_values:
                        # break loop if we have the policy value.
                        logging.debug("Breaking")
                        break

                    elif next_is_value and "Setting" in item_tag:
                        # Get the policy value if the previous tag was name
                        policy_value = item.text
                        logging.debug("Policy value is %s", policy_value)
                        policy_values.append(policy_value)
                        logging.debug(
                            "After adding value Current policy_values: %s",
                            policy_values,
                        )

                    elif next_is_value and "Member" in item_tag:
                        # If the policy value is a list (Member) get all list
                        # members. Also do not verify.
                        logging.debug("Getting Members: %s", item.tag)
                        for name in item:
                            logging.debug(
                                f"Current name .tag: {name.tag!s:15} "
                                ".text: {name.text!s}"
                            )
                            policy_values.append(name.text.lower())
                        verify = False

        # Verify/convert policy value.
        # COMBAK: Is there a float value?
        logging.debug(" ------ Starting Conversion ------")
        policy_values_out = []
        for policy_value in policy_values:
            logging.debug("Current policy value %s", policy_value)
            if not isinstance(policy_value, type(None)) and verify:
                try:
                    float(policy_value)
                except ValueError:
                    policy_value = str(policy_value)

                    if policy_value.title() == "True":
                        policy_value = True
                    elif policy_value.title() == "False":
                        policy_value = False
                    else:
                        policy_value = str(policy_value)
                else:
                    logging.debug("Is a float.")
                    if str(policy_value).count(".") == 1:
                        policy_value = float(policy_value)
                        logging.debug("Really a float.")
                    else:
                        policy_value = int(policy_value)
                        logging.debug("No - Really an int")
                finally:
                    logging.info(
                        "Appending %s (%s)", policy_value, type(policy_value)
                    )
                    policy_values_out.append(policy_value)

        logging.debug(
            "Current policy_values: %s length: %i",
            policy_values,
            len(policy_values),
        )

        # Change policy_values list to one item. If list is empty, use None.
        if not policy_values_out:
            policy_values = None
        elif len(policy_values_out) == 1:
            policy_values = policy_values_out[0]
        else:
            policy_values = policy_values_out.sort()
        logging.debug(
            "Current policy_values %s is %s",
            policy_values,
            type(policy_values),
        )

        # Ceate output list.
        # OPTIMIZE: combine code below with a list comprehention.
        logging.debug("row_dict: %s", row_dict)
        logging.debug("EXPORT_VALUES: %s", tuple(EXPORT_VALUES))
        to_csv = [row_dict[key] for key in EXPORT_VALUES]

        if isinstance(policy_values, list):
            policy_values = ",".join(policy_values).title()
        to_csv.insert(4, str(policy_values).title())

        logging.debug("Inintial to_csv: %s", to_csv)

        logging.info(
            "%s is %s where min: %s max: %s exact: %s",
            row_dict["user_key"],
            row_dict["type"],
            bool(row_dict["min_val"]),
            bool(row_dict["max_val"]),
            bool(row_dict["exact_val"]),
        )

        # Warn about type differences.
        # OPTIMIZE: Use isinstance. Use `in` statements with tuples.
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

        # WHAAAAAT? - comment not matching with if clause.
        # If no policy values are found and type is None, warn about it.
        if isinstance(row_dict["type"], type(None)) and policy_values is None:
            # Policy expected but not found.
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
        ):
            # If an exact value is requested, compare using exact values.
            logging.debug("In exact value")
            if row_dict["type"] == int:
                to_csv.append(int(policy_values) == int(row_dict["exact_val"]))

            elif row_dict["type"] == float:
                to_csv.append(
                    float(policy_values) == float(row_dict["exact_val"])
                )

            elif isinstance(row_dict["type"], type(None)):
                to_csv.append(not policy_values)

            elif row_dict["type"] == str:
                to_csv.append(policy_values == row_dict["exact_val"])

            # OPTIMIZE: Use isinstance.
            elif row_dict["type"] == list:
                # FIXME: Don't need to check. (?)
                try:
                    list_values["exact_val"]
                except KeyError:
                    raise ConfigError("Could not find any data in exact_val")

                # Convert to lists if nessesary.
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
        ):
            # If minimum value is requested, compare using minimum.
            # OPTIMIZE: First look for range, then min/max.
            logging.debug("In min value")
            logging.debug(
                "Type %s - value %s", row_dict["type"], policy_values
            )

            if row_dict["type"] == int:
                to_csv.append(int(policy_values) >= int(row_dict["min_val"]))

            elif row_dict["type"] == float:
                to_csv.append(
                    float(policy_values) >= float(row_dict["min_val"])
                )

            elif row_dict["type"] == list:
                try:
                    list_values["min_val"]
                except KeyError:
                    raise ConfigError("Could not find any data in min_val")

                # Convert to list if nessesary.
                # OPTIMIZE: use list()
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
        ):
            # If maximum value is requested, compare using maxmum.
            # OPTIMIZE: First look for range, then min/max.
            logging.debug("In max value")
            if row_dict["type"] == int:
                to_csv.append(int(policy_values) < int(row_dict["min_val"]))

            elif row_dict["type"] == float:
                to_csv.append(
                    float(policy_values) < float(row_dict["min_val"])
                )

            elif row_dict["type"] == list:
                try:
                    list_values["max_val"]
                except KeyError:
                    raise ConfigError("Could not find any data in max_val")

                # Convert to list if nessesary.
                # OPTIMIZE: use list()
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
        ):
            # If range value is requested, compare using range.
            # OPTIMIZE: First look for range, then min/max.
            # NOTE: Range is inclusive of max value! (note the +1)
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

                # Convert to list if nessesary.
                # OPTIMIZE: use list()
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

        # Ok. This is emparasing. rev_pos is not defined.
        # WHAAAAAT ?
        if negation:
            for rev_pos in range(len(to_csv) - 1, -1, -1):
                logging.debug(
                    f"Negation: rev_pos {rev_pos}, "
                    "to_csv[rev_pos] {to_csv[rev_pos]}"
                )

                if isinstance(to_csv[rev_pos], bool):
                    to_csv[rev_pos] = not to_csv[rev_pos]
                    break

        # Write to out CSV file.
        logging.info("Writing %s", to_csv)
        out_csv.writerow(to_csv)

        # WHAAAAAT? reverse list and iterate to find the compliance boolean?
        to_csv.reverse()
        for item in to_csv:
            if isinstance(item, bool):
                hash.update(bytes(str(item).lower(), "utf-8"))
                break

    # Add compliance hash.
    out_csv.writerow(["Compliance integrity:", hash.hexdigest().upper()])

# Change rights to read only.
logging.info("Changing %s to read_only", OUT_PATH)
os.chmod(OUT_PATH, stat.S_IRUSR)

# Clean up after yourself.
logging.info("Cleaning up")
if not args.no_generate_gpo:
    os.chmod(XML_PATH, stat.S_IWUSR)  # Need to allow writing to delete.
    os.remove(XML_PATH)
else:
    logging.warning("Did not clean up.")

logging.info("Exiting")
print("Done")

# File: xml_parse
# Author: Nicolas Fischer
# Program: Python 3.8
# Ext: py
# Licensed under GPU GPLv3 and later.
# -----------------------
import os
from xml.etree import ElementTree as ET

WORK_DIR = os.path.dirname(__file__)
XML_PATH = os.path.join(WORK_DIR, "output-local.xml")

xml_root = ET.parse("output-pg.xml").getroot()

STUPID_NAMESPACE = {
    "rsop" : "http://www.microsoft.com/GroupPolicy/Rsop",
    "settings" : "http://www.microsoft.com/GroupPolicy/Settings",
    "registry" : "http://www.microsoft.com/GroupPolicy/Settings/Registry",
    "security" : "http://www.microsoft.com/GroupPolicy/Settings/Security",
    "type" : "http://www.microsoft.com/GroupPolicy/Types"
}

# XML Notes
# q10: = Account policies
print("Read time:", xml_root.find("rsop:ReadTime", STUPID_NAMESPACE).text)

with open("xml-output.txt", "w+") as file:
    for extention_data in xml_root.findall("rsop:ComputerResults", STUPID_NAMESPACE):
        file.write(extention_data.tag.split("}")[-1]+"\n")
        for extention_name in extention_data.findall("rsop:ExtensionData", STUPID_NAMESPACE):
            file.write(" "+extention_name.tag.split("}")[-1]+"\n")
            for extention in extention_name.findall("settings:Extension", STUPID_NAMESPACE):
                file.write("  "+extention.tag.split("}")[-1]+"\n")
                for q10 in extention.findall("security:UserRightsAssignment", STUPID_NAMESPACE):
                    file.write("   "+q10.tag.split("}")[-1]+"\n")
                    for child1 in q10.findall("*"):
                        file.write("    "+child1.tag.split("}")[-1]+" "+child1.text+"\n")
                        for child2 in child1.findall("*"):
                            file.write("    "+child2.tag.split("}")[-1]+"\n")
                            for child3 in child2.findall("*"):
                                file.write("    "+child3.tag.split("}")[-1]+"\n")
                                for child4 in child3.findall("*"):
                                    file.write("    "+child4.tag.split("}")[-1]+"\n")

d = {}
for item in xml_root.findall("rsop:ComputerResults/rsop:ExtensionData/settings:Extension/security:UserRightsAssignment/*", STUPID_NAMESPACE):
    # print(item.tag)
    item_tag = item.tag.split("}")[-1]
    print(item_tag, end=": ", flush = True)
    if "Name" in item_tag:
        d_key = item.text
        print(d_key)
    elif "Setting" in item_tag:
        item_value = item.text
        tag_type_str = item_tag[len("Setting"):]

        if tag_type_str.lower().strip() == "number":
            item_value = int(item_value)
        elif tag_type_str.lower().strip() == "boolean":
            if item_value.title() == "True":
                item_value = True
            else:
                item_value = False

        d[d_key] = item_value
        d_key = None
    else: print()
print(d)
for key, value in d.items():
    print(key, value)

# Found in "rsop:ComputerResults/rsop:ExtensionData/settings:Extension/security:Account/"
# LockoutDuration 4294967295
# MaximumPasswordAge 180
# MinimumPasswordAge 0
# ResetLockoutCount 15
# LockoutBadCount 10
# PasswordHistorySize 8
# MinimumPasswordLength 8
# PasswordComplexity False
# ClearTextPassword False

from xml.etree import ElementTree as ET
xml_root = ET.parse("output-pg.xml").getroot()
STUPID_NAMESPACE = {
    "rsop" : "http://www.microsoft.com/GroupPolicy/Rsop",
    "settings" : "http://www.microsoft.com/GroupPolicy/Settings",
    "registry" : "http://www.microsoft.com/GroupPolicy/Settings/Registry",
    "security" : "http://www.microsoft.com/GroupPolicy/Settings/Security",
    "type" : "http://www.microsoft.com/GroupPolicy/Types"
}
next_is_value = False
for i in xml_root.findall("rsop:ComputerResults/rsop:ExtensionData/settings:Extension/security:SecurityOptions/security:*", STUPID_NAMESPACE):
    i_tag = i.tag.split("}")[-1]

    if "KeyName" in i_tag:
        next_is_value = True
        kn = (i_tag, i.text)
    elif "Display" in i_tag and next_is_value:
        j = i.find("security:Name", STUPID_NAMESPACE)
        print(j.tag.split("}")[-1]+":", j.text)
        print(" ", ": ".join(kn))
        next_is_value = False

# File:
# Author: Nicolas Fischer -program@licolas.net
# Program: Python 3.8
# Ext: py
# Licenced under GPU GLP v3. See LICENCE file for information.
# -----------------------

import os, xml, csv
from xml.etree import ElementTree as ET

def get_tag_name(tag):
    if isinstance(tag, xml.etree.ElementTree.Element):
        tag = tag.tag
    return tag.split("}")[-1]

def get_namespace(tag):
    global STUPID_NAMESPACE
    if isinstance(tag, xml.etree.ElementTree.Element):
        tag = tag.tag
    ns = tag.split("}")[0]
    ns = ns.split("{")[1]

    for key, value in STUPID_NAMESPACE.items():
        if value == ns:
            return key + ":" + get_tag_name(tag)

STUPID_NAMESPACE = {
    "rsop" : "http://www.microsoft.com/GroupPolicy/Rsop", # root
    "settings" : "http://www.microsoft.com/GroupPolicy/Settings", # root 2
    "type" : "http://www.microsoft.com/GroupPolicy/Types", # root 3
    "script" : "http://www.microsoft.com/GroupPolicy/Settings/Scripts", # q1 & q6
    "win-reg" : "http://www.microsoft.com/GroupPolicy/Settings/Windows/Registry", # q2 & q8
    "pub-key" : "http://www.microsoft.com/GroupPolicy/Settings/PublicKey", # q3 & q12
    "registry" : "http://www.microsoft.com/GroupPolicy/Settings/Registry", # q4 & q5 & q15 & q16
    "audit" : "http://www.microsoft.com/GroupPolicy/Settings/Auditing", # q7
    "file" : "http://www.microsoft.com/GroupPolicy/Settings/Files", # q9
    "security" : "http://www.microsoft.com/GroupPolicy/Settings/Security", # q10 & q11
    "eqos" : "http://www.microsoft.com/GroupPolicy/Settings/eqos", # q13
    "fw" : "http://www.microsoft.com/GroupPolicy/Settings/WindowsFirewall" # q14
}

WORK_DIR = os.path.dirname(__file__)
XML_PATH = os.path.join(WORK_DIR, "group-policy.xml")
OUT_PATH = os.path.join(WORK_DIR, "group-policy-keys-output2.log")
CSV_PATH = os.path.join(WORK_DIR, "group-policy-keys.csv")
GENERATION_COMMAND = 'gpresult /F /X "%s"'%XML_PATH

if not os.path.exists(XML_PATH):
    os.system(GENERATION_COMMAND)

xml_root = ET.parse(XML_PATH)
PATH = ["rsop:ComputerResults","rsop:ExtensionData"]
path = PATH.copy()
with open(CSV_PATH, "w+", newline = "") as file:
    csv_file = csv.writer(file, delimiter=",")
    for child1 in xml_root.findall("rsop:ComputerResults/rsop:ExtensionData/*", STUPID_NAMESPACE):
        child1_tag = get_tag_name(child1)

        for child2 in child1:
            child2_tag = get_tag_name(child2)
            path.append(get_namespace(child2.tag))
            out = ["/".join(path)]
            for child3 in child2:
                child3_tag = get_tag_name(child3)
                # path.append(get_namespace(child3.tag))
                # print(path)#, "/".join(path))
                for item in ("Display",):
                    if item.lower() in child3_tag.lower():
                        for child4 in child3:
                            child4_tag = get_tag_name(child4)
                            for item in ("Name", "Type"):
                                if item.lower() in child4_tag.lower():
                                    out.extend((child4_tag, child4.text))
                for item in ("Name", "Type"):
                    if item.lower() in child3_tag.lower():
                        out.extend((child3_tag, child3.text))

            if len(out) > 1:
                csv_file.writerow(out)
                # path = path[:-1]
            path = PATH.copy()

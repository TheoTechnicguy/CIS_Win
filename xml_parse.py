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

xml_root = ET.parse("output-local.xml").getroot()

NS = { # NameSpace
    "xmlns" : "http://www.microsoft.com/GroupPolicy/Rsop",
    "xmlns:xsd" : "http://www.w3.org/2001/XMLSchema",
    "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance"
}

print(xml_root.find("xmlns:ReadTime", NS).text)

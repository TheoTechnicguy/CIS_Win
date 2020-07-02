import os
from os import listdir
from os.path import isdir, isfile, islink

global indent, base_path, last_dir, file

version=1.2

indent = 0
count = 0
while True:
    usr_input = input('Paste or enter your BASE folder.\n > ')
    if os.path.exists(usr_input) and isdir(usr_input):
        base_path=usr_input#+'\\'
        break
    elif not path.exists(usr_input):
        print('This folder doesn\'t exist...')
    elif not isdir(usr_input):
        print('This isn\'t a folder.')

output_file=base_path+'/directory listing.txt'
print(base_path)
print('-'*len(output_file))

pols = []

def get_dir(path):
    global count, pols
    listed_dir = listdir(path)
    for item in listed_dir:
        item_path = os.path.join(path, item)
        count += 1
        if count == 1e99:
            input('Safety lock. Press enter to continue.')
            count = 0
        if isdir(item_path):
            get_dir(item_path)
        elif isfile(item_path) and item.endswith(".pol"):
            print(item_path)
            pols.append(item_path)

get_dir(base_path)
print(pols)

for pol in pols:
    if "User" in pol.split("\\")[-2]:
        arg = "/u"
    elif "Machine" in pol.split("\\")[-2]:
        arg = "/m"
    os.system("LGPO /parse %s %s"%(arg, pol))

print("Done")
input()

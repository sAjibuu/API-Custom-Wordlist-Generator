import xml.etree.ElementTree as ET
import urllib.parse
import base64
import math
import sys
import re
import os
import re
import subprocess

# Usage: Open Burp, navigate to proxy history, ctrl-a to select all records, right click and "Save Items" as an .xml file.
# python Custom-Wordlist.py burprequests.xml
# Output is saved to wordlist.txt
#!/usr/bin/env python3

def cleaning():
    regexes = [
        r".{100,}", # Ignore lines with more than 100 characters (overly specific)
        r"[0-9]{4,}", # Ignore lines with 4 or more consecutive digits (likely an id)
        r"[0-9]{3,}$", # Ignore lines where the last 3 or more characters are digits (likely an id)
        r"[a-z0-9]{32}", # Likely MD5 hash or similar
        r"[0-9]+[A-Z0-9]{5,}", # Number followed by 5 or more numbers and uppercase letters (almost all noise)
        r"\/.*\/.*\/.*\/.*\/.*\/.*\/", # Ignore lines more than 6 directories deep (overly specific)
        r"\w{8}-\w{4}-\w{4}-\w{4}-\w{12}", # Ignore UUIDs
        r"[0-9]+[a-zA-Z]+[0-9]+[a-zA-Z]+[0-9]+", # Ignore multiple numbers and letters mixed together (likely noise)
        r"\.(png|jpg|jpeg|gif|svg|bmp|ttf|avif|wav|mp4|aac|ajax|css|all)$", # Ignore low value filetypes
        r"^$" # Ignores blank lines
    ]

    wordlist = "wordlist.txt"
    print("[+] Cleaning {}".format(wordlist))

    # Read input file
    with open(wordlist, "r") as f:
        lines = f.readlines()

    original_size = len(lines)

    # Apply regexes to remove lines
    for regex in regexes:
        lines = [line for line in lines if not re.search(regex, line)]

    # Remove lines starting with digits
    lines = [line for line in lines if not re.search(r"^[0-9]", line)]

    # Sort and remove duplicates
    lines = sorted(set(lines))

    # Remove empty lines
    lines = [line for line in lines if line.strip()]

    # Write output file
    output_file = "{}_cleaned".format(wordlist)
    with open(output_file, "w") as f:
        f.writelines(lines)

    # Calculate changes
    new_size = len(lines)
    removed = original_size - new_size

    print("[-] Removed {} lines".format(removed))
    print("[+] Wordlist is now {} lines".format(new_size))
    print("[+] Done")
    print("[+] Removing old wordlist file")
    os.remove("wordlist.txt")
    os.rename("wordlist.txt_cleaned", "wordlist.txt")

    
def entropy(string):
    #"Calculates the Shannon entropy of a string"
    # get probability of chars in string
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]

    # calculate the entropy
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])

    return entropy

def avgEntropyByChar(en, length):
    # calulate "average" entropy level
    return en / length


tree = ET.parse(sys.argv[1])
root = tree.getroot()
wordlist = []

for i in root:

    # preserve subdomains, file/dir names with . - _
    wordlist += re.split('\/|\?|&|=', i[1].text)

    # get subdomain names and break up file names
    wordlist += re.split('\/|\?|&|=|_|-|\.|\+', i[1].text)

    # get words from cookies, headers, POST body requests
    wordlist += re.split('\/|\?|&|=|_|-|\.|\+|\:| |\n|\r|"|\'|<|>|{|}|\[|\]|`|~|\!|@|#|\$|;|,|\(|\)|\*|\|', urllib.parse.unquote(base64.b64decode(i[8].text)))

    # response
    if i[12].text is not None:
        wordlist += re.split('\/|\?|&|=|_|-|\.|\+|\:| |\n|\r|\t|"|\'|<|>|{|}|\[|\]|`|~|\!|@|#|\$|;|,|\(|\)|\*|\^|\\\\|\|', urllib.parse.unquote(base64.b64decode(i[12].text)))

auxiliaryList = list(set(wordlist))
final = []
avgEntropyByLength = {}

for word in auxiliaryList:
    if word.isalnum() or '-' in word or '.' in word or '_' in word:
        en = entropy(word)
        # remove "random strings" that are high entropy
        if en < 4.4:
            final.append(word)

final.sort()

with open('wordlist.txt', 'w') as f:
    for item in final:
        f.write("%s\n" % item)


print("Wordlist saved to wordlist.txt")
print("Cleaning Wordlist and saving it as wordlist.txt_cleaned")
cleaning()

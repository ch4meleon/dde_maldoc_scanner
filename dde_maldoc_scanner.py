#!/usr/bin/python

# DDE Maldoc Scanner
# By Ch4meleon
#

import os
import sys
import zipfile
import logging
import re
from optparse import OptionParser
from glob import glob


logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__file__)


# All strings in lowercase
BLACKLIST_STRINGS = [
"powershell",
"dde",
"cmd",
"exe",
"hidden",
"new-object system.net.webclient",
"downloadstring",
"-nop -sta -noni"
]

def analyze_document_xml(filename):
    try:
        fh = open(filename, 'rb')

        doc_file = zipfile.ZipFile(fh)

        d = {name.lower(): doc_file.read(name) for name in doc_file.namelist()}

        if "word/document.xml" in d.keys():
            doc_xml_content = d['word/document.xml']

            """ Find anything between <w:instrText>...</w:instrText> """
            REGEX_PATTERN = "<w:instrText.*?>(.*?)</w:instrText>"

            log.info("[+] Found string(s):")

            found = False
            is_malicious = False

            m = re.findall(REGEX_PATTERN, doc_xml_content, re.MULTILINE | re.DOTALL)
            for n in m:
                line = n.strip()
                if line != "":
                    print "\t",line
                    found = True

                    if line in BLACKLIST_STRINGS:
                        is_malicious = True

            if found == False:
                log.info("[-] No string was found.")

            if is_malicious == True:
                log.info("[+] Found malicious strings!")
            else:
                log.info("[-] No malicious string was found")

            # Empty line
            log.info("")

        else:
            print "ERROR: Unable to find document.xml in the input filename!\n"
            sys.exit(-1)

        fh.close()

    except zipfile.BadZipfile:
        print "ERROR: Not a Microsoft Word Document!\n"
        sys.exit(-1)


if __name__ == '__main__':
    parser = OptionParser(usage="usage: %prog -f malicious_dde.doc", version="%prog 1.0")
    
    parser.add_option("-f", "--filename",
                      action="store",
                      dest="file_to_scan",
                      default="",
                      help="Scan a file.",)

    parser.add_option("-d", "--directory",
                      action="store",
                      dest="dir_to_scan",
                      default="",
                      help="Scan a directory.",)

    (options, args) = parser.parse_args()

    file_to_scan = options.file_to_scan
    dir_to_scan = options.dir_to_scan

    if (file_to_scan == "") and (dir_to_scan == ""):
        parser.error("Wrong number of arguments. Need either -f or -d.")

    log.info("DDE Maldoc Scanner v0.1")
    log.info("[*] Scanning file (%s)..." % file_to_scan)

    if (file_to_scan != "") and (dir_to_scan == ""):
        analyze_document_xml(file_to_scan)
    else:
        files = glob(dir_to_scan + ".doc")
        for file in files:
            print file


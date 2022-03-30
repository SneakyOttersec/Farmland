import json
import subprocess
import xml.etree.ElementTree as ET
import shutil
import os
from Modules.utils import *

def exec_massscan_nmap(data_stage1,args):
    data_to_ip(data_stage1)
    # TODO : Arg massscan and nmap
    answer_masscan = args.skip
    anwser_nmap = args.skip
    if args.masscan:
        if os.path.exists(args.outputdir + args.domain + "/Raw/" + args.domain + "_massscan.json"):
            print("[+] The masscan output seems to exist. Do you want do skip this step ? [y/n]")
            if not answer_masscan:
                answer_masscan = input()
        else:
            answer_masscan = "doesnotexist"
        if answer_masscan != "y":
            masscan = subprocess.Popen(("./Resources/Binary/masscan","-iL","tmp_ip.txt",
                                 "-p1-10000","--rate","10000","-oJ",args.outputdir  + args.domain + "/Raw/" + args.domain + "_massscan.json"))

            masscan.communicate()
            if not os.path.exists(args.outputdir + args.domain + "/Formatted/" + args.domain + "_massscan.json"):
                convert_massscan_json(args)

    if args.nmap:
        if os.path.exists(args.outputdir + args.domain + "/Raw/" + args.domain + "_nmap.xml"):
            print("[+] The nmap output seems to exist. Do you want do skip this step ? [y/n]")
            if not anwser_nmap:
                anwser_nmap = input()
        else:
            anwser_nmap ="doesnotexist"
        if anwser_nmap != "y":
            nmap = subprocess.Popen(("./Resources/Binary/nmap","--top-port","100","-iL", "tmp_ip.txt",
                                "-oX", args.outputdir  + args.domain + "/Raw/" + args.domain + "_nmap.xml"))

            nmap.communicate()
        if not os.path.exists(args.outputdir + args.domain + "/Formatted/" + args.domain + "_nmap.json"):
            convert_nmap_json(args)
    # Remove the temp ip file
    if os.path.exists("tmp_ip.txt"):
        os.remove("tmp_ip.txt")
    return True

def convert_massscan_json(args):
    # 1  We need to make the tuple into a 3d list
    # [domain , ip[], ports[]]
    ## Thus we need to iterate it ...
    if os.path.exists(args.outputdir + args.domain + "/Raw/" + args.domain + "_massscan.json"):
        shutil.copy(args.outputdir + args.domain + "/Raw/" + args.domain + "_massscan.json",args.outputdir  + args.domain + "/Formatted/" + args.domain + "_massscan.json")
    else:
        print("[!] Error while trying to format the raw masscan output to a json format. Most likely due to a missing file.")
    return True

def convert_nmap_json(args):
    print("[++] Converting nmap output to JSON")
    tree = ET.parse(args.outputdir + args.domain + "/Raw/" + args.domain + "_nmap.xml")
    root = tree.getroot()
    g_data = []
    for child in root.findall("host"):
        # For each host let's find the address and ALL the open ports
        open_ports = []
        addr = child.find("address").get("addr")
        for port in child.find("ports").findall("port"):
            open_ports.append(port.get("portid"))

        g_data.append([addr,open_ports])
        with open(args.outputdir + args.domain + "/Formatted/" + args.domain + "_nmap.json","w") as f_json:
            json.dump(g_data,f_json)
    return True



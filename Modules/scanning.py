import json
import subprocess
import xml.etree.ElementTree as ET
import shutil
import os

def exec_massscan_nmap(ip_list,args):
    with open("tmp_ip.txt","w") as f:
        for ip in ip_list:
            f.write(ip[1] + "\n")
    # TODO : Arg massscan and nmap
    answer_masscan = "n"
    anwser_nmap = "n"
    if args.masscan:
        if os.path.exists(args.outputdir + "Raw/" + args.domain + "_massscan.json"):
            print("[+] The masscan output seems to exist. Do you want do skip this step ? [y/n]")
            answer_masscan = input()
        if answer_masscan != "y":
            masscan = subprocess.Popen(("./Resources/Binary/masscan","-iL","tmp_ip.txt",
                                 "-p1-10000","--rate","10000","-oJ",args.outputdir + "Raw/" + args.domain + "_massscan.json"))

            masscan.communicate()
            if not os.path.exists(args.outputdir + "Formatted/" + args.domain + "_massscan.json"):
                convert_massscan_json(args)
    if args.nmap:
        if os.path.exists(args.outputdir + "Raw/" + args.domain + "_nmap.xml"):
            print("[+] The nmap output seems to exist. Do you want do skip this step ? [y/n]")
            anwser_nmap = input()
        if anwser_nmap != "y":
            nmap = subprocess.Popen(("./Resources/Binary/nmap","--top-port","100","-iL", "tmp_ip.txt",
                                "-oX", args.outputdir + "Raw/" + args.domain + "_nmap.xml"))

            nmap.communicate()
        if not os.path.exists(args.outputdir + "Formatted/" + args.domain + "_nmap.json"):
            convert_nmap_json(args)
    # Remove the temp ip file
    if os.path.exists("tmp_ip.txt"):
        os.remove("tmp_ip.txt")
    return True

def convert_massscan_json(args):
    # 1  We need to make the tuple into a 3d list
    # [domain , ip[], ports[]]
    ## Thus we need to iterate it ...
    shutil.copy(args.outputdir + "Raw/" + args.domain + "_massscan.json",args.outputdir + "Formatted/" + args.domain + "_massscan.json")
    return True

def convert_nmap_json(args):
    print("[++] Converting nmap output to JSON")
    tree = ET.parse(args.outputdir +"Raw/" + args.domain + "_nmap.xml")
    root = tree.getroot()
    g_data = []
    for child in root.findall("host"):
        # For each host let's find the address and ALL the open ports
        open_ports = []
        addr = child.find("address").get("addr")
        for port in child.find("ports").findall("port"):
            open_ports.append(port.get("portid"))

        g_data.append([addr,open_ports])
        with open(args.outputdir + "Formatted/" + args.domain + "_nmap.json","w") as f_json:
            json.dump(g_data,f_json)
    return True



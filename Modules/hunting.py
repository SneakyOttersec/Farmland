import json
import os.path
import subprocess
import socket

def exec_base_domain(args):
    """
    FUnction to return the resolved ip addr of the base domain
    Include a connectivity check.
    :param args:
    :return: True
    """
    try:
        resolvedip = socket.gethostbyname_ex(args.domain)
        return (resolvedip[0], resolvedip[2])
    except socket.gaierror:
        print("[!] Error : Seems like you do not have a proper nameserver/internet connection. Aborting.")
        exit()
    except:
        print("[!] Error : Unknown error. Aborting")
        exit()
    return True

def exec_massdns_subbbrute(args):
    """
    Function to execute the Massdns binary in order to perform a proper subdomain bruteforce
    :param args: domain and output dir will be used. The domain is both used as the target (to generate the list) and part of the outputed filename
    :return: True
    """
    answer_sublist = args.skip
    answer_massdns = args.skip

    print("[+] Generating the sub domain list associated with the domain")
    if os.path.exists("Resources/Wordlists/"+ args.domain + "_fulldomain.txt"):
        print("[+] The subdomain list seems to exist. Do you want do skip this step ? [y/n]")
        if not args.skip:
            answer_sublist = input()
    else:
        answer_sublist = "doesnotexist"
    if answer_sublist != "y":
        with open("Resources/Wordlists/" + args.domain + "_fulldomain.txt", "w") as f_fulldomain:
            subbrute = subprocess.Popen(("python3", "./Resources/Scripts/subbrute.py", args.massdns_wordlist, args.domain),
                                        stdout=f_fulldomain)
        subbrute.communicate()
    if os.path.exists(args.outputdir + args.domain + "/Raw/" + args.domain +"_massdns_output.txt"):
        print("[+] The massdns output seems to exist. Do you want do skip this step ? [y/n]")
        if not answer_sublist:
            answer_massdns = input()
    else:
        answer_massdns = "doesnotexist"
    if answer_massdns != "y":
        print("[+] Launching massdns ...")
        massdns = subprocess.Popen(("./Resources/Binary/massdns", "-l", "./Logs/" + args.domain + "_massdns_eror.log",
                                    "-s", args.massdns_rate, "-o", "S", "-r"
                                    , "./Resources/Wordlists/resolvers.txt", "-w",
                                    args.outputdir + args.domain + "/Raw/" + args.domain + "_massdns_output.txt",
                                    "./Resources/Wordlists/" + args.domain + "_fulldomain.txt"),
                                   stdout=subprocess.DEVNULL)
        massdns.wait()
        print("[+] Massdns scan finished.")
        # TODO : Maybe hide what massdns is doing ?

    if not os.path.exists(args.outputdir + args.domain + "/Formatted/" + args.domain + "_massdns_output.json"):
        convert_massdns_raw_to_json(args)
    return True

def exec_dnsrecon(args):
    """
    Function to execute dnsrecon in order to parse the crt.sh website.
    :param args: domain and output dir will be used. The domain is both used as the target and part of the outputed filename
    Custom / Default output dir for all of our files
    :return: True
    """
    # Check if we already have a DNSRecon output AND that is not empty
    answer_dnsrecon = args.skip
    if os.path.exists(args.outputdir + args.domain + "/Raw/" + args.domain + "_dnsrecon_crt.raw"):
        if os.path.getsize(args.outputdir + args.domain + "/Raw/" + args.domain + "_dnsrecon_crt.raw") > 0:
            print("[+] The DNSRecon output seems to exist. Do you want do skip this step ? [y/n]")
            if not args.skip:
                answer_dnsrecon = input()
    else:
        answer_dnsrecon = "doesnotexist"
    if answer_dnsrecon != "y":
        with open(args.outputdir + args.domain + "/Raw/" + args.domain + "_dnsrecon_crt.raw","w") as dnsrecon_output:
            print("[+] Launching DNSRecon ... ")
            dnsrecon_args = "crt"
            if args.dnsrecon_bing == True:
                print("   [+] DNSRecon Bing search enabled")
                dnsrecon_args += ",bing"
            if args.dnsrecon_std == True:
                print("   [+] DNSRecon Std search enabled")
                dnsrecon_args += ",std"
            try:
                crt = subprocess.Popen(("python3","./Resources/Scripts/dnsrecon/dnsrecon.py","-t",dnsrecon_args,"-d",args.domain,"-n","8.8.8.8"),stdout=dnsrecon_output,stderr=None)
                crt.communicate()
            except:
                print("[!] Unknown error while running dnsrecon")

    convert_crt_raw_json(args)
    return True

def convert_crt_raw_json(args):
    """
    Will parse the raw output of crt in order to extract the A record with the domain / IP
    May include the AAA/MX record ?
    :param args: farmland args
    :return:
    """
    crt_json = []
    with open(args.outputdir + args.domain + "/Raw/" + args.domain + "_dnsrecon_crt.raw","r") as f_in, \
        open(args.outputdir + args.domain + "/Formatted/" + args.domain + "_dnsrecon_crt.json","w") as f_out:
        data = f_in.readlines()
        for entry in data:
            try:
                if " A " in entry:
                    splitted_entry = entry.split(" A ")[1].split(" ")
                    crt_json.append([splitted_entry[0].rstrip(),splitted_entry[1].rstrip()])
            except:
                print("[!] Error : Could not parse the dnsrecon raw file. Continuing without the dnsrecon data.")
                exit()
        try:
            json.dump(crt_json, f_out)
        except:
            print("[!] Error : Could not dump the dnrecon data into a json file. Continuing whithout the dnsrecon data.")
    return True

def convert_massdns_raw_to_json(args):
    """
    Function to convert the raw output of massdns to a properly formatted json.
    :param domain: domain nam which will be part of the filename
    :param outputdir: Custom / Default output dir for all of our files
    :return: True
    """
    massdns_json = []
    print("[+] Converting the raw output of massdns to the json format")
    try:
        with open(args.outputdir + args.domain + "/Raw/" + args.domain + "_massdns_output.txt","r") as f_raw,open(args.outputdir + args.domain + "/Formatted/" + args.domain + "_massdns_output.json","w") as f_json:
            for line in f_raw:
                if line.split(" ")[1] == "A":
                    massdns_json.append([line.split(" ")[0].rstrip(".").rstrip(),line.split(" ")[2].rstrip(".").rstrip()])
            json.dump(massdns_json,f_json)
        print("[+] Done converting.")
    except:
        print("[!] Error while converting the massdns raw output to a json while. Continuing whithout the massdns data.")
    return True

# This function should be useless from version 1.1
def convert_crt_json_json(args):
    """
    Function to convert the raw output of dnsrecon to a properly formatted json.
    :param domain: domain nam which will be part of the filename
    :param outputdir: Custom / Default output dir for all of our files
    :return: True
    """
    crt_json = []
    print("[+] Converting the raw output of dnsrecon to the json format")
    with open(args.outputdir + args.domain + "/Formatted/" + args.domain + "_dnsrecon_crt.json","w") as f_json,open(args.outputdir + args.domain + "/Raw/" + args.domain + "_dnsrecon_crt.json") as f_raw:
        data = json.load(f_raw)
        for entry in data[1:]:
            if entry["type"] == "A":
                crt_json.append([entry['name'],entry['address']])
            elif entry["type"] == "MX":
                crt_json.append([entry['domain'], entry['address']])
        json.dump(crt_json,f_json)
    print("[+] Done converting.")
    return True
import json
import os.path
import subprocess
import socket

def exec_base_domain(args):
    """
    FUnction to return the resolved ip addr of the base domain
    :param args:
    :return:
    """
    data = socket.gethostbyname_ex(args.domain)
    return (data[0],data[2])

def exec_massdns_subbbrute(args):
    """
    Function to execute the Massdns binary in order to perform a proper subdomain bruteforce
    :param args: domain and output dir will be used. The domain is both used as the target (to generate the list) and part of the outputed filename
    :return: True
    """
    answer_sublist = "n"
    answer_massdns = "n"

    print("[+] Generating the sub domain list associated with the domain")
    if os.path.exists("Resources/Wordlists/"+ args.domain + "_fulldomain.txt"):
        print("[+] The subdomain list seems to exist. Do you want do skip this step ? [y/n]")
        answer_sublist = input()
    if answer_sublist != "y":
        with open("Resources/Wordlists/" + args.domain + "_fulldomain.txt", "w") as f_fulldomain:
            subbrute = subprocess.Popen(("python3", "./Resources/Scripts/subbrute.py", args.wordlist, args.domain),
                                        stdout=f_fulldomain)
        subbrute.communicate()
    if os.path.exists(args.outputdir + args.domain + "/Raw/" + args.domain +"_massdns_output.txt"):
        print("[+] The massdns output seems to exist. Do you want do skip this step ? [y/n]")
        answer_massdns = input()
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

def exec_crt_sh(args):
    """
    Function to execute dnsrecon in order to parse the crt.sh website.
    :param args: domain and output dir will be used. The domain is both used as the target and part of the outputed filename
    Custom / Default output dir for all of our files
    :return: True
    """
    # TODO : dnsrecon has trouble to output as csv, thus we are using the xml one.
    answer_crt = "n"
    print("[+] Search through the certificate transprency logs (e.g : crt.sh)")
    if os.path.exists(args.outputdir + args.domain + "/Raw/" + args.domain + "_dnsrecon_crt.json"):
        print("[+] The crt output seems to exist. Do you want do skip this step ? [y/n]")
        answer_crt = input()
    if answer_crt == "n":
        crt = subprocess.Popen(("python3","./Resources/Scripts/dnsrecon/dnsrecon.py","-t","std,crt,bing","-d",args.domain,"-j",args.outputdir + args.domain + "/Raw/" + args.domain + "_dnsrecon_crt.json"),stdout=subprocess.DEVNULL)
        crt.communicate()
        if crt.stderr:
            print("ERROR ERROR ")
            print(crt.stderr)
        print("[+] Certificate transprency searching finished.")

    #if os.path.exists(args.outputdir + args.domain + "/Formatted/" + args.domain + "_dnsrecon_crt.json"):
    #    pass
    #else:
    #    print("here")
    convert_crt_raw_json(args.domain,args)
    return True

def convert_crt_raw_json(domain,args):
    """
    Function to convert the raw output of dnsrecon to a properly formatted json.
    :param domain: domain nam which will be part of the filename
    :param outputdir: Custom / Default output dir for all of our files
    :return: True
    """
    crt_json = []
    print("[+] Converting the raw output of dnsrecon to the json format")
    with open(args.outputdir + args.domain + "/Formatted/" + domain + "_dnsrecon_crt.json","w") as f_json,open(args.outputdir + args.domain + "/Raw/" + domain + "_dnsrecon_crt.json") as f_raw:
        data = json.load(f_raw)
        for entry in data[1:]:
            if entry["type"] == "A":
                crt_json.append([entry['name'],entry['address']])
            elif entry["type"] == "MX":
                crt_json.append([entry['domain'], entry['address']])
        json.dump(crt_json,f_json)
    print("[+] Done converting.")
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
    with open(args.outputdir + args.domain + "/Raw/" + args.domain + "_massdns_output.txt","r") as f_raw,open(args.outputdir + args.domain + "/Formatted/" + args.domain + "_massdns_output.json","w") as f_json:
        for line in f_raw:
            if line.split(" ")[1] == "A":
                massdns_json.append([line.split(" ")[0].rstrip(".").rstrip(),line.split(" ")[2].rstrip(".").rstrip()])
        json.dump(massdns_json,f_json)
    print("[+] Done converting.")
    return True
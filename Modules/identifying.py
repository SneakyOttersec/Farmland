import subprocess
import os
import json
from Modules.utils import *

def exec_intrigue(address_data_list,args):
    #TODO : Read from file is broken ... What should we do ?
    #TODO : Associate the port <-> protocol for intrigue to work
    #1. Ignore the tool
    #2. Iterate over our URLs but this may be quite long
    print("   [+] Launching intrigue ..")
    data_to_urls(address_data_list)
    print("Intrigue : WIP")
    #with open("tmp_urls.txt") as f:
    #    urls = f.readlines()
    #with open(args.outputdir + args.domain + "/Formatted/intrigue_" + args.domain + ".json", "a") as output:
        #os.chdir("./Resources/Binary/intrigue-ident")
        #print(os.getcwd())
        # BETA : To improve
        #for url in urls:
        #       cmd = "bundle exec ruby ./util/ident.rb -u https://" + url + " --json -n"
        #        os.system(cmd)
    #if os.path.exists("tmp_urls.txt"):
    #    os.remove("tmp_urls.txt")
    #os.chdir("../../../")
    print("   [+] intrigue scan done !")
    return

def exec_nrich(s2_address_data_list,args):

    data_to_ip(s2_address_data_list)
    answer_nrich = args.skip
    if os.path.exists(args.outputdir  + args.domain + "/Formatted/nrich_" + args.domain + ".json"):
        print("[+] The nrich output seems to exist. Do you want do skip this step ? [y/n]")
        if not answer_nrich:
            answer_nrich = input()
    else:
        answer_nrich = "doesnotexist"
    if answer_nrich != "y":
        with open(args.outputdir  + args.domain + "/Formatted/nrich_" + args.domain + ".json","w") as output:
            print("   [+] Launching nrich ..")
            nrich = subprocess.Popen(("nrich", "tmp_ip.txt","--output","json"),stdout=output)
            nrich.communicate()
        if os.path.exists("tmp_ip.txt"):
            os.remove("tmp_ip.txt")
        print("   [+] nrich passive scan done !")
    return True

def exec_eyewitness(address_data_list,args):
    # TODO : We may need to add some intelligence somewhere in order to determine if the targeted port is an http server or not ?
    # TODO : Fix WebDriver error
    data_to_urls(address_data_list)
    answer_eyewitness = args.skip
    if os.path.exists(args.outputdir + args.domain + "/Eyewitness"):
        print("[+] The Eyewitness output seems to exist. Do you want do skip this step ? [y/n]")
        if not answer_eyewitness:
            answer_eyewitness = input()
    else:
        answer_nrich = "doesnotexist"
    if answer_eyewitness != "y":
        print("   [+] Launching eyewitness ..")
        if args.eyewitness_full == True:
            urls_file = "tmp_urls_full.txt"
        else:
            urls_file = "tmp_urls.txt"
        masscan = subprocess.Popen(("./Resources/Scripts/EyeWitness/Python/EyeWitness.py", "-f",
                                    urls_file,"--no-prompt","-d",args.outputdir +
                                    args.domain + "/Eyewitness" ))
        masscan.communicate()
        if os.path.exists("tmp_urls.txt"):
            os.remove("tmp_urls.txt")
        if os.path.exists("tmp_urls_full.txt"):
            os.remove("tmp_urls_full.txt")
    return True
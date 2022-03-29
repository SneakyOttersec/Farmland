import subprocess
import os
import json
from Modules.utils import *

def exec_intrigue(address_data_list,args):
    #TODO : Read from file is broken ... What should we do ?
    #1. Ignore the tool
    #2. Iterate over our URLs but this may be quite long
    print("   [+] Launching intrigue ..")
    data_to_urls(address_data_list)
    #with open(args.outputdir + args.domain + "/Formatted/intrigue_" + args.domain + ".json", "w") as output:
    #    intrigue = subprocess.Popen(("bundle exec ruby ./Resources/Binary/intrigue-ident/util/ident.rb", "-f", "tmp_urls.txt","-j","-n"),stdout=output)
    #    intrigue.communicate()
    #if os.path.exists("tmp_urls.txt"):
    #    os.remove("tmp_urls.txt")
    print("   [+] intrigue scan done !")
    return

def exec_nrich(address_data_list,args):
    print("   [+] Launching nrich ..")
    data_to_ip(address_data_list)
    with open(args.outputdir  + args.domain + "/Formatted/nrich_" + args.domain + ".json","w") as output:
        nrich = subprocess.Popen(("nrich", "tmp_ip.txt","--output","json"),stdout=output)
        nrich.communicate()
    if os.path.exists("tmp_ip.txt"):
        os.remove("tmp_ip.txt")
    print("   [+] nrich passive scan done !")
    return True

def exec_eyewitness(address_data_list,args):
    # TODO : We may need to add some intelligence somewhere in order to determine if the targeted port is an http server or not ?
    # TODO : Fix WebDriver error
    print("   [+] Launching eyewitness ..")
    data_to_urls(address_data_list)
    answer_eyewitness = "n"
    if os.path.exists(args.outputdir + args.domain + "/Eyewitness"):
        print("[+] The Eyewitness output seems to exist. Do you want do skip this step ? [y/n]")
        answer_eyewitness = input()
    if answer_eyewitness != "y":
        masscan = subprocess.Popen(("/home/pridwen/Tools/EyeWitness/Python/EyeWitness.py", "-f",
                                    "tmp_urls.txt","--no-prompt","-d",args.outputdir +
                                    args.domain + "/Eyewitness" ))
        masscan.communicate()
        if os.path.exists("tmp_urls.txt"):
            os.remove("tmp_urls.txt")
    return True
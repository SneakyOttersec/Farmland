import subprocess
import os
import json

def exec_intrigue(address_data_list,args):
    print("TODO : Exec intrigue")
    return

def exec_nrich(address_data_list,args):
    print("   [+] Launching nrich ..")
    with open("tmp_ip.txt", "w") as f:
        for addr in address_data_list:
            f.write(addr.ipAddress + "\n")
    with open(args.outputdir + "Formatted/nrich_" + args.domain + ".json","w") as output:
        nrich = subprocess.Popen(("nrich", "tmp_ip.txt","--output","json"),stdout=output)
        nrich.communicate()
    if os.path.exists("tmp_ip.txt"):
        os.remove("tmp_ip.txt")
    print("   [+] nrich passive scan done !")
    return True

def exec_eyewitness(address_data_list,args):
    # TODO : We may need to add some intelligence somewhere in order to determine if the targeted port is an http server or not ?
    # TODO : Fix WebDriver error
    known_https_ports = ['80','443','8443','8080','8888']
    if args.eyewitness_full:
        with open("temp_url_eyewitness.txt","w+") as f_temp:
            for entry in address_data_list:
                for domain in entry.domains:
                    for port in known_https_ports:
                        if port in entry.ipPorts:
                            f_temp.write(entry.ipAddress + ":" + port + "\n")
                            f_temp.write(domain + ":" + port + "\n")
    else:
        with open("temp_url_eyewitness.txt","w+") as f_temp:
            for entry in address_data_list:
                f_temp.write(entry.ipAddress + ":443" + "\n")
                for domain in entry.domains:
                    f_temp.write(domain + ":443" +"\n")

    #masscan = subprocess.Popen(("/home/pridwen/Tools/EyeWitness/Python/EyeWitness.py", "-f","tmp-urls.txt"))
    #masscan.communicate()
    return True
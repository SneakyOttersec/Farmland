import json
import xlsxwriter

class AddressData():
    ipAddress = ""
    ipPorts = []
    domains = []
    cpes = []
    vulns = []
    tags = []
    def __init__(self,domain,ipAddress):
        self.ipAddress = ipAddress
        self.domains = domain

def data_to_urls(data,file_name="tmp_urls.txt"):
    known_https_ports = ['80', '443', '8443', '8080', '8888']
    with open(file_name, "w+") as f_temp:
        for entry in data:
            if isinstance(entry.domains, list):
                for domain in entry.domains:
                    for port in known_https_ports:
                        if not entry.ipPorts:
                            f_temp.write(domain + "\n")
                            break
                        elif port in entry.ipPorts:
                            f_temp.write(entry.ipAddress + ":" + port + "\n")
                            f_temp.write(domain + ":" + port + "\n")
            else:
                for port in known_https_ports:
                    if not entry.ipPorts:
                        f_temp.write(entry.domains + "\n")
                        break
                    elif port in entry.ipPorts:
                        f_temp.write(entry.ipAddress + ":" + port + "\n")
                        f_temp.write(entry.domains + ":" + port + "\n")
    return
def data_to_ip(data,file_name="tmp_ip.txt"):
    with open(file_name, "w") as f:
        for addr in data:
            f.write(addr.ipAddress + "\n")
    return

# TODO : Add check for empty json
def agregate_data_stage1(args,base_domain):

    """
    Agregate the data of massscan and dnsrecon
    :param domain:
    :param outputdir:
    :return:
    """
    if args.massdns and args.crt :
        with open(args.outputdir + args.domain + "/Formatted/" + args.domain + "_dnsrecon_crt.json" ) as f1, open(args.outputdir + args.domain + "/Formatted/" + args.domain + "_massdns_output.json") as f2:
            data1 = json.load(f1)
            data2 = json.load(f2)
            g_data = sorted(data1 + data2, key=lambda x: x[0], reverse=False)
    if args.massdns and not args.crt:
        with open(args.outputdir + args.domain + "/Formatted/" + args.domain + "_massdns_output.json") as f2:
            data2 = json.load(f2)
            g_data = sorted(data2,key=lambda x:x[0],reverse=False)
    if not args.massdns and args.crt :
        with open(args.outputdir + args.domain + "/Formatted/" + args.domain + "_dnsrecon_crt.json") as f1:
            data1 = json.load(f1)
            g_data = sorted(data1 , key=lambda x: x[0], reverse=False)

    dup = set()
    new_g_data = []
    for entry in base_domain[1]:
        g_data.append((base_domain[0],entry))
    for data in g_data:
        t = tuple(data)
        if t not in dup:
            new_g_data.append(t)
            dup.add(t)
    return new_g_data

def agregate_data_stage2(ip_list,args):
    """
    Agregate the data of nmap and masscan with the associated domain.
    :param domain:
    :param Outputdir:
    :return:
    """
    listipmetdata = []
    masscan_json = args.outputdir  + args.domain + "/Formatted/" + args.domain + "_massscan.json"
    nmap_json = args.outputdir  + args.domain + "/Formatted/" + args.domain + "_nmap.json"
    if args.masscan and args.nmap:
        with open(masscan_json,"r") as fmassscan_json,open(nmap_json,"r") as fnmap_json:
            data_masscan = json.load(fmassscan_json)
            data_nmap = json.load(fnmap_json)
            for entry in ip_list:
                # We add our IP Addr and the associated domain
                tmpAddressData = AddressData(entry[0],entry[1])
                listipmetdata.append(tmpAddressData)
                portlist = []

                # We now have to iterate over our list to find the open ports asssociated with our IP Addr in massscan.
                for mdata in data_masscan:
                    if mdata["ip"] == entry[1]:
                        # Check for dup
                        if mdata["ports"][0]["port"] not in portlist:
                            portlist.append(str(mdata["ports"][0]["port"]))

                # We now have to iterate over our list to find the open ports asssociated with our IP Addr in nmap
                for ndata in data_nmap:
                    if ndata[0] == entry[1]:
                        for port in ndata[1]:
                            # Check for dup
                            if port not in portlist:
                                portlist.append(port)
                tmpAddressData.ipPorts = sorted(portlist, key=lambda x: int(x), reverse=False)
    elif args.masscan:
        with open(masscan_json, "r") as fmassscan_json:
            data_masscan = json.load(fmassscan_json)
            for entry in ip_list:
                # We add our IP Addr and the associated domain
                tmpAddressData = AddressData(entry[0], entry[1])
                listipmetdata.append(tmpAddressData)
                portlist = []
                # We now have to iterate over our list to find the open ports asssociated with our IP Addr in massscan.
                for mdata in data_masscan:
                    if mdata["ip"] == entry[1]:
                        # Check for dup
                        if mdata["ports"][0]["port"] not in portlist:
                            portlist.append(str(mdata["ports"][0]["port"]))
                tmpAddressData.ipPorts = sorted(portlist,key=lambda x: int(x),reverse=False)
    elif args.nmap:
        with open(nmap_json, "r") as fnmap_json:
            data_nmap = json.load(fnmap_json)
            for entry in ip_list:
                # We add our IP Addr and the associated domain
                tmpAddressData = AddressData(entry[0], entry[1])
                listipmetdata.append(tmpAddressData)
                portlist = []
                # We now have to iterate over our list to find the open ports asssociated with our IP Addr in nmap
                for ndata in data_nmap:
                    if ndata[0] == entry[1]:
                        for port in ndata[1]:
                            # Check for dup
                            if port not in portlist:
                                portlist.append(port)
                tmpAddressData.ipPorts = sorted(portlist, key=lambda x: int(x), reverse=False)
    else:
        for entry in ip_list:
            # We add our IP Addr and the associated domain
            tmpAddressData = AddressData(entry[0], entry[1])
            listipmetdata.append(tmpAddressData)
    return listipmetdata

def agregate_data_stage3(ipDataList,args):
    """
    Aggregate the nrich /  Intrigue to the global data
    :param ipDataList:
    :param args:
    :return:
    """
    new_ipDataList = ipDataList
    if args.nrich:
        with open(args.outputdir + args.domain + "/Formatted/nrich_" + args.domain + ".json") as f_nrich:
            data_nrich = json.load(f_nrich)

        for ipData in new_ipDataList:
            for nrichentry in data_nrich:
                try:
                    if nrichentry['ip'] == ipData.ipAddress:
                        if not ipData.cpes:
                            ipData.cpes = nrichentry['cpes']
                        if not ipData.vulns:
                            ipData.vulns = nrichentry['vulns']
                        if not ipData.tags:
                            ipData.tags = nrichentry['tags']
                        #TODO : Add a check to see if nrich port are indeed in our scan ?
                except:
                    pass
    return new_ipDataList

def write_to_xls_s3(data,args):
    workbook = xlsxwriter.Workbook(args.outputdir + args.domain + '/Recon_' + args.domain +'.xlsx')
    worksheet = workbook.add_worksheet('Recon')
    wrap_format = workbook.add_format({'text_wrap':True})
    title_format = workbook.add_format({'bold':True,'align':'center','bg_color':"#D9D9D9"})
    ip_format = workbook.add_format({'bold':True,'align':'left','bg_color':"#DAF7A6"})
    worksheet.set_column(0,0,20)
    worksheet.set_column(1,1,30)
    worksheet.set_column(3, 3,25)
    worksheet.write(0,0,"IP Address",title_format)
    worksheet.write(0, 1, "Domains", title_format)
    worksheet.write(0, 2, "Ports", title_format)
    worksheet.write(0, 3, "CPEs", title_format)
    worksheet.write(0, 4, "Tags", title_format)
    worksheet.write(0, 5, "Vulns", title_format)
    row = 1
    column = 0
    for entry in data:
        #Write the IP Addr
        worksheet.write(row,column,entry.ipAddress,ip_format)
        # Iterate through the domains and write them
        column +=1
        if not isinstance(entry.domains,str):
            worksheet.write(row,column,"\n".join(entry.domains),wrap_format)
        else:
            worksheet.write(row, column, entry.domains + "\n")

        # Write the ports
        column += 1
        worksheet.write(row, column, "\n".join(entry.ipPorts), wrap_format)
        # Write the CPEs
        column += 1
        worksheet.write(row,column,"\n".join(entry.cpes))
        # Write the tags
        column += 1
        worksheet.write(row, column, "\n".join(entry.tags))
        # Write the Vulns
        column += 1
        worksheet.write(row, column, "\n".join(entry.vulns),wrap_format)

        row += 1
        column = 0

    workbook.close()
    return
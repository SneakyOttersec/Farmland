import json
import xlsxwriter

class AddressData():
    ipDatas = []
    domain = ""
    cpes = []
    vulns = []
    tags = []
    def __init__(self,domain,ipData):
        self.ipDatas = [ipData]
        self.domain = domain

    def get_ipList(self):
        ipList = []
        for ipData in self.ipDatas:
            ipList.append(ipData[0])
        return ipList

    def add_ipSmallData(self,ipAddr,ipPorts):
        self.ipDatas.append([ipAddr,ipPorts])
        return

    def get_ipSmallData(self):
        return self.ipDatas

def data_to_urls(address_data_list,filename_small="tmp_urls.txt",filename_full="tmp_urls_full.txt"):
    known_https_ports = ['80', '443', '8443', '8080', '8888']
    with open(filename_small, "w") as f_small,open(filename_full,"w") as f_full:
        for entry in address_data_list:
            for ipData in entry.ipDatas:
                for port in known_https_ports:
                    if ipData[1] is None:
                        break
                    elif port in ipData[1]:
                        f_full.write(ipData[0] + ":" + port + "\n")
                        f_full.write(entry.domain + ":" + port + "\n")
                        f_small.write(entry.domain + ":" + port + "\n")
    return

def data_to_ip(data,file_name="tmp_ip.txt"):
    """
    Extract the IP Addr from our ipDatas and write it to a file
    :param data:
    :param file_name:
    :return:
    """
    written_ip = []
    with open(file_name, "w") as f:
        for entry in data:
            for ipData in entry.ipDatas:
                if ipData[0] not in written_ip:
                    f.write(ipData[0] + "\n")
                    written_ip.append(ipData[0])
    return

def agregate_data_stage1(args,base_domain):
    """
    Agregate the data of massscan and dnsrecon into a list of AddressData
    :param domain:
    :param outputdir:
    :return: agregated AddressData list of the stage1
    """
    if args.massdns and args.dnsrecon :
        with open(args.outputdir + args.domain + "/Formatted/" + args.domain + "_dnsrecon_crt.json" ,"r") as f1, open(args.outputdir + args.domain + "/Formatted/" + args.domain + "_massdns_output.json","r") as f2:
            try:
                data1 = json.load(f1)
                data2 = json.load(f2)
            except:
                print("[!] Error could not load the massdns/dnsrecon json. Aborting")
                exit()
            data_stage1_temp = sorted(data1 + data2, key=lambda x: x[0], reverse=False)
    if args.massdns and not args.dnsrecon:
        with open(args.outputdir + args.domain + "/Formatted/" + args.domain + "_massdns_output.json") as f2:
            try:
                data2 = json.load(f2)
            except:
                print("[!] Error could not load the massdns json. Aborting")
                exit()
            data_stage1_temp = sorted(data2,key=lambda x:x[0],reverse=False)
    if not args.massdns and args.dnsrecon :
        with open(args.outputdir + args.domain + "/Formatted/" + args.domain + "_dnsrecon_crt.json") as f1:
            try:
                data1 = json.load(f1)
            except:
                print("[!] Error could not load the dnsrecon json. Aborting")
                exit()
            data_stage1_temp = sorted(data1 , key=lambda x: x[0], reverse=False)

    # Add our 'base domain' to the list
    for entry in base_domain[1]:
        data_stage1_temp.append((base_domain[0],entry))

    # We need to check for duplicate domains/ip. In case a dup is found we merge the ip.
    data_stage1 = []
    for data in data_stage1_temp:
        entry_present = 0
        for new_data in data_stage1:
            # Check if the domain in entry match
            if data[0] == new_data.domain:
                entry_present = 1
                # Check if an entry for the domain exist but with no IP associated
                if new_data.get_ipList() == None :
                    data_stage1.append(AddressData(data[0], [data[1], None]))
                # Otherwise check if the ip addr is already in the entry
                elif data[1] not in new_data.get_ipList():
                    # The ip is not present, so we add it
                    new_data.add_ipSmallData(data[1],None)

        # If the domain was not present , then add it
        if entry_present == 0 :
            data_stage1.append(AddressData(data[0], [data[1], None]))
        # Check if in the end the domain was present in our list, if not simply add it with the associated ip
    return data_stage1

def agregate_data_stage2(addressdatalist_stage1,args):
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
            raw_data_masscan = json.load(fmassscan_json)
            raw_data_nmap = json.load(fnmap_json)
            for entry in addressdatalist_stage1:
                for ipData in entry.ipDatas:
                    for masscan_data in raw_data_masscan:
                        if masscan_data['ip'] == ipData[0]:
                            if ipData[1] is None:
                                ipData[1] = [str(masscan_data["ports"][0]["port"])]
                            elif str(masscan_data["ports"][0]["port"]) not in ipData[1]:
                                ipData[1].append(str(masscan_data["ports"][0]["port"]))
                    # Iterate over our nmap Data
                    for nmap_data in raw_data_nmap:
                        if nmap_data[0] == ipData[0]:
                            for port in nmap_data[1]:
                                if ipData[1] is None:
                                    ipData[1] = [port]
                                elif port not in ipData[1]:
                                    ipData[1].append(port)
    # Ok !
    # TODO : Port filtered / closed
    elif args.masscan:
        with open(masscan_json, "r") as fmassscan_json:
            raw_data_masscan = json.load(fmassscan_json)
            for entry in addressdatalist_stage1:
                for ipData in entry.ipDatas:
                    for masscan_data in raw_data_masscan:
                        if masscan_data['ip'] == ipData[0]:
                            if ipData[1] is None:
                                ipData[1] = [str(masscan_data["ports"][0]["port"])]
                            elif str(masscan_data["ports"][0]["port"]) not in ipData[1]:
                                ipData[1].append(str(masscan_data["ports"][0]["port"]))
    # Ok !
    # TODO : Port filtered / closed
    elif args.nmap:
        with open(nmap_json, "r") as fnmap_json:
            raw_data_nmap = json.load(fnmap_json)
            for entry in addressdatalist_stage1:
                for ipData in entry.ipDatas:
                    for nmap_data in raw_data_nmap:
                        # Check if ip are equal
                        if nmap_data[0] == ipData[0]:
                            # Iterate over the discovered ports
                            for port in nmap_data[1]:
                                # Check if there is port entry for the match
                                if ipData[1] is None:
                                    ipData[1] = [port]
                                elif port not in ipData[1]:
                                    ipData[1].append(port)
    else:
        # Well nothing to do since 1.1
        pass
    return addressdatalist_stage1

def agregate_data_stage3(ipDataList,args):
    """
    Aggregate the nrich /  Intrigue to the global data
    :param ipDataList:
    :param args:
    :return:
    """
    if args.nrich:
        with open(args.outputdir + args.domain + "/Formatted/nrich_" + args.domain + ".json") as f_nrich:
            data_nrich = json.load(f_nrich)

        for entry in ipDataList:
            for ipData in entry.ipDatas:
                for nrichentry in data_nrich:
                    try:
                        if nrichentry['ip'] == ipData[0]:
                            if not entry.cpes:
                                entry.cpes = nrichentry['cpes']
                            if not entry.vulns:
                                entry.vulns = nrichentry['vulns']
                            if not entry.tags:
                                entry.tags = nrichentry['tags']
                            #TODO : Add a check to see if nrich port are indeed in our scan ?
                    except:
                        pass
    return ipDataList

def write_to_xls_s3(full_AdressData,args):
    workbook = xlsxwriter.Workbook(args.outputdir + args.domain + '/Recon_' + args.domain +'.xlsx')
    worksheet = workbook.add_worksheet('Recon')
    wrap_format = workbook.add_format({'text_wrap':True,'align':'top'})
    title_format = workbook.add_format({'bold':True,'align':'center','bg_color':"#D9D9D9"})
    domain_format = workbook.add_format({'bold':True,'bg_color':"#DAF7A6",'align':'top'})
    worksheet.set_column(0,0,20)
    worksheet.set_column(1,1,30)
    worksheet.set_column(2, 2, 50)
    worksheet.set_column(3, 3,40)
    worksheet.set_column(4, 4, 30)
    worksheet.set_column(5, 5, 60)
    worksheet.write(0,0,"Domain",title_format)
    worksheet.write(0, 1, "IP Addr", title_format)
    worksheet.write(0, 2, "Ports", title_format)
    worksheet.write(0, 3, "CPEs", title_format)
    worksheet.write(0, 4, "Tags", title_format)
    worksheet.write(0, 5, "Vulns", title_format)
    row = 1
    column = 0
    for entry in full_AdressData:
        # Write domains
        worksheet.write(row, column, entry.domain + "\n",domain_format)
        column +=1
        # Iterate through the ip and write them
        ip_addr = []
        ip_ports = []
        for ipData in entry.ipDatas:
            ip_addr.append("".join(ipData[0]) + "\n")
            if ipData[1] == None:
                ipData[1] = ['None']
            ip_ports.append(",".join(ipData[1]) + "\n")
        worksheet.write(row, column,''.join(ip_addr), wrap_format)
        # Write the ports
        column += 1
        if ip_ports :
            worksheet.write(row, column, ''.join(ip_ports), wrap_format)

        # Write the CPEs
        column += 1
        worksheet.write(row,column,"\n".join(entry.cpes), wrap_format)
        # Write the tags
        column += 1
        worksheet.write(row, column, "\n".join(entry.tags), wrap_format)
        # Write the Vulns
        column += 1
        worksheet.write(row, column, "\n".join(entry.vulns),wrap_format)

        row += 1
        column = 0

    workbook.close()
    return
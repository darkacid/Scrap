#!/usr/bin/env python3
#D-LINK Version

import requests
import sys
import ipaddress
import csv
def parseResult(requestResult):
    patternString="index_dlink.htm"#DGS-1210
    SWdes1228Pattern = "<title>DES-1228                                 Login</title>"
    SWdgs1210mePattern = "var LoginUser = '';"
    SWdgs1210Pattern = "var LoginUser = 'admin';"
    unknownSWPattern = "login"
    
    #Case 1: DES1228
    #Case 2: DGS-1210
    #Case 3: DGS-1210/ME
    #Case 4: Unknown SW
    #Case 5: Regular PC
    #Case 6: No response
    
    #Logical Statement: If from mngmnt network switch doesnt respont, but responds from its vlan,
    #then it has old settings



    if SWdes1228Pattern in requestResult:
        return "DES-1228"
    elif SWdgs1210Pattern in requestResult:
        return "DGS-1210"
    elif SWdgs1210mePattern in requestResult:
        return "DGS-1210/ME"
    elif unknownSWPattern in requestResult:
        return "loginPage"
    elif "No route to host" in requestResult:
        return "No Host"
    elif "Connection refused" in requestResult:
        return "Connection Refused"
    return False

def sendRequest(IP):

    session_requests = requests.session()
    LoginIP=IP
    url = "http://"+LoginIP
    try:

        is_Dlink = session_requests.get(url,timeout=5)
        session_requests.close()
        return (parseResult(is_Dlink.text))

    except OSError as err:
        
        error_text = str(err)
        if "No route to host" in error_text:
            return "No Host"
        elif "Connection refused" in error_text:
            return "Connection Refused"
        elif "BadStatusLine('<html>\\n',))" in error_text:
            return "DES-1228"
        elif "connect timeout":
            return "Timeout"

        else:
            print (error_text)
            return("unknown error")
            
        session_requests.close()



   # if(parseResult(is_Dlink.text)):
   #

    #    print(LoginIP,"is a switch")
    #else:
    #    print(LoginIP,"is NOT a switch")


def genRange(cidr_network):

    network = ipaddress.ip_network(cidr_network)
    ipList = network.hosts()
    
    print("Found",network.num_addresses,"addresses")
    #sendRequest("10.100.100.7")
    #return
    parsed_list = []
    for address in ipList:
        addr=str(address)           
        parsed_result = sendRequest(str(address))
        print(addr,end=' ')     
        print (parsed_result)
        parsed_list.append([addr,parsed_result])
    with open ("hosts-"+str(network.network_address)+".csv","w") as csvfile:
        writer = csv.writer(csvfile)
        for row in parsed_list:
            writer.writerow(row)
       
    
        
if len(sys.argv) > 1:
    genRange(sys.argv[1])
else:
    print("Wrong arguments given")

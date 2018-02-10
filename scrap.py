#!/usr/bin/env python3
#D-LINK Version

import requests
import sys
import re
import os.path
import csv
import ipaddress
import hashlib



class Switch:
    '''
saveConfigBackup("ip of TFTP") - Saves current running config to TFTP server
getLldp() - Returns True or False for LLDP
setLldp(1 or 2) - Enables or Disables LLDP
getVlan() - Returns a table for VLANs
    '''
    def __init__(self,switchIP,Username,Password,switchModel):

        self.switchIP=switchIP
        self.switchUsername=Username
        self.model = switchModel
        self.Password = Password        
        self.checkGambit()

    def setLoginPayload(self):

        loginPayload = {
        "currlang":"0",
        "BrowsingPage":"index_dlink.htm",         
        "changlang":"0"
        }        
        PasswordMD5= hashlib.md5(str.encode(self.Password)).hexdigest()
        newFirmware = {"pelican":self.switchUsername, "pinkpanther":PasswordMD5}
        oldFirmware = {"Login":self.switchUsername, "Password":self.Password}
        loginPayload.update(oldFirmware)
        loginPayload.update(newFirmware)
        self.loginPayload = loginPayload

    def setLldpPayload(self, value):
        
        self.lldpPayload = {
            "Gambit":self.gambitString,
            "FormName":"formLLDPSetting",
            "enabled_flag":value,
            "LLDPHoldTime":"4",
            "LLDPTimer":"30",
            "LLDPReinitDelay":"2",
            "LLDPTxDelay":"2"
        }

    def setConfigBackupPayload(self, tftp_addr):

        self.saveBackupPayload = {
            "Gambit":self.gambitString,
            "FormName":"tftp_set",
            "tftp_type":"1",
            "server_iptype":"1",
            "IsLinkLocal":"0",
            "InterfaceName":"",
            "bb":"0",
            "serverip":tftp_addr,
            "radio_serverip":"on",
            "filename":"config-"+self.switchIP+".bin"
        }

    def setLoginURL(self):

        self.login_url = "http://"+self.switchIP+"/"
        if self.model == "DGS-1210":
            self.login_url+="homepage.htm"
        elif self.model == "DGS-1210/ME":
            return True
        elif self.model == "DES-1228":
            return True
        else:
            return "Model unknown"

    def checkGambit(self):

        if os.path.isfile(self.switchIP+"-gambit.txt"):
            self.gambitString= open(self.switchIP+"-gambit.txt",mode='r').read()
            return "Token exists"
        else:
            self.gambitString=""
            return ("Token didn't exist")

    def login(self):

        session_requests = requests.session()
        self.setLoginURL()
        self.setLoginPayload()

        try:
            login_result = session_requests.post(self.login_url,data=self.loginPayload,timeout=5)
        except requests.Timeout as timeout:
            return "login timeout"
        except OSError as error:
            errorText = str(error)
            if "Remote end closed connection without response" in errorText:
                print ("Server closed connection while login")
                return "Failed"
            else:
                return "Other OSError"

        #Get Gambit string
        gambitREPattern = "Gambit=([A-Za-z0-9]+)\'"
        for element in login_result.text.split():
            if("Gambit" in element):
                patternResult = re.search(gambitREPattern,element)
                if(patternResult):
                    self.gambitString = patternResult.group(1)

        with  open(self.switchIP+"-gambit.txt",mode='w')as writeFile:
            writeFile.write(self.gambitString)
        return True
        
    def getVlan(self):

        vlan_url="http://"+self.switchIP+"/iss/specific/QVLAN.js?Gambit="+self.gambitString
        session_requests = requests.session()
        try:
            vlan_result = session_requests.get(vlan_url)
        except :
            print("Token invalid, logging in...")
            self.login()
            vlan_url="http://"+self.switchIP+"/iss/specific/QVLAN.js?Gambit="+self.gambitString
            vlan_result = session_requests.get(vlan_url)

        #parse_vlan = vlan_result.text.split('\n')        
        #vlan_string = "".join(parse_vlan)
        match = re.search("^var TVLAN_Setting.*\]\\n\];",vlan_result.text,re.MULTILINE | re.DOTALL)
        print (match.group(0))
        #print(vlan_result.text)
        
    def getLldp(self):

        lldp_url="http://"+self.switchIP+"/iss/specific/LLDP.js?Gambit="+self.gambitString
        session_requests = requests.session()        
        
        try:
            lldp_result = session_requests.get(lldp_url)
        except :
            #print("Token invalid, logging in...")   
            loginResult = self.login()

            if(loginResult != True):
                return loginResult            
            lldp_url="http://"+self.switchIP+"/iss/specific/LLDP.js?Gambit="+self.gambitString
            lldp_result = session_requests.get(lldp_url)
        if "LLDP_Enable = '2'" in lldp_result.text:
            return False
        elif "LLDP_Enable = '1'" in lldp_result.text:
            return True
        else:
            return None
        
    def setLldp(self,value):

        if(not(value == 2 or value == 1)):
            print("Possible values: 1 - enabled; 2 - disabled")
            return False

        self.setLldpPayload(value)

        lldp_url="http://"+self.switchIP+"/iss/specific/LLDP.js"
        session_requests = requests.session()
        try:
            lldp_result = session_requests.post(lldp_url,data=self.lldpPayload, timeout = 5)
        except:
            #print("Token invalid, logging in...")
            self.login()
            lldp_result = session_requests.post(lldp_url,data=self.lldpPayload, timeout =5 )
    
    def saveConfigBackup(self,tftp_addr):   

        self.setConfigBackupPayload(tftp_addr)

        tftp_save_url="http://"+self.switchIP+"/iss/specific/TFTPBackup.js"
        session_requests = requests.session()
        try:
            tftp_save_result = session_requests.post(tftp_save_url,data=self.saveBackupPayload, timeout=5)
        except:
            print("Token invalid, logging in...")
            self.login()
            tftp_save_result = session_requests.post(tftp_save_url,data=self.saveBackupPayload, timeout=5)
        if("Config file backup successfully via TFTP" in tftp_save_result.text):
            print("Backup Success")
            return "Backup Success"

def fetchLldpResult(switch):

    lldpResult = switch.getLldp()
    if(lldpResult == False):
        return("LLDP Disabled, will enable...")
        switch.setLldp(1)
    elif (lldpResult ==True):
        return("LLDP enabled")

def sendRequests(cidr_network):

    network = ipaddress.ip_network(cidr_network)
    with open ("hosts-"+str(network.network_address)+".csv","r") as csvfile:
        reader = csv.reader(csvfile)
        hostList = list(reader)
    
    loginUsername = "admin"
    loginPassword = "admin"
    for host in hostList:
        switchModel = host[1]
        LoginIP = host[0]

        if switchModel == "DGS-1210" or switchModel == "DGS-1210/ME" or switchModel == "DES-1228":

            mySw = Switch(LoginIP, loginUsername, loginPassword, switchModel)
            print(LoginIP+' ',end='')
            print(fetchLldpResult(mySw))
        else:
            print("Unknown switch model")
            return
    print()
            
if  len(sys.argv) == 1:
    sendRequests(sys.argv[1])
else:
    print("Wrong arguments given")
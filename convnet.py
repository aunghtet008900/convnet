#!/usr/bin/python

################[INFO]#################
# SCRIPT: Convnet                     #
#Version: 1                           #
#    JOB: Calculate Subnet(IPv4)      #
#   Date: 2/1/2019                    #
#CodedBy: Oseid Aldary                #
#######################################
import socket,struct; from time import sleep as se; from sys import argv
def convnet(IP):
        if "/" not in IP:
                print("\n[!] Invalid Input: Must Select Prefix Number [OR] Subnet Mask !!!\n[*] Examples:\n\tpython convnet.py 192.168.1.1/24\n\tpython convnet.py 172.16.0.0/255.255.0.0")
                exit(1)
        IP = IP.split("/")
        subnet = IP[1]
        IP = IP[0]
        if IP.count(".") <3 or IP.count(".") >3:
                print("\nInvalid IPv4: [ {} ]".format(IP))
                exit(1)
        a = IP.split(".")
        if (len(a) == 4) and (1 <= int(a[0]) <= 223) and (int(a[0]) != 127) and (int(a[0]) != 169 or int(a[1]) != 254) and (0 <= int(a[1]) <= 255 and 0 <= int(a[2]) <= 255 and 0 <= int(a[3]) <= 255):
                access = "OK"
        else:
                print("\n[!] Invalid IP: [ {} ]".format(IP))
                exit(1)
        c = 0
        if "." in subnet:
                if not subnet.count(".") ==3:
                        print("\n[!] Invalid Subnet Mask[ {} ] ".format(subnet))
                        exit(1)
                c +=1 
                masks = [255, 254, 252, 248, 240, 224, 192, 128, 0]
                netmask = subnet
                b = netmask.split(".")
                if (len(b) == 4) and (int(b[0]) == 255) and (int(b[1]) in masks) and (int(b[2]) in masks) and (int(b[3]) in masks) and (int(b[0]) >= int(b[1]) >= int(b[2]) >= int(b[3])):
                        access = "OK"
                        bits = sum([bin(int(x)).count("1") for x in netmask.split(".")])
                else:
                        print("\n[!] Invalid Subnet Mask[ {} ] ".format(netmask))
                        exit(1)
        else:
                if int(subnet) > 32:
                        print("\n[!] Invalid Prefix Number: Must Be less than or equal '32' \n[*] example: 192.168.1.1/24")
                        exit(1)
                else:
                        netmask = '.'.join([str((0xffffffff << (32 - int(subnet)) >> i) & 0xff) for i in [24, 16, 8, 0]])
        ##################################### Convert ############################################
        ip2bin = lambda IP: ".".join(map(str,["{0:08b}".format(int(x)) for x in IP.split(".")])) #
        bin2ip = lambda bnum: ".".join(map(str, [ int(x, 2) for x in bnum.split(".")]))          #
        ip2int = lambda ip2: struct.unpack('!I', socket.inet_aton(ip2))[0]                       #
        int2ip = lambda inum: socket.inet_ntoa(struct.pack('!I', inum))                          #
        ##########################################################################################
        wacard = ".".join(map(str, [255 - int(x) for x in netmask.split(".")]))
        net2bin = ip2bin(netmask)
        IP2BIN = ip2bin(IP)
        nid = "".join(map(str, [int(i) & int(r) for i,r in zip("".join(IP2BIN.split(".")),"".join(net2bin.split(".")))]))
        netIDbin = ".".join(map(''.join, zip(*[iter(nid)] * 8)))
        if netIDbin.split(".")[0][0] =="0" : classType = "A"
        elif netIDbin.split(".")[0][:2] =="10" : classType = "B"
        else : classType = "C"
        
        if classType =="C":
                zeros = net2bin.split(".")[-1].count("0")
                ones = net2bin.split(".")[-1].count("1")
        elif classType =="B":
                zeros = "".join(net2bin.split(".")[-2:]).count("0")
                ones = "".join(net2bin.split(".")[-2:]).count("1")
        else:
                zeros = "".join(net2bin.split(".")[-3:]).count("0")
                ones = "".join(net2bin.split(".")[-3:]).count("1")
        validSubnets = abs(2 **ones)
        validHosts = abs(2 **zeros)
        usableHosts = abs(2 **zeros -2)
        validsubnets = "{0:,}".format(validSubnets) if len(str(validSubnets)) > 4 else validSubnets
        validHost = "{0:,}".format(usableHosts) if len(str(usableHosts)) > 4 else usableHosts
        netID = bin2ip(netIDbin)
        inmsk = ''.join([bin(~0)[3:] if x == '0' else bin(~1)[4:] for x in "".join(net2bin.split("."))])
        broadidbin = "".join(map(str, [int(i) | int(r) for i,r in zip(nid,inmsk)]))
        broadidbin =".".join(map(''.join, zip(*[iter(broadidbin)] * 8)))
        broadid = bin2ip(broadidbin)
        if netID !=broadid:
                firstIP = ip2int(netID)+1
                lastIP = ip2int(broadid)-1
                firstIP = int2ip(firstIP)
                lastIP = int2ip(lastIP)
        else:
                firstIP = netID
                lastIP = broadid
        # Show Info
        print("\n=========="+"="*len(IP)+"="+"="*len(subnet)+"======")
        print(".:: INFO[ {}/{} ] ::.".format(IP,subnet))
        se(0.10)
        print("=========="+"="*len(IP)+"="+"="*len(subnet)+"======")
        if c==0:
                print("  [+] NetMask     :>[ {}".format(netmask))
                se(0.10)
        else:
                print("  [+] NetMask Bits:>[ /{}".format(bits))
                se(0.10)
        print("  [+] WildCardMask:>[ {}".format(wacard))
        se(0.10)
        print("  [+] NetWorkID   :>[ {}".format(netID))
        se(0.10)
        print("  [+] BroadCatID  :>[ {}".format(broadid))
        se(0.10)
        print("  [+] ClassType   :>[ {}".format(classType))
        se(0.10)
        print("  [+] FirstIP     :>[ {}".format(firstIP))
        se(0.10)
        print("  [+] LastIP      :>[ {}".format(lastIP))
        se(0.10)
        print("  [+] UsableHosts :>[ {}".format(validHost))
        se(0.10)
        print("  [+] ValidSubnets:>[ {}".format(validsubnets))

        if validSubnets > 1:
                n = 1
                print("\n=====================================")
                print("[+]        VLSM Calculator        [+]")
                print("=====================================")
                for i in range(1,validsubnets+1):
                        print("\n[*] Subnet Number:[{}]".format(n))
                        print("===================="+'='*len(str(n)))
                        print("  [+] NetWorkID  :>[ {}".format(netID))
                        print("  [+] FirstIP    :>[ {}".format(firstIP))
                        print("  [+] LastIP     :>[ {}".format(lastIP))
                        print("  [+] BroadCatID :>[ {}".format(broadid))
                        netID = int2ip(ip2int(broadid)+1)
                        firstIP = int2ip(ip2int(netID)+1)
                        broadid = int2ip(ip2int(broadid)+validHosts)
                        lastIP = int2ip(ip2int(broadid)-1)
                        n+=1


def usage():
        print("\n\nUsage: python convnet.py <IP/Netmask [OR] Perfix Number>\nExamples:\n\tpython convnet.py 192.8.3.1/255.255.192.0\n\tpython convnet.py 192.8.3.1/18\n\n")
        exit(1)

if len(argv) !=2:
        usage()
subnet = argv[1]
if subnet in ["-h","-H","-hh","-HH","--help","--HELP","?","/?","help","HELP"]:
        usage()
else:
        convnet(subnet)
#Calculat Subnet(IPv6) --- Soon  In Version:2 :)
##############################################################
######################               #########################
###################### END OF Module #########################
######################               #########################
##############################################################
#This Module Codedby: Oseid Aldary
#Have a nice day :)
#GoodBye

import pandas as pd
import re
import os

def network(full_path): # full_path from FGT_Auditor.py

    wordlist = ['https', 'http', 'ssh', 'telnet', 'delamrede']
    null_serie = "Series([], )"
    df = pd.read_csv(full_path, sep=';', header=0)
    table = []
    interface_added = False

    for word in wordlist:
        vuln_Obj_search = df['allowaccess'].str.contains(word)==True # To check if "word" is in the collumn "AllowAccess"
        vuln_Obj_search = vuln_Obj_search.to_string(index=False) # To pass the table to string
        vuln_Obj_search_table = vuln_Obj_search.splitlines()

        vuln_Obj_name = df[df['allowaccess'].str.contains(word) == True].id # Retrieve object name where "word" contains member column 
        vuln_Obj_name = vuln_Obj_name.to_string(index=False) # Pass the table to string format

        vuln_Obj_member = df[df['allowaccess'].str.contains(word) == True].allowaccess
        vuln_Obj_member = vuln_Obj_member.to_string(index=False)

        vuln_Obj_ip = df[df['allowaccess'].str.contains(word) == True].ip # Retrieve object name where "word" contains member column 
        vuln_Obj_ip = vuln_Obj_ip.to_string(index=False) # Pass the table to string format
        
        # TABLE DECLARATION
        ## This table is only 1 line table (or 1 column)
        table_name = [vuln_Obj_name]
        table_member = [vuln_Obj_member]
        table_ip = [vuln_Obj_ip]

        ## Replace space with nothing, only stay with \n
        sub_name = (table_name[0].replace('  ',''))
        sub_name = sub_name.split() # Split all line with \n into array ['word1', 'word2'...]

        # Replace tabulation for member
        sub_member = table_member[0].splitlines() # Split table into lines
        sub_ip = table_ip[0].splitlines()
        #if "True" in vuln_Obj_search: # If value "True" is found on the first search, we have a vulnerability
        if null_serie not in sub_member :
            for i in (range(len(sub_name)) and range(len(sub_member))): # Loop for print all objects in the array
                for ii in table:
                    for iii in ii:
                        if sub_name[i] in iii:
                            interface_added = True

                if interface_added == False: # If 0 occurence of sub_name in table[]
                    table += [[[sub_name[i]],[sub_member[i]],[sub_ip[i]]]] # Make 3 dimensionnal array for [[Interface name], [Attributes]]
                    #print(table)

    return table


def address(full_path):
    wordlist = ['0.0.0.0','any']
    null_serie = "Series([], )"
    df = pd.read_csv(full_path, sep=';', header=0)
    table = []
    address_added = False

    for word in wordlist:
        vuln_Obj_search = df['subnet'].str.contains(word)==True
        vuln_Obj_search = vuln_Obj_search.to_string(index=False) # To pass the table to string
        vuln_Obj_search_table = vuln_Obj_search.splitlines()

        vuln_Obj_name = df[df['subnet'].str.contains(word) == True].id # Retrieve object name where "word" contains member column 
        vuln_Obj_name = vuln_Obj_name.to_string(index=False) # Pass the table to string format
        
        vuln_Obj_subnet = df[df['subnet'].str.contains(word)==True].subnet
        vuln_Obj_subnet = vuln_Obj_subnet.to_string(index=False)

        table_name = [vuln_Obj_name]
        table_subnet = [vuln_Obj_subnet]

        sub_name = table_name[0].splitlines()
        sub_subnet = table_subnet[0].splitlines()
        
        if null_serie not in vuln_Obj_subnet :
            for i in (range(len(sub_name)) and range(len(sub_subnet))): # Loop for print all objects in the array
                for ii in table:
                    for iii in ii:
                        if sub_name[i] in iii:
                            interface_added = True

                if address_added == False: # If 0 occurence of sub_name in table[]
                    table += [[[sub_name[i]],[sub_subnet[i]]]] # Make 2 dimensionnal array for [[Interface name], [Attributes]]
    return table



def vip(full_path):
    null_serie = "Series([], )"
    df = pd.read_csv(full_path, sep=';', header=0)
    table = []
    vip_added = False

    vuln_Obj_name = df
    vuln_Obj_name = vuln_Obj_name.to_string(index=False) # To pass the table to string
    vuln_Obj_name_table = vuln_Obj_name.splitlines()

    if null_serie not in vuln_Obj_name :
        return vuln_Obj_name

def ssl_settings(full_path):
    null_serie = "Series([], )"
    df = pd.read_csv(full_path, sep=';', header=0)
    table = []
    ssl_active = False

    vuln_Obj_name = df
    vuln_Obj_name = vuln_Obj_name.to_string(index=False) # To pass the table to string
    vuln_Obj_name_table = vuln_Obj_name.splitlines()
    
    try:
        vuln_Obj_srcintf = df['source-interface']
        vuln_Obj_srcintf = vuln_Obj_srcintf.to_string(index=False)
        ssl_active = True
        print('\n[!] SSL VPN is active on interface %s' % vuln_Obj_srcintf)
        print("##############################")
        print (vuln_Obj_name)
        print("##############################\n")

    except Exception:
        ssl_active = False
        print("[*] NO SSL VPN ACTIVE")
"""
def admin_check(full_path):

    null_serie = "Series([], )"
    df = pd.read_csv(full_path, sep=';', header=0)

    admin_Obj_all = df
    admin_Obj_all = admin_Obj_all.to_string(index=False) # To pass the table to string
    admin_Obj_all_table = admin_Obj_all.splitlines()
    
    admin_Obj_name = (df.id).to_string(index=False)
    if "admin" in admin_Obj_name:
        print("[!] Admin account is enable. Kindly delete the default account")
    admin_Obj_name = admin_Obj_name.splitlines()

    admin_Obj_accprofile = (df.accprofile).to_string(index=False)
    admin_Obj_accprofile = admin_Obj_accprofile.splitlines()

    admin_list = []

    # For check all account
    for i in range(len(admin_Obj_name)):
        admin_list += [[admin_Obj_name[i], admin_Obj_accprofile[i]]]

    for row in admin_list:
        #print(row)
        for collumn in row:
            #print(collumn)
            for cell in collumn:
                print(cell,end = "")
        print() # for \n between row
    print("##############################\n")
"""

def ipsec_p1(full_path):

    proposal_list = ['aes256-sha256']
    dhgroup_list = ['16']
    null_serie = "Series([], )"
    df = pd.read_csv(full_path, sep=';', header=0)
    table = []
    ipsec_added = False
    ipsec_vuln = False

    ipsec_Obj_all = df
    ipsec_Obj_all = ipsec_Obj_all.to_string(index=False) # To pass the table to string
    ipsec_Obj_all_table = ipsec_Obj_all.splitlines()

    for best_proposal in proposal_list:

        ipsec_Obj_name = (df['id'].to_string(index=False)).splitlines()
        ipsec_Obj_interface = (df['interface'].to_string(index=False)).splitlines()
        ipsec_Obj_proposal = df[df['proposal'].str.contains(best_proposal) == True].proposal
        ipsec_Obj_proposal = ipsec_Obj_proposal.to_string(index=False)
        ipsec_Obj_dhgrp = (df['dhgrp'].to_string(index=False)).splitlines()
        ipsec_Obj_gw = (df['remote-gw'].to_string(index=False)).splitlines()
    
        if best_proposal not in ipsec_Obj_proposal :

            for i in (range(len(ipsec_Obj_name))): # Loop for print all objects in the array
                for ii in table: 
                    for iii in ii: 
                        if ipsec_Obj_name[i] in iii:
                            ipsec_added = True
                if ipsec_added == False: # If 0 occurence of sub_name in table[]
                    table += [[[ipsec_Obj_name[i]]]]
                    ipsec_vuln = True
        else:
            print("IPSEC are well configured")

    if ipsec_vuln == True:
        print("##############################")
        print("[!] VULNERABLE IPSEC [!]")
        for row in table:
            for collumn in row:
                for cell in collumn:
                    print(cell,end = " ")
            print() # for \n between row
        print("Kindly reconfigure Phase1 : Encrypt AES256-SHA256 / DHGROUP 16")
        print("##############################\n")

def ipsec_p2(full_path): # TODO

    # id, phase1name, proposal, dhgrp
    proposal_list = ['aes256-sha256']
    pfs_list = ['enable']
    dhgroup_list = ['16']
    src_subnet = []
    dst_subnet = []
    null_serie = "Series([], )"
    df = pd.read_csv(full_path, sep=';', header=0)
    table = []
    ipsec_added = False
    ipsec_vuln = False

    ipsec_Obj_all = df
    ipsec_Obj_all = ipsec_Obj_all.to_string(index=False) # To pass the table to string
    ipsec_Obj_all_table = ipsec_Obj_all.splitlines()
    ipsec_Obj_name = (df['id'].to_string(index=False)).splitlines()
    ipsec_Obj_phase1name = (df['phase1name'].to_string(index=False)).splitlines()

    # Test if PFS is enabled
    try:
        ipsec_Obj_proposal = (df['proposal'].to_string(index=False)).splitlines()
        ipsec_Obj_dhgrp = (df['dhgrp'].to_string(index=False)).splitlines()
    except Exception:
        print("[!] PFS is not enabled. [!]")
        ipsec_Obj_proposal = ''
        ipsec_Obj_dhgrp = ''

    # Test if source subnet is configured
    try:
        ipsec_Obj_srcsubnet = (df['src-subnet'].to_string(index=False)).splitlines()
    except Exception:
        print("[!] SOURCE : Any host are authorized over VPN [!]")
        print("---> Kindly modify the phase2 configuration and add source subnet/host")
        ipsec_Obj_srcsubnet = ''

    #Test if destination subnet is configured
    try:
        ipsec_Obj_dstsubnet = (df['dst-subnet'].to_string(index=False)).splitlines()
    except Exception:
        print("[!] DESTINATION : Any host are authorized over VPN [!]")
        print("---> Kindly modify the phase2 configuration and add destination subnet/host")
        ipsec_Obj_dstsubnet = ''

def policies(full_path):
    df = pd.read_csv(full_path, sep=';', header=0)
    any_value = ['any', 'ANY', 'all', 'ALL']
    null_serie = "Series([], )"

    # Source address
    for value in any_value:
        #print(value)
        policy_Obj_srcaddr = df[df['srcaddr'].str.contains(value) == True].id
        policy_Obj_uuid = df[df['srcaddr'].str.contains(value) == True].uuid
        policy_Obj_uuid = (policy_Obj_uuid.to_string(index=False)).splitlines()
        policy_Obj_srcaddr = (policy_Obj_srcaddr.to_string(index=False)).splitlines()
    
        if null_serie not in policy_Obj_srcaddr:
            for policy_id in range(len(policy_Obj_srcaddr)) :
                print("[!] SRC [!] Policy ID %s contains %s on its source address [!] UUID : %s " % (policy_Obj_srcaddr[policy_id], value, policy_Obj_uuid[policy_id]))
    
    # Destination address
    for value in any_value:

        policy_Obj_dstaddr = df[df['dstaddr'].str.contains(value) == True].id
        policy_Obj_dstaddr = (policy_Obj_dstaddr.to_string(index=False)).splitlines()
        policy_Obj_uuid = df[df['dstaddr'].str.contains(value) == True].uuid
        policy_Obj_uuid = (policy_Obj_uuid.to_string(index=False)).splitlines()

        if null_serie not in policy_Obj_dstaddr:
            for policy_id in range(len(policy_Obj_dstaddr)) :
                print("[!] DST [!] Policy ID %s contains %s on its destination address [!] UUID : %s" % (policy_Obj_dstaddr[policy_id], value, policy_Obj_uuid[policy_id]))
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Script for exporting configuration files into CSV file
# And auditing it

######################################
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from codecs import open
from os import path
import sys
import re
import csv
import os
from datetime import datetime

# Importing anothers scripts
import generate_csv
import parse_network, parse_address, parse_admin, parse_ipsec_p1, parse_ipsec_p2, parse_policies, parse_routes, parse_services, parse_services_grp, parse_snmp, parse_ssl_portal, parse_ssl_settings, parse_vip
import audit_csv

# OptionParser importss
from optparse import OptionParser
from optparse import OptionGroup
######################################

# Python 2 and 3 compatibility
if (sys.version_info < (3, 0)):
    fd_read_options = 'rb'
    fd_write_options = 'wb'
else:
    fd_read_options = 'r'
    fd_write_options = 'w'

# Read configuration files from folders
#for file in os.listdir('.'):
#    print(file)

##########################################################################
# Options definition
parser = OptionParser(usage="%prog [options]")
main_grp = OptionGroup(parser, 'Main parameters')
main_grp.add_option('-i', '--input-file', dest='input_file', help='Partial or full Fortigate configuration file. Ex: fgfw.cfg')
main_grp.add_option('-o', '--output-file', dest='output_file', help='Output csv file (default ./network.csv)', default=path.abspath(path.join(os.getcwd(), './network.csv')))
main_grp.add_option('-l', '--input-folder', dest='input_folder', help='Folder location for multiple configuration files')
main_grp.add_option('-s', '--skip-header', help='Do not print the csv header', action='store_true', default=False)
main_grp.add_option('-n', '--newline', help='Insert a newline between each interface for better readability', action='store_true', default=False)
main_grp.add_option('-d', '--delimiter', help='CSV delimiter (default ";")', default=';')
main_grp.add_option('-f', '--firewall', dest="firewall", help='Set up the name of firewall for output files')

parser.option_groups.extend([main_grp])
options, arguments = parser.parse_args()
##########################################################################

#####################################
# GLOBAL VARIABLE
fw_directory_path = ""

##########################################################################
# Set up Date variables for files generation
date = str(datetime.now())
regex_date = re.compile(r'(?P<date>^\S+)\s(?P<time>\S\S\S\S\S\S\S\S)\S(?P<ms>\S+)', re.IGNORECASE)
date_date = regex_date.search(date).group('date')
date_time = regex_date.search(date).group('time')
date_time = re.sub('[ :]', '', date_time)
##########################################################################

# Validate input file and send help to user when wrong command
# Don't forget to add -h for HELP
#if (options.input_file == None): # Need to set a input file
    #parser.error('''\n\nPlease specify a valid input file.
    #--> "python3 script.py -i /root/config_file.txt
    #--> "python3 script.py --input_file /root/config_file.txt
    #Type -h to check all possibles options (TODO)\n''')

##########################################################################

def input_file(): # CREATING FOLDER WHEN ONLY 1 FILE ( -i option)
    global fw_directory_path
    if (options.input_file != None):
        current_path = os.getcwd()

        if(str(path.exists(current_path + '/reports')) == False):
            os.mkdir(current_path + '/reports')
            current_path = os.getcwd() + '/reports'

        else:
            current_path = os.getcwd() + '/reports'
            print ("\"Report\" Directory is already created !")

        p_fw_name = re.compile(r'Config.Current.Running.(?P<fw_name>\S*).txt') # Regex for firewall name in configuration file name
        fw_name = p_fw_name.search(options.input_file).group('fw_name')
        fw_directory_path = current_path +'/' + fw_name

        print("DEBUG : " + fw_directory_path)

        try:
        #if folder exist, don't create it !
        #report_directory = os.getcwd()
            if(str(path.exists(fw_directory_path)) == True):
                print ("Folder " + fw_name + " already exist. Skipped folder creation.")
            else:
                print ("Successfully created the directory %s " % fw_directory_path)
                os.mkdir(fw_directory_path)
        except OSError:
            print ("Creation of the directory %s failed " % fw_directory_path)

##########################################################################

###########################################
# CSV generation code
def generate_csv(results, keys, options):
    """
        Generate a plain csv file
    """
    if results and keys:
        with open(options.output_file, mode=fd_write_options) as fd_output:
            spamwriter = csv.writer(fd_output, delimiter=options.delimiter, quoting=csv.QUOTE_ALL, lineterminator='\n')

            if not(options.skip_header):
                spamwriter.writerow(keys)

            for interface in results:
                output_line = []

                for key in keys:
                    if key in interface.keys():
                        output_line.append(interface[key])
                    else:
                        output_line.append('')

                spamwriter.writerow(output_line)
                if options.newline:
                    spamwriter.writerow('')

        fd_output.close()

    return None
###########################################

def audit_network(network_table):
    
    if network_table:
        print("##############################")
        print("[!] VULNERABLE INTERFACES [!]")
        for row in network_table:
            for collumn in row:
                for cell in collumn:
                    print(cell,end = " ")
            print() # for \n between row
        print("##############################\n")

def audit_vip(vip_table):
        print("##############################")
        print("\n[!] VIRTUAL IP IS CONFIGURED [!]")
        print(vip_table)
        print("##############################")

def exporting_csv(fw_directory_path,fw_name, full_path):
    """
        Network interface to CSV
    """
    global parser, date_date, date_time

    config_export = ["network", "address", "admin", "ipsec_p1", "ipsec_p2", "policies", "routes", "services", "services_grp", "snmp", "ssl_portal", "ssl_settings", "vip"]

    for csv_type in config_export: # Export configuration for all properties in configuration files

        if (options.firewall == None): # Use name in file title if "-f" option is not set
            # Setting name of the file if no -f option
            # options.output_file = fw_directory_path + '/' + date_date + date_time + '_' + fw_name + '_' + csv_type + '.csv' # Add date to file name
            options.output_file = fw_directory_path + '/' + fw_name + '_' + csv_type + '.csv' # Add date to CSV file
            #print(options.output_file)
        else:
            # Setting name of the file if -f option
            options.output_file = fw_directory_path + '/' + date_date + date_time + '_' + options.firewall + '_' + csv_type + '.csv' # If "-f" option is set

        # For each properties, generate the CSV file according to the associated module
        if (csv_type == "network"):
             results, keys = parse_network.parse(options,full_path)
             generate_csv(results, keys, options)
             print("[*] " + fw_name + " : Network interfaces exported to CSV done. [*]")
             #audit_csv.network(options.output_file)
             audit_network(audit_csv.network(options.output_file))
        #if (csv_type == "address"):
        #    results, keys = parse_address.parse(options,full_path)
        #    generate_csv(results, keys, options)
        #    print("[*] " + fw_name + " : Addresses exported to CSV done. [*]")
        #    #audit_csv.address(options.output_file)
        #    audit_network(audit_csv.address(options.output_file))
#
#        if (csv_type == "admin"):
#            results, keys = parse_admin.parse(options,full_path)
#            generate_csv(results, keys, options)
#            print("[*] " + fw_name + " : Admins account exported to CSV done. [*]")
#            audit_csv.admin_check(options.output_file)
#
        if (csv_type == "ipsec_p1"):
            results, keys = parse_ipsec_p1.parse(options,full_path)
            generate_csv(results, keys, options)
            if path.exists(options.output_file): # If no vip are in the config file, no file will be created
                print("[*] " + fw_name + " : IPSEC Phase1 exported to CSV done. [*]")
                audit_csv.ipsec_p1(options.output_file)
#        if (csv_type == "ipsec_p2"):
#            results, keys = parse_ipsec_p2.parse(options,full_path)
#            generate_csv(results, keys, options)
#            print("[*] " + fw_name + " : IPSEC Phase2 exported to CSV done. [*]")
#            audit_network(audit_csv.ipsec_p2(options.output_file))

        if (csv_type == "policies"):
            results, keys = parse_policies.parse(options,full_path)
            generate_csv(results, keys, options)
            print("[*] " + fw_name + " : Firewall policies exported to CSV done. [*]")
            audit_network(audit_csv.policies(options.output_file))
        if (csv_type == "routes"):
            results, keys = parse_routes.parse(options,full_path)
            generate_csv(results, keys, options)
            print("[*] " + fw_name + " : Static routes exported to CSV done. [*]")
        if (csv_type == "services"):
            results, keys = parse_services.parse(options,full_path)
            generate_csv(results, keys, options)
            print("[*] " + fw_name + " : Services exported to CSV done. [*]")
        if (csv_type == "services_grp"):
            results, keys = parse_services_grp.parse(options,full_path)
            generate_csv(results, keys, options)
            print("[*] " + fw_name + " : Services Groups exported to CSV done. [*]")
        if (csv_type == "snmp"):
            results, keys = parse_snmp.parse(options,full_path)
            generate_csv(results, keys, options)
            print("[*] " + fw_name + " : SNMP communities exported to CSV done. [*]")
        if (csv_type == "ssl_portal"):
            results, keys = parse_ssl_portal.parse(options,full_path)
            generate_csv(results, keys, options)
            print("[*] " + fw_name + " : SSL settings exported to CSV done. [*]")
        if (csv_type == "ssl_settings"):
            results, keys = parse_ssl_settings.parse(options,full_path)
            generate_csv(results, keys, options)
            print("[*] " + fw_name + " : SSL portals exported to CSV done. [*]")
            audit_csv.ssl_settings(options.output_file)
        if (csv_type == "vip"):
            results, keys = parse_vip.parse(options,full_path)
            generate_csv(results, keys, options)
            #print(full_path)
            if path.exists(options.output_file): # If no vip are in the config file, no file will be created
                print("[*] " + fw_name + " : Virtual IP exported to CSV done. [*]")
                audit_vip(audit_csv.vip(options.output_file))

        #print("DEBUG FULL PATH ::EXPORTING_CSV:: " + options.output_file)
        #audit_csv.network(options.output_file)

    return None

def input_folders(): # CREATING FOLDER WHEN MULTIPLE FILES
    global parser
    files_folder = os.listdir(os.path.abspath(options.input_folder))
    folder_path = os.path.abspath(options.input_folder)
    current_path = os.getcwd() # Current path in CMD

    report_check = path.exists(current_path + '/reports/') # Check if reports folder exists
    report_path = os.getcwd() + '/reports/' # Set up the reports path

    if (options.input_folder != None):
        #print("DEBUG : " + current_path)

        if(report_check == False):
            os.mkdir(current_path + '/reports')
            print ("[*] Creating reports folder")
        else:
            print ("\n[!] Report directory is already created Skipped folder creation.\n")

        for file_name in files_folder:
            p_fw_name = re.compile(r'Config.Current.Running.(?P<fw_name>\S*).txt') # Regex for firewall name in configuration file name
            fw_name = p_fw_name.search(file_name).group('fw_name')
            fw_directory_path = report_path + fw_name
            print ('[*] ' + fw_name + ' folder is located at : ' + fw_directory_path)
            
            # Getting full path of config folder for parsing scripts
            full_path = os.path.join(folder_path, file_name)

            #print("DEBUG FULL PATH : " + full_path)

            fw_folders_check = path.exists(fw_directory_path)
            #print(fw_folders_check)

    #folder_content = os.listdir(os.path.abspath(options.input_folder))
    #folder_path = os.path.abspath(options.input_folder)
    #for config_file in folder_content:
    #    full_path = os.path.join(folder_path, config_file)
        #print(full_path)


            try:
                #if folder exist, don't create it !
                #report_directory = os.getcwd()
                if(fw_folders_check == False):
                    print ("[*] Successfully created the directory %s " % fw_directory_path)
                    os.mkdir(fw_directory_path)
            except OSError:
                print ("[!] Creation of the directory %s failed " % fw_directory_path)

            exporting_csv(fw_directory_path,fw_name,full_path)
            print ("_________________")


fw_name=True # For use when -f option is chosen
# For user information about the name of firewall will be used for files saving
if (options.firewall == None): # Use name in file title if "-f" option is not set
    if (options.input_folder != None): # If multiple config file
        input_folders()
    if (options.input_file != None): # If only 1 config file
        input_file()
else:
    print('\nFirewall name is set. ' + options.firewall + ' will be used for files saving.')
    fw_name = False

# Condition for creating the directories for each firewall
#path = os.getcwd()
if (fw_name == False):
#    if (options.input_folder != None):
#        input_folders()
    fw_directory_path = path + '/' + options.firewall
    print(fw_directory_path)
#else:
#    fw_directory_path = path + '/' + fw_name
#    print(fw_directory_path)


#output()
#pool_file()
#create_dir()
#exporting_csv()
#address_csv()
#input_folders()

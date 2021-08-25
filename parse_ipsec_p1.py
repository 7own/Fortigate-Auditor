#!/usr/bin/env python3

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from codecs import open
from os import path 
import sys
import re
import csv
import os

# OptionParser imports
from optparse import OptionParser
from optparse import OptionGroup

# Options definition
parser = OptionParser(usage="%prog [options]")

main_grp = OptionGroup(parser, 'Main parameters')
main_grp.add_option('-i', '--input-file', help='Partial or full Fortigate configuration file. Ex: fgfw.cfg')
main_grp.add_option('-o', '--output-file', help='Output csv file (default ./ipsec-p1.csv)', default=path.abspath(path.join(os.getcwd(), './ipsec-p1.csv')))
main_grp.add_option('-s', '--skip-header', help='Do not print the csv header', action='store_true', default=False)
main_grp.add_option('-n', '--newline', help='Insert a newline between each ipsec for better readability', action='store_true', default=False)
main_grp.add_option('-d', '--delimiter', help='CSV delimiter (default ";")', default=';')
parser.option_groups.extend([main_grp])

# Python 2 and 3 compatibility
if (sys.version_info < (3, 0)):
    fd_read_options = 'rb'
    fd_write_options = 'wb'
else:
    fd_read_options = 'r'
    fd_write_options = 'w'

# Handful patterns
# -- Entering ipsec definition block
p_entering_ipsec_block = re.compile(r'^\s*config vpn ipsec phase1-interface$', re.IGNORECASE)
p_entering_subipsec_block = re.compile(r'^\s*config .*$', re.IGNORECASE)

# -- Exiting ipsec definition block
p_exiting_ipsec_block = re.compile(r'^end$', re.IGNORECASE)

# -- Commiting the current ipsec definition and going to the next one
p_ipsec_next = re.compile(r'^next$', re.IGNORECASE)

# -- ipsec number
p_ipsec_number = re.compile(r'^\s*edit\s+(?P<ipsec_number>\S*)', re.IGNORECASE)

# -- ipsec setting
p_ipsec_set = re.compile(r'^\s*set\s+(?P<ipsec_key>\S+)\s+(?P<ipsec_value>.*)$', re.IGNORECASE)

# Functions
def parse(options,full_path):
    """
        Parse the data according to several regexes
    """
    global p_entering_ipsec_block, p_exiting_ipsec_block, p_ipsec_next, p_ipsec_number, p_ipsec_set
    
    in_ipsec_block = False
    ipsec_list = []
    ipsec_elem = {}
    order_keys = []

    if (options.input_file != None):
        with open(options.input_file, mode=fd_read_options) as fd_input:
            for line in fd_input:
                line = line.strip()
                
                # We match a ipsec block
                if p_entering_ipsec_block.search(line):
                    in_ipsec_block = True
                
                # We are in a ipsec block
                if in_ipsec_block:
                    if p_ipsec_number.search(line):
                        ipsec_number = p_ipsec_number.search(line).group('ipsec_number')
                        ipsec_number = re.sub('["]', '', ipsec_number)
                        ipsec_elem['id'] = ipsec_number
                        if not('id' in order_keys):
                            order_keys.append('id')
                    
                    # We match a setting
                    if p_ipsec_set.search(line):
                        ipsec_key = p_ipsec_set.search(line).group('ipsec_key')
                        if not(ipsec_key in order_keys):
                            order_keys.append(ipsec_key)
                        
                        ipsec_value = p_ipsec_set.search(line).group('ipsec_value').strip()
                        ipsec_value = re.sub('["]', '', ipsec_value)
                        
                        
                        ipsec_elem[ipsec_key] = ipsec_value
                    
                    # We are done with the current ipsec id
                    if p_ipsec_next.search(line):
                        ipsec_list.append(ipsec_elem)
                        ipsec_elem = {}

                # We are exiting the ipsec block
                if p_exiting_ipsec_block.search(line):
                        in_ipsec_block = False
        return (ipsec_list, order_keys)
    else:
        with open(full_path, mode=fd_read_options) as fd_input:
            for line in fd_input:
                line = line.strip()
                
                # We match a ipsec block
                if p_entering_ipsec_block.search(line):
                    in_ipsec_block = True
                
                # We are in a ipsec block
                if in_ipsec_block:
                    if p_ipsec_number.search(line):
                        ipsec_number = p_ipsec_number.search(line).group('ipsec_number')
                        ipsec_number = re.sub('["]', '', ipsec_number)
                        ipsec_elem['id'] = ipsec_number
                        if not('id' in order_keys):
                            order_keys.append('id')
                    
                    # We match a setting
                    if p_ipsec_set.search(line):
                        ipsec_key = p_ipsec_set.search(line).group('ipsec_key')
                        if not(ipsec_key in order_keys):
                            order_keys.append(ipsec_key)
                        
                        ipsec_value = p_ipsec_set.search(line).group('ipsec_value').strip()
                        ipsec_value = re.sub('["]', '', ipsec_value)
                        ipsec_elem[ipsec_key] = ipsec_value
                    
                    # We are done with the current ipsec id
                    if p_ipsec_next.search(line):
                        ipsec_list.append(ipsec_elem)
                        ipsec_elem = {}
                        
                # We are exiting the ipsec block
                if p_exiting_ipsec_block.search(line):
                        in_ipsec_block = False
        return (ipsec_list, order_keys)
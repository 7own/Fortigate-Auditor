#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Fortigate - Address to CSV

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

# Python 2 and 3 compatibility
if (sys.version_info < (3, 0)):
    fd_read_options = 'rb'
    fd_write_options = 'wb'
else:
    fd_read_options = 'r'
    fd_write_options = 'w'

# Handful patterns
# -- Entering address definition block
p_entering_address_block = re.compile(r'^\s*config firewall address$', re.IGNORECASE)
p_entering_subaddress_block = re.compile(r'^\s*config .*$', re.IGNORECASE)

# -- Exiting address definition block
p_exiting_address_block = re.compile(r'^end$', re.IGNORECASE)

# -- Commiting the current address definition and going to the next one
p_address_next = re.compile(r'^next$', re.IGNORECASE)

# -- address number
p_address_number = re.compile(r'^\s*edit\s+(?P<address_number>\S*)', re.IGNORECASE)

# -- address setting
p_address_set = re.compile(r'^\s*set\s+(?P<address_key>\S+)\s+(?P<address_value>.*)$', re.IGNORECASE)

# Functions
def parse(options,full_path):
    """
        Parse the data according to several regexes
        
        @param options:  options
        @rtype: return a list of policies ( [ {'id' : '1', 'srcintf' : 'internal', ...}, {'id' : '2', 'srcintf' : 'external', ...}, ... ] )  
                and the list of unique seen keys ['id', 'srcintf', 'dstintf', ...]
    """
    global p_entering_address_block, p_exiting_address_block, p_address_next, p_address_number, p_address_set
    
    in_address_block = False
    
    address_list = []
    address_elem = {}
    
    order_keys = []

    if (options.input_file != None):
        with open(options.input_file, mode=fd_read_options) as fd_input:
            for line in fd_input:
                line = line.strip()
                
                # We match a address block
                if p_entering_address_block.search(line):
                    in_address_block = True
                
                # We are in a address block
                if in_address_block:
                    if p_address_number.search(line):
                        address_number = p_address_number.search(line).group('address_number')
                        address_number = re.sub('["]', '', address_number)

                        address_elem['id'] = address_number
                        if not('id' in order_keys):
                            order_keys.append('id')
                    
                    # We match a setting
                    if p_address_set.search(line):
                        address_key = p_address_set.search(line).group('address_key')
                        if not(address_key in order_keys):
                            order_keys.append(address_key)
                        
                        address_value = p_address_set.search(line).group('address_value').strip()
                        address_value = re.sub('["]', '', address_value)
                        
                        
                        address_elem[address_key] = address_value
                    
                    # We are done with the current address id
                    if p_address_next.search(line):
                        address_list.append(address_elem)
                        address_elem = {}
                        
                
                # We are exiting the address block
                if p_exiting_address_block.search(line):
                        in_address_block = False
        
        return (address_list, order_keys)

    else:
        #for files in os.listdir(os.path.abspath(options.input_folder)):
        with open(full_path, mode=fd_read_options) as fd_input:
            for line in fd_input:
                line = line.strip()
                
                # We match a address block
                if p_entering_address_block.search(line):
                    in_address_block = True
                
                # We are in a address block
                if in_address_block:
                    if p_address_number.search(line):
                        address_number = p_address_number.search(line).group('address_number')
                        address_elem['id'] = address_number
                        if not('id' in order_keys):
                            order_keys.append('id')
                    
                    # We match a setting
                    if p_address_set.search(line):
                        address_key = p_address_set.search(line).group('address_key')
                        if not(address_key in order_keys):
                            order_keys.append(address_key)
                        
                        address_value = p_address_set.search(line).group('address_value').strip()
                        address_value = re.sub('["]', '', address_value)
                        
                        
                        address_elem[address_key] = address_value
                    
                    # We are done with the current address id
                    if p_address_next.search(line):
                        address_list.append(address_elem)
                        address_elem = {}
                        
                
                # We are exiting the address block
                if p_exiting_address_block.search(line):
                        in_address_block = False
        
        return (address_list, order_keys)
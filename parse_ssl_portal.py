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

# Python 2 and 3 compatibility
if (sys.version_info < (3, 0)):
    fd_read_options = 'rb'
    fd_write_options = 'wb'
else:
    fd_read_options = 'r'
    fd_write_options = 'w'

# Handful patterns
# -- Entering sslvpn definition block
p_entering_sslvpn_block = re.compile(r'^\s*config vpn ssl web portal$', re.IGNORECASE)
p_entering_subsslvpn_block = re.compile(r'^\s*config .*$', re.IGNORECASE)

# -- Exiting sslvpn definition block
p_exiting_sslvpn_block = re.compile(r'^end$', re.IGNORECASE)

# -- Commiting the current sslvpn definition and going to the next one
p_sslvpn_next = re.compile(r'^next$', re.IGNORECASE)

# -- sslvpn number
p_sslvpn_number = re.compile(r'^\s*edit\s+(?P<sslvpn_number>\S*)', re.IGNORECASE)

# -- sslvpn setting
p_sslvpn_set = re.compile(r'^\s*set\s+(?P<sslvpn_key>\S+)\s+(?P<sslvpn_value>.*)$', re.IGNORECASE)

# Functions
def parse(options,full_path):
    """
        Parse the data according to several regexes
    """
    global p_entering_sslvpn_block, p_exiting_sslvpn_block, p_sslvpn_next, p_sslvpn_number, p_sslvpn_set
    
    in_sslvpn_block = False
    sslvpn_list = []
    sslvpn_elem = {}
    order_keys = []
    
    if (options.input_file != None):
        with open(options.input_file, mode=fd_read_options) as fd_input:
            for line in fd_input:
                line = line.strip()
                
                # We match a sslvpn block
                if p_entering_sslvpn_block.search(line):
                    in_sslvpn_block = True
                
                # We are in a sslvpn block
                if in_sslvpn_block:
                    if p_sslvpn_number.search(line):
                        sslvpn_number = p_sslvpn_number.search(line).group('sslvpn_number')
                        sslvpn_number = re.sub('["]', '', sslvpn_number)
                        sslvpn_elem['id'] = sslvpn_number
                        if not('id' in order_keys):
                            order_keys.append('id')
                    
                    # We match a setting
                    if p_sslvpn_set.search(line):
                        sslvpn_key = p_sslvpn_set.search(line).group('sslvpn_key')
                        if not(sslvpn_key in order_keys):
                            order_keys.append(sslvpn_key)
                        
                        sslvpn_value = p_sslvpn_set.search(line).group('sslvpn_value').strip()
                        sslvpn_value = re.sub('["]', '', sslvpn_value)
                        sslvpn_elem[sslvpn_key] = sslvpn_value
                    
                    # We are done with the current sslvpn id
                    if p_sslvpn_next.search(line):
                        sslvpn_list.append(sslvpn_elem)
                        sslvpn_elem = {}
                
                # We are exiting the sslvpn block
                if p_exiting_sslvpn_block.search(line):
                        in_sslvpn_block = False
        return (sslvpn_list, order_keys)
    else:
        #for files in os.listdir(os.path.abspath(options.input_folder)):
        with open(full_path, mode=fd_read_options) as fd_input:
            for line in fd_input:
                line = line.strip()
                
                # We match a sslvpn block
                if p_entering_sslvpn_block.search(line):
                    in_sslvpn_block = True
                
                # We are in a sslvpn block
                if in_sslvpn_block:
                    if p_sslvpn_number.search(line):
                        sslvpn_number = p_sslvpn_number.search(line).group('sslvpn_number')
                        sslvpn_number = re.sub('["]', '', sslvpn_number)
                        sslvpn_elem['id'] = sslvpn_number
                        if not('id' in order_keys):
                            order_keys.append('id')
                    
                    # We match a setting
                    if p_sslvpn_set.search(line):
                        sslvpn_key = p_sslvpn_set.search(line).group('sslvpn_key')
                        if not(sslvpn_key in order_keys):
                            order_keys.append(sslvpn_key)
                        
                        sslvpn_value = p_sslvpn_set.search(line).group('sslvpn_value').strip()
                        sslvpn_value = re.sub('["]', '', sslvpn_value)
                        sslvpn_elem[sslvpn_key] = sslvpn_value

					# We are done with the current sslvpn id
                    if p_sslvpn_next.search(line):
                        sslvpn_list.append(sslvpn_elem)
                        sslvpn_elem = {}
                
                # We are exiting the sslvpn block
                if p_exiting_sslvpn_block.search(line):
                        in_sslvpn_block = False
        return (sslvpn_list, order_keys)

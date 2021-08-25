#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# fgpoliciestocsv.py

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
# -- Entering snmp definition block
p_entering_snmp_block = re.compile(r'^\s*config system snmp community$', re.IGNORECASE)
p_entering_subsnmp_block = re.compile(r'^\s*config .*$', re.IGNORECASE)

# -- Exiting snmp definition block
p_exiting_snmp_block = re.compile(r'^end$', re.IGNORECASE)

# -- Commiting the current snmp definition and going to the next one
p_snmp_next = re.compile(r'^next$', re.IGNORECASE)

# -- snmp number
p_snmp_number = re.compile(r'^\s*edit\s+(?P<snmp_number>\d+)', re.IGNORECASE)

# -- snmp setting
p_snmp_set = re.compile(r'^\s*set\s+(?P<snmp_key>\S+)\s+(?P<snmp_value>.*)$', re.IGNORECASE)

# Functions
def parse(options,full_path):
    """
        Parse the data according to several regexes
        
        @param options:  options
        @rtype: return a list of policies ( [ {'id' : '1', 'srcintf' : 'internal', ...}, {'id' : '2', 'srcintf' : 'external', ...}, ... ] )  
                and the list of unique seen keys ['id', 'srcintf', 'dstintf', ...]
    """
    global p_entering_snmp_block, p_exiting_snmp_block, p_snmp_next, p_snmp_number, p_snmp_set
    
    in_snmp_block = False
    
    snmp_list = []
    snmp_elem = {}
    
    order_keys = []

    if (options.input_file != None):
        with open(options.input_file, mode=fd_read_options) as fd_input:
            for line in fd_input:
                line = line.strip()
                
                # We match a snmp block
                if p_entering_snmp_block.search(line):
                    in_snmp_block = True
                
                # We are in a snmp block
                if in_snmp_block:
                    if p_snmp_number.search(line):
                        snmp_number = p_snmp_number.search(line).group('snmp_number')
                        snmp_elem['id'] = snmp_number
                        if not('id' in order_keys):
                            order_keys.append('id')
                    
                    # We match a setting
                    if p_snmp_set.search(line):
                        snmp_key = p_snmp_set.search(line).group('snmp_key')
                        if not(snmp_key in order_keys):
                            order_keys.append(snmp_key)
                        
                        snmp_value = p_snmp_set.search(line).group('snmp_value').strip()
                        snmp_value = re.sub('["]', '', snmp_value)
                        snmp_elem[snmp_key] = snmp_value
                    
                    # We are done with the current snmp id
                    if p_snmp_next.search(line):
                        snmp_list.append(snmp_elem)
                        snmp_elem = {}
                
                # We are exiting the snmp block
                if p_exiting_snmp_block.search(line):
                        in_snmp_block = False
        return (snmp_list, order_keys)

    else:
        #for files in os.listdir(os.path.abspath(options.input_folder)):
        with open(full_path, mode=fd_read_options) as fd_input:
            for line in fd_input:
                line = line.strip()
                
                # We match a snmp block
                if p_entering_snmp_block.search(line):
                    in_snmp_block = True
                
                # We are in a snmp block
                if in_snmp_block:
                    if p_snmp_number.search(line):
                        snmp_number = p_snmp_number.search(line).group('snmp_number')
                        snmp_elem['id'] = snmp_number
                        if not('id' in order_keys):
                            order_keys.append('id')
                    
                    # We match a setting
                    if p_snmp_set.search(line):
                        snmp_key = p_snmp_set.search(line).group('snmp_key')
                        if not(snmp_key in order_keys):
                            order_keys.append(snmp_key)
                        
                        snmp_value = p_snmp_set.search(line).group('snmp_value').strip()
                        snmp_value = re.sub('["]', '', snmp_value)
                        snmp_elem[snmp_key] = snmp_value
                    
                    # We are done with the current snmp id
                    if p_snmp_next.search(line):
                        snmp_list.append(snmp_elem)
                        snmp_elem = {}
                
                # We are exiting the snmp block
                if p_exiting_snmp_block.search(line):
                        in_snmp_block = False
        return (snmp_list, order_keys)
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
# -- Entering vip definition block
p_entering_vip_block = re.compile(r'^\s*config firewall vip$', re.IGNORECASE)
p_entering_subvip_block = re.compile(r'^\s*config .*$', re.IGNORECASE)

# -- Exiting vip definition block
p_exiting_vip_block = re.compile(r'^end$', re.IGNORECASE)

# -- Commiting the current vip definition and going to the next one
p_vip_next = re.compile(r'^next$', re.IGNORECASE)

# -- vip number
p_vip_number = re.compile(r'^\s*edit\s+(?P<vip_number>\S*)', re.IGNORECASE)

# -- vip setting
p_vip_set = re.compile(r'^\s*set\s+(?P<vip_key>\S+)\s+(?P<vip_value>.*)$', re.IGNORECASE)

# Functions
def parse(options,full_path):
    """
        Parse the data according to several regexes
    """
    global p_entering_vip_block, p_exiting_vip_block, p_vip_next, p_vip_number, p_vip_set
    
    in_vip_block = False
    vip_list = []
    vip_elem = {}
    order_keys = []
    
    if (options.input_file != None):
        with open(options.input_file, mode=fd_read_options) as fd_input:
            for line in fd_input:
                line = line.strip()
                
                # We match a vip block
                if p_entering_vip_block.search(line):
                    in_vip_block = True
                
                # We are in a vip block
                if in_vip_block:
                    if p_vip_number.search(line):
                        vip_number = p_vip_number.search(line).group('vip_number')
                        vip_number = re.sub('["]', '', vip_number)
                        vip_elem['id'] = vip_number
                        if not('id' in order_keys):
                            order_keys.append('id')
                    
                    # We match a setting
                    if p_vip_set.search(line):
                        vip_key = p_vip_set.search(line).group('vip_key')
                        if not(vip_key in order_keys):
                            order_keys.append(vip_key)
                        
                        vip_value = p_vip_set.search(line).group('vip_value').strip()
                        vip_value = re.sub('["]', '', vip_value)
                        vip_elem[vip_key] = vip_value
                    
                    # We are done with the current vip id
                    if p_vip_next.search(line):
                        vip_list.append(vip_elem)
                        vip_elem = {}
                
                # We are exiting the vip block
                if p_exiting_vip_block.search(line):
                        in_vip_block = False
        return (vip_list, order_keys)


    else:
       # for files in os.listdir(os.path.abspath(options.input_folder)):
        with open(full_path, mode=fd_read_options) as fd_input:
            for line in fd_input:
                line = line.strip()
                
                # We match a vip block
                if p_entering_vip_block.search(line):
                    in_vip_block = True
                
                # We are in a vip block
                if in_vip_block:
                    if p_vip_number.search(line):
                        vip_number = p_vip_number.search(line).group('vip_number')
                        vip_number = re.sub('["]', '', vip_number)
                        vip_elem['id'] = vip_number
                        if not('id' in order_keys):
                            order_keys.append('id')
                    
                    # We match a setting
                    if p_vip_set.search(line):
                        vip_key = p_vip_set.search(line).group('vip_key')
                        if not(vip_key in order_keys):
                            order_keys.append(vip_key)
                        
                        vip_value = p_vip_set.search(line).group('vip_value').strip()
                        vip_value = re.sub('["]', '', vip_value)
                        vip_elem[vip_key] = vip_value
                    
                    # We are done with the current vip id
                    if p_vip_next.search(line):
                        vip_list.append(vip_elem)
                        vip_elem = {}
                
                # We are exiting the vip block
                if p_exiting_vip_block.search(line):
                        in_vip_block = False
        return (vip_list, order_keys)
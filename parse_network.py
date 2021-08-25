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

# -- Entering interface definition block
p_entering_interface_block = re.compile(r'^\s*config system interface$', re.IGNORECASE)
p_entering_subinterface_block = re.compile(r'^\s*config .*$', re.IGNORECASE)

# -- Exiting interface definition block
p_exiting_interface_block = re.compile(r'^end$', re.IGNORECASE)

# -- Commiting the current interface definition and going to the next one
p_interface_next = re.compile(r'^next$', re.IGNORECASE)

# -- interface number
p_interface_number = re.compile(r'^\s*edit\s+(?P<interface_number>\S*)', re.IGNORECASE)

# -- interface setting
p_interface_set = re.compile(r'^\s*set\s+(?P<interface_key>\S+)\s+(?P<interface_value>.*)$', re.IGNORECASE)

# Functions
def parse(options,full_path):
    """
        Parse the data according to several regexes
        
        @param options:  options
        @rtype: return a list of policies ( [ {'id' : '1', 'srcintf' : 'internal', ...}, {'id' : '2', 'srcintf' : 'external', ...}, ... ] )  
                and the list of unique seen keys ['id', 'srcintf', 'dstintf', ...]
    """
    global p_entering_interface_block, p_exiting_interface_block, p_interface_next, p_interface_number, p_interface_set, fw_directory_path
    
    in_interface_block = False
    interface_list = []
    interface_elem = {}
    order_keys = []
    
    if (options.input_file != None):
        with open(options.input_file, mode=fd_read_options) as fd_input:
            for line in fd_input:
                line = line.strip()
                
                # We match a interface block
                if p_entering_interface_block.search(line):
                    in_interface_block = True
                
                # We are in a interface block
                if in_interface_block:
                    if p_interface_number.search(line):
                        interface_number = p_interface_number.search(line).group('interface_number')
                        interface_elem['id'] = interface_number
                        if not('id' in order_keys):
                            order_keys.append('id')
                    
                    # We match a setting
                    if p_interface_set.search(line):
                        interface_key = p_interface_set.search(line).group('interface_key')
                        if not(interface_key in order_keys):
                            order_keys.append(interface_key)
                        
                        interface_value = p_interface_set.search(line).group('interface_value').strip()
                        interface_value = re.sub('["]', '', interface_value)
                        interface_elem[interface_key] = interface_value
                    
                    # We are done with the current interface id
                    if p_interface_next.search(line):
                        interface_list.append(interface_elem)
                        interface_elem = {}
                
                # We are exiting the interface block
                if p_exiting_interface_block.search(line):
                        in_interface_block = False
        return (interface_list, order_keys)

    else:
        with open(full_path, mode=fd_read_options) as fd_input:
            for line in fd_input:
                line = line.strip()
                
                # We match a interface block
                if p_entering_interface_block.search(line):
                    in_interface_block = True
                
                # We are in a interface block
                if in_interface_block:
                    if p_interface_number.search(line):
                        interface_number = p_interface_number.search(line).group('interface_number')
                        interface_number = re.sub('["]', '', interface_number)
                        interface_elem['id'] = interface_number
                        if not('id' in order_keys):
                            order_keys.append('id')
                    
                    # We match a setting
                    if p_interface_set.search(line):
                        interface_key = p_interface_set.search(line).group('interface_key')
                        if not(interface_key in order_keys):
                            order_keys.append(interface_key)
                        
                        interface_value = p_interface_set.search(line).group('interface_value').strip()
                        interface_value = re.sub('["]', '', interface_value)
                        interface_elem[interface_key] = interface_value
                    
                    # We are done with the current interface id
                    if p_interface_next.search(line):
                        interface_list.append(interface_elem)
                        interface_elem = {}

                # We are exiting the interface block
                if p_exiting_interface_block.search(line):
                        in_interface_block = False
        return (interface_list, order_keys)



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
# -- Entering service definition block
p_entering_service_block = re.compile(r'^\s*config firewall service group$', re.IGNORECASE)
p_entering_subservice_block = re.compile(r'^\s*config .*$', re.IGNORECASE)

# -- Exiting service definition block
p_exiting_service_block = re.compile(r'^end$', re.IGNORECASE)

# -- Commiting the current service definition and going to the next one
p_service_next = re.compile(r'^next$', re.IGNORECASE)

# -- service number
p_service_number = re.compile(r'^\s*edit\s+.(?P<service_number>\S*)', re.IGNORECASE)

# -- service setting
p_service_set = re.compile(r'^\s*set\s+(?P<service_key>\S+)\s+(?P<service_value>.*)$', re.IGNORECASE)

# Functions
def parse(options,full_path):
    """
        Parse the data according to several regexes
    """
    global p_entering_service_block, p_exiting_service_block, p_service_next, p_service_number, p_service_set
    
    in_service_block = False
    service_list = []
    service_elem = {}
    order_keys = []

    if (options.input_file != None):
        with open(options.input_file, mode=fd_read_options) as fd_input:
            for line in fd_input:
                line = line.strip()
                
                # We match a service block
                if p_entering_service_block.search(line):
                    in_service_block = True
                
                # We are in a service block
                if in_service_block:
                    if p_service_number.search(line):
                        service_number = p_service_number.search(line).group('service_number')
                        service_number = re.sub('["]', '', service_number)
                        service_elem['name'] = service_number
                        if not('name' in order_keys):
                            order_keys.append('name')
                    
                    # We match a setting
                    if p_service_set.search(line):
                        service_key = p_service_set.search(line).group('service_key')
                        if not(service_key in order_keys):
                            order_keys.append(service_key)
                        
                        service_value = p_service_set.search(line).group('service_value').strip()
                        service_value = re.sub('["]', '', service_value)
                        service_elem[service_key] = service_value
                    
                    # We are done with the current service id
                    if p_service_next.search(line):
                        service_list.append(service_elem)
                        service_elem = {}
                
                # We are exiting the service block
                if p_exiting_service_block.search(line):
                        in_service_block = False
        return (service_list, order_keys)

    else:
        #for files in os.listdir(os.path.abspath(options.input_folder)):
        with open(full_path, mode=fd_read_options) as fd_input:
            for line in fd_input:
                line = line.strip()
                
                # We match a service block
                if p_entering_service_block.search(line):
                    in_service_block = True
                
                # We are in a service block
                if in_service_block:
                    if p_service_number.search(line):
                        service_number = p_service_number.search(line).group('service_number')
                        service_number = re.sub('["]', '', service_number)
                        service_elem['name'] = service_number
                        if not('name' in order_keys):
                            order_keys.append('name')
                    
                    # We match a setting
                    if p_service_set.search(line):
                        service_key = p_service_set.search(line).group('service_key')
                        if not(service_key in order_keys):
                            order_keys.append(service_key)
                        
                        service_value = p_service_set.search(line).group('service_value').strip()
                        service_value = re.sub('["]', '', service_value)
                        service_elem[service_key] = service_value
                    
                    # We are done with the current service id
                    if p_service_next.search(line):
                        service_list.append(service_elem)
                        service_elem = {}
                
                # We are exiting the service block
                if p_exiting_service_block.search(line):
                        in_service_block = False
        return (service_list, order_keys)
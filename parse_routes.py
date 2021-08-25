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
# -- Entering router definition block
p_entering_router_block = re.compile(r'^\s*config router static$', re.IGNORECASE)
p_entering_subrouter_block = re.compile(r'^\s*config .*$', re.IGNORECASE)

# -- Exiting router definition block
p_exiting_router_block = re.compile(r'^end$', re.IGNORECASE)

# -- Commiting the current router definition and going to the next one
p_router_next = re.compile(r'^next$', re.IGNORECASE)

# -- router number
p_router_number = re.compile(r'^\s*edit\s+(?P<router_number>\S*)', re.IGNORECASE)

# -- router setting
p_router_set = re.compile(r'^\s*set\s+(?P<router_key>\S+)\s+(?P<router_value>.*)$', re.IGNORECASE)

# Functions
def parse(options,full_path):
    """
        Parse the data according to several regexes
    """
    global p_entering_router_block, p_exiting_router_block, p_router_next, p_router_number, p_router_set

    in_router_block = False
    router_list = []
    router_elem = {}
    order_keys = []

    if (options.input_file != None):
        with open(options.input_file, mode=fd_read_options) as fd_input:
            for line in fd_input:
                line = line.strip()
                
                # We match a router block
                if p_entering_router_block.search(line):
                    in_router_block = True
                
                # We are in a router block
                if in_router_block:
                    if p_router_number.search(line):
                        router_number = p_router_number.search(line).group('router_number')
                        router_number = re.sub('["]', '', router_number)
                        router_elem['id'] = router_number
                        if not('id' in order_keys):
                            order_keys.append('id')
                    
                    # We match a setting
                    if p_router_set.search(line):
                        router_key = p_router_set.search(line).group('router_key')
                        if not(router_key in order_keys):
                            order_keys.append(router_key)
                        
                        router_value = p_router_set.search(line).group('router_value').strip()
                        router_value = re.sub('["]', '', router_value)
                        router_elem[router_key] = router_value
                    
                    # We are done with the current router id
                    if p_router_next.search(line):
                        router_list.append(router_elem)
                        router_elem = {}
                
                # We are exiting the router block
                if p_exiting_router_block.search(line):
                        in_router_block = False
        return (router_list, order_keys)
    else:
        #for files in os.listdir(os.path.abspath(options.input_folder)):
        with open(full_path, mode=fd_read_options) as fd_input:
            for line in fd_input:
                line = line.strip()
                
                # We match a router block
                if p_entering_router_block.search(line):
                    in_router_block = True
                
                # We are in a router block
                if in_router_block:
                    if p_router_number.search(line):
                        router_number = p_router_number.search(line).group('router_number')
                        router_number = re.sub('["]', '', router_number)
                        router_elem['id'] = router_number
                        if not('id' in order_keys):
                            order_keys.append('id')
                    
                    # We match a setting
                    if p_router_set.search(line):
                        router_key = p_router_set.search(line).group('router_key')
                        if not(router_key in order_keys):
                            order_keys.append(router_key)
                        
                        router_value = p_router_set.search(line).group('router_value').strip()
                        router_value = re.sub('["]', '', router_value)
                        router_elem[router_key] = router_value
                    
                    # We are done with the current router id
                    if p_router_next.search(line):
                        router_list.append(router_elem)
                        router_elem = {}
                
                # We are exiting the router block
                if p_exiting_router_block.search(line):
                        in_router_block = False
        return (router_list, order_keys)

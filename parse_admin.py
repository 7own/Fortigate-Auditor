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

# Python 2 and 3 compatibility
if (sys.version_info < (3, 0)):
    fd_read_options = 'rb'
    fd_write_options = 'wb'
else:
    fd_read_options = 'r'
    fd_write_options = 'w'

# Handful patterns
# -- Entering username definition block
p_entering_username_block = re.compile(r'^\s*config system admin$', re.IGNORECASE)
p_entering_subusername_block = re.compile(r'^\s*config .*$', re.IGNORECASE)

# -- Exiting username definition block
p_exiting_username_block = re.compile(r'^end$', re.IGNORECASE)

# -- Commiting the current username definition and going to the next one
p_username_next = re.compile(r'^    next$')

# -- username number
p_username_number = re.compile(r'^\s*edit\s+.(?P<username_number>\S*)"', re.IGNORECASE)

# -- username setting
p_username_set = re.compile(r'^\s*set\s+(?P<username_key>\S+)\s+(?P<username_value>.*)$', re.IGNORECASE)

# Functions
def parse(options,full_path):
	"""
		Parse the data according to several regexes
	"""
	global p_entering_username_block, p_exiting_username_block, p_username_next, p_username_number, p_username_set
	
	in_username_block = False
	username_list = []
	username_elem = {}
	order_keys = []
	
	if (options.input_file != None):
		with open(options.input_file, mode=fd_read_options) as fd_input:
			for line in fd_input:
				line = line.strip()
				
				# We match a username block
				if p_entering_username_block.search(line):
					in_username_block = True
				
				# We are in a username block
				if in_username_block:
					if p_username_number.search(line):
						username_number = p_username_number.search(line).group('username_number')
						username_number = re.sub('["]', '', username_number)
						username_elem['id'] = username_number
						if not('id' in order_keys):
							order_keys.append('id')
					
					# We match a setting
					if p_username_set.search(line):
						username_key = p_username_set.search(line).group('username_key')
						if not(username_key in order_keys):
							order_keys.append(username_key)
						
						username_value = p_username_set.search(line).group('username_value').strip()
						username_value = re.sub('["]', '', username_value)
						username_elem[username_key] = username_value
					
					# We are done with the current username id
					if p_username_next.search(line):
						username_list.append(username_elem)
						username_elem = {}
				
				# We are exiting the username block
				if p_exiting_username_block.search(line):
						in_username_block = False
		return (username_list, order_keys)

	else:
		#for files in os.listdir(os.path.abspath(options.input_folder)):
		with open(full_path, mode=fd_read_options) as fd_input:
			for line in fd_input:
				line = line.strip()
				
				# We match a username block
				if p_entering_username_block.search(line):
					in_username_block = True
				
				# We are in a username block
				if in_username_block:
					if p_username_number.search(line):
						username_number = p_username_number.search(line).group('username_number')
						username_number = re.sub('["]', '', username_number)
						username_elem['id'] = username_number
						if not('id' in order_keys):
							order_keys.append('id')
					
					# We match a setting
					if p_username_set.search(line):
						username_key = p_username_set.search(line).group('username_key')
						if not(username_key in order_keys):
							order_keys.append(username_key)
						
						username_value = p_username_set.search(line).group('username_value').strip()
						username_value = re.sub('["]', '', username_value)
						username_elem[username_key] = username_value
					
					# We are done with the current username id
					if p_username_next.search(line):
						username_list.append(username_elem)
						username_elem = {}
						
				# We are exiting the username block
				if p_exiting_username_block.search(line):
						in_username_block = False
		return (username_list, order_keys)


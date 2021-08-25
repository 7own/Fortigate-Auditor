#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Script for exporting configuration files into CSV file

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
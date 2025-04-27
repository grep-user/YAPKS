#!/usr/bin/env python3
import os
import sys
from pathlib import Path

from apkleaks.apkleaks import APKLeaks
from apkleaks.colors import color as col


def key_scan(input_args):
	print("-------")
	args = {}
	args['file']  = input_args.get('file')
	# args['output'] = input_args.get('output')
	args['json'] = input_args.get('json',False)
	if(args.get('listOfApks') != None):
		apk_list = args.get('listOfApks').split(",")
		for i in apk_list:
			print(i)
			args.file = i
			init = APKLeaks(args)
			try:
				init.integrity()
				init.decompile()
				init.scanning()
			finally:
				init.cleanup()
	else:
		print(args)
		init = APKLeaks(args)
		try:
			init.integrity()
			init.decompile()
			init.scanning()
		finally:
			pass
			init.cleanup()  

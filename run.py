import sys
from analyze import (get_manifest,manifest_data,manifest_analysis)
from libsast import Scanner
import os
import json
from mobsfscan.mobsfscan import MobSFScan
from apkleaks.apkleaks import APKLeaks
from apkleaks.colors import color as col
from apkleaks.utils import util
from datetime import datetime

AGGR_RULES_PATH = os.path.join(os.getcwd(),"rules","agressive/")
SRC_PATH = '/sources'
VULN_LIBS = ['org/apache/commons/collections/']

def getActions(mfxml):
    applications = mfxml.getElementsByTagName('application')
    result_dic = {}
    for application in applications:
        for node in application.childNodes:
            intentfilters = node.childNodes
            for i in intentfilters:
                result = []
                if i.nodeName == 'intent-filter':
                    x =i 
                    for j in range(len(x.getElementsByTagName('action'))):
                        result.append(i.getElementsByTagName('action')[j].getAttribute('android:name'))
                    result_dic[node.getAttribute('android:name')] = result
    return result_dic
  
  

def get_exported_components(tmp_dir):
    app_dic = {}
    man_data_dic = {}
    app_dic['manifest_file'], app_dic['parsed_xml'] = get_manifest(tmp_dir,"","","custom")
    man_data_dic = manifest_data(app_dic['parsed_xml'])
    # print(man_data_dic)  
    
    
    # Get actions from android manifest
    
      
    man_an_dic = manifest_analysis(
                    app_dic['parsed_xml'],
                    man_data_dic,
                    '',
                    ''
                )
    
    return app_dic,man_an_dic 
    
def get_path(exported_components,tmp_dir):
    path_list = []
    for comp in exported_components:
        path = os.path.join(tmp_dir,"sources",comp.replace('.','/')+".java")
        path_list.append(path)
    return path_list  

def apkleaks_scan():
	if(args.listOfApks != None):
		apk_list = args.listOfApks.split(",")
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
		init = APKLeaks(args)
		try:
			decompile_path = init.decompile()
			init.scanning()
		finally:
			init.cleanup()



def aggressive_scan(tmp_dir,fileout):
    app_dic , man_an_dic = get_exported_components(tmp_dir)
    man_data_dic = manifest_data(app_dic['parsed_xml'])
    
    browsable_activities = []
    for i in man_an_dic.get("browsable_activities").keys():browsable_activities.append(man_an_dic.get("browsable_activities").get(i))
    exported_comp = man_an_dic.get('exported_act')
    exported_comp.append(man_data_dic.get('mainactivity'))
    paths = get_path(exported_comp,tmp_dir)
    
    exported_contents = man_an_dic.get('exported_cnt')
    options = {'sgrep_rules':AGGR_RULES_PATH}
    scanner = Scanner(options, paths)
    
    if(fileout != None):
        scan = scanner.scan()
        # fileout.write("%s" % (json.dumps({'paths':paths}, indent=4)))
        fileout.write("%s" % (json.dumps({'exported_activities':exported_comp},indent=4)))
        fileout.write("%s" % (json.dumps({'exported_contents':exported_contents},indent=4)))
        fileout.write("%s" % (json.dumps({'browsable_activity':browsable_activities}, indent=4)))
        fileout.write("%s" % (json.dumps(scan, indent=4)))
        fileout.write("%s" % (json.dumps({'actions':getActions(app_dic['parsed_xml'])},indent=4)))
        fileout.write("%s" % (json.dumps({'vulnerable library':get_libraries(tmp_dir)},indent=4)))
        
    else:
        util.writeln("Exported Activities", col.BOLD)
        util.writeln(str(exported_comp), col.OKGREEN)
        print()
        
        util.writeln("Exported Contents", col.BOLD)
        util.writeln(str(exported_contents), col.OKGREEN)
        print()
        
        util.writeln("Browsable Activities", col.BOLD)
        util.writeln(str(browsable_activities), col.OKGREEN)
        print()
            
        # util.writeln("Exported activities path", col.BOLD)
        # util.writeln(str(paths), col.OKGREEN)
        # print()
        # print(options)
            
        util.writeln("Aggressive scan results", col.BOLD)
        util.writeln(str(scanner.scan()), col.OKGREEN)
        print()
        
        util.writeln("activity actions",col.BOLD)
        util.writeln(str(getActions(app_dic['parsed_xml'])),col.OKGREEN)
        print()
        
        util.writeln("vulnerable library",col.BOLD)
        util.writeln(str(get_libraries(tmp_dir)),col.OKGREEN)
        print()
  
PATHS = ['android','androidx','org/apache/commons','retrofit2','okhttp3','com/microsoft','com/ReactNativeBlobUtil','com/google','com/facebook','org/spongycastle']
      
def get_libraries(directory_path):
    all_files = []
    for root,dirs,files in os.walk(directory_path):
        # for path in PATHS:
        #     if path in dirs:break
        for dir in dirs:
            res = any(path in dirs for path in PATHS)
            if res:break
            dir_path = os.path.join(root,dir)
            all_files.append(dir_path)
    vuln = ['']
        
        # Need to add this if vuln_libs in list of files
        # for files in all_files:
        #     if any(files in vuln_path for vuln_path in VULN_LIBS):
        #         print(files)
        #         vuln.append(files)
    for files in all_files:
        if VULN_LIBS[0] in files:
            vuln.append(files)
            # print(files)
    return vuln
    # return all_files


def normal_scan(tmp_dir,fileout):
    config_path = os.path.join(os.getcwd(),"sample.mobsf")
    scanner = MobSFScan([tmp_dir+SRC_PATH], json=True,config=config_path)
    # print(scanner.conf['ignore_paths'])
    src_path = tmp_dir + SRC_PATH
    # IGNORE PATHS
    
    for path in PATHS:
        scanner.conf['ignore_paths'].add(os.path.join(src_path,path))
        # print(os.path.join(src_path,path))
    if(fileout != None):
        fileout.write("%s" % (json.dumps(scanner.scan(), indent=4)))
    else:
        util.writeln("Normal scan results", col.BOLD)
        util.writeln(str(scanner.scan()), col.OKGREEN)    
        print()
    # scanner = MobSFScan([src], json=True,config='/home/local/ZOHOCORP/praveen-14116/tools/custom_rules/sample/ss.mobsf')

def start_scan(input_args,K_scan,N_scan,A_scan,saveToFile):
	args = {}
	args['file']  = input_args.get('file')
	# args['output'] = input_args.get('output')
	args['json'] = input_args.get('json',False)
    
    # Output file

	# Starting scan
	init = APKLeaks(args)
	try:
		init.integrity()
		init.decompile()
		print("\033[96m Tmp Dir: {}\033[00m".format(init.tempdir))
		if K_scan: init.scanning()
		fileout = None
		if saveToFile:
			output = os.path.join(os.getcwd(),"outputs", datetime.now().strftime(init.apk.package+"-%d-%m-%Y")+'--scan'+'.json')
			fileout = open(output, "%s" % ("w" if saveToFile else "a"))		
		if N_scan: normal_scan(init.tempdir,fileout)
		if A_scan: aggressive_scan(init.tempdir,fileout)
	finally:
		init.cleanup()
		if saveToFile:
			fileout.close()
		

def apkleaks_scan(path):
    pass

	
if __name__ == '__main__':    
    args = {}
    args['file'] = sys.argv[1]
    # args['file'] = './base.apk'
    args['json'] = True
    # args['listOfApks'] = []
    
    if(args.get('listOfApks') != None):
        apk_list = args.get('listOfApks') 
        for apk in apk_list:
            args['file'] = apk
            start_scan(args,K_scan=True,N_scan=True,A_scan=True,saveToFile=True)
    else:
        start_scan(args,K_scan=True,N_scan=True,A_scan=True,saveToFile=True)
    
		


# /var/folders/dg/x_k6_dfd12lc57hpdkjzz94c0000gp/T/apkleaks-vu9rv2vx
# Check if the file is deleted on turn Off
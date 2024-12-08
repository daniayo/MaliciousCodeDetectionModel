import json
import urllib
import sys
import os
import time
import re
import hashlib

_md5 = '[a-z0-9]{32}'

path_dir = './malware_samples'
file_list = os.listdir(path_dir)

md5_pattern = re.compile(_md5)

class vtAPI():
	def __init__(self):
		self.api = '-'
		self.base = 'https://www.virustotal.com/vtapi/v2/'
	
	def getReport(self,md5):
		param = {'resource':md5,'apikey':self.api,'allinfo': '1'}
		url = self.base + "file/report"
		data = urllib.urlencode(param)
		result = urllib.urlopen(url,data)
		
		jdata = json.loads(result.read())

		if jdata['response_code'] == 0:
			print(md5 + " -- Not Found in VT")
			return "no"
		else:
			print("=== Results for MD5: ", jdata['md5'], "\tDetected by: ", jdata['positives'])
			return jdata['positives']


	def reqScan(self,filepath):
		print("- Requesting a new scan")
		param = {'file':filepath,'apikey':self.api}
		url = self.base + "file/scan"
		data = urllib.urlencode(param)
		result = urllib.urlopen(url,data)
		
		jdata = json.loads(result.read())
		
		return jdata

	def getMd5(self, filepath, blocksize=8192):
	    md5 = hashlib.md5()
	    try:
	        f = open(filepath, "rb")
	    except IOError as e:
	        print("file open error", e)
	        return
	    while True:
	        buf = f.read(blocksize)
	        if not buf:
	            break
	        md5.update(buf)
	    return md5.hexdigest()


def main():

	vt = vtAPI()
	i = 0

	for file in file_list:

		before = path_dir + "/" + file
		name_check = re.search(md5_pattern, file)

		if name_check == None:
			file = vt.getMd5(before)

		try:
			i += 1
			rns = vt.getReport(file)
			if(rns == "no"):
				file_path = os.getcwd() + "/" + file
				rns = vt.reqScan(file_path)
				file = rns['md5']

				while True:
					time.sleep(20)
					rns = vt.getReport(file)
					if(rns != "no"):
						break
				
			after = path_dir + "/" + str(rns) + "#" + file

			print("Processed " + str(i) + " files - "+ after)
			os.rename(before, after)

			time.sleep(15)
		except:
			pass

	

if __name__ == '__main__':
	main()

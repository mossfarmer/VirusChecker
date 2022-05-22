import requests
import re
d  = re.compile(r"^[a-f0-9]{32}(:.+)?$", re.IGNORECASE) # MD5
e =  re.compile(r"^[a-f0-9]{64}(:.+)?$", re.IGNORECASE) # SHA-256
while(1):
	hasher = input("Enter file hash\n").strip()
	key = input("Enter API key \n")
	if((d.match(hasher) or e.match(hasher)) and e.match(key)) :
		response = requests.get("https://www.virustotal.com/api/v3/search?query=" + hasher,headers={'x-apikey': key})
		code = re.findall(r'\d+',str(response))
		#print(response.text)
		if('200' in code):
			a = response.text 
			bad = (a[a.find('last_analysis_stats')+270:a.find('last_analysis_stats')+290]).split()[1] # index of malicious +12 is # of malicious reports
			bad = bad.replace(',','')
			#print(bad)
			if(int(bad) >= 5): #idk if its inclusive or not
				print("File is Malicious, " + str(bad) + " anti-virus softwares have labeled the file as such")
			elif(int(bad) > 0 and int(bad) < 5): 
				print("File may be  Malicious," + str(bad) + " anti-virus softwares have labeled the file as such")
			elif(int(bad) == 0):
				print("File is clean")
		print("API Call status code " + str(code) + "\n")
		if('200' not in code):
			print("API call failed\n")
	else: 
		print("Invalid Hash or Key\n")

		#print(a[a.find('malicious')+12]) #1669  malicious +

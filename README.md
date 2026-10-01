# Threat intelligence 
# understand the differences in the type of threat intelligence .gathering intelligence from Open Sources Intelligence(OSINT)platforms.identify indicators of compromise(IOCs).Analyze malicious IPs, Domains, URLs, and file hashes.               
# features :                                                                                                      -Tactical                                                                                                      - Operational                                    - Technical
Tools used : 
VirusTotal
AbuseIPDB
AlienVault OTX
Cisco Talos
URLVoid.
# OS: windows   
# AbuseIPDB
# procedure: Investigate the IP Address 185.220.101.45
Go to https://www.abuseipdb.com/  
Paste 185.220.101.45 into the search box and click check.  
# Results/Findings.   
confidence of Abuse: 100%   
Total Reports : 6,523 times   
Country: Germany   
ISP/Network:Network for Tor-Exit traffic.  
Hostname: Tor-exit-46.for-privacy.net   
Usage Type : fixed line ISP  
Domain name : For-Privacy.net     
<img width="3024" height="2279" alt="IMG_5670" src="https://github.com/user-attachments/assets/2db29495-c03e-434a-88b6-a0a6c1cb7c35" />  
Recent Activities : Still actively reported (SSH brute-force, web attacks, scanning ,Etc.)   
<img width="3024" height="2343" alt="IMG_5669" src="https://github.com/user-attachments/assets/4c635ebd-4ab5-432f-a688-80a8d21576e6" />  
It is a known TOR EXIT NODE .The owner is not directly malicious ,but traffic exiting Tor is frequently abused.   
# VirusTotal  
# Procedure :   
Go to https://www.virustotal.com/   
input the IPaddress : 185.220.101.45  
Results : multiple detections, Community comments flagging it as Tor exit / malicious traffic, high number of related files/URLs that contacted it.  
community scores : 16   
country : Germany   
<img width="3024" height="2529" alt="IMG_5674" src="https://github.com/user-attachments/assets/4b874865-be54-4df0-8800-4db957155820" />  
<img width="4284" height="3452" alt="IMG_5675" src="https://github.com/user-attachments/assets/da9850e4-b1f8-4d6e-86c8-36200a19599c" />  
# Cisco Talos    
Go to ; https://talosintelligence.com/  
input the IP address : 185.220.101.45   
Result : high risk reputation categorized under anonymous proxies/Tor-related activity.  
<img width="3024" height="2348" alt="IMG_5680" src="https://github.com/user-attachments/assets/4b56382a-042a-4186-9273-722737326c94" />  
# Alienvault OTX  
Go to : https://otx.alienvault.com/  
search the IP:185.220.101.45   
Results: Pulses(threat reports) linking it to Tor exit nodes, Scanning , or abuse.  
<img width="4253" height="3050" alt="IMG_5683" src="https://github.com/user-attachments/assets/a4bd68f2-c30b-47cb-b643-e4bef7475d5b" />  
verdict for the IP :Malicious/high risk(Tor exit node heavily abused for attacks) .    
# TASK 02  
Threat intelligence using virustotal objective  
Analyze a suspicious domain.   
# Procedures  
Open virus total (www.virustotal.com)  
Search the provided domain (suspicious-update.com)  
<img width="4284" height="3030" alt="IMG_5739" src="https://github.com/user-attachments/assets/d8a65a4c-194b-4868-b20c-48d1f15e4eb9" />  
No security officer flagged this domain as malicious, clean and no malicious record.  
Open www.urlvoid.com  
<img width="4284" height="3041" alt="IMG_5740" src="https://github.com/user-attachments/assets/7eb93894-2a2f-4022-b9e4-0a5cbdc10252" />  
No security officer flagged this domain as malicious.

Open https://otx.alienvault.com   
<img width="3024" height="2210" alt="IMG_5741" src="https://github.com/user-attachments/assets/cebaf90e-4840-41e2-be9e-303311ffa305" />  
No security officer flagged this domain as malicious   

Open https://talosintellegence.com    
<img width="4284" height="3100" alt="IMG_5743" src="https://github.com/user-attachments/assets/b0e61734-3b66-4029-b033-b1446266cf32" />   
No security officer flagged this domain as malicious .
# Investigate the hash :  
44d88612fea8a8f36de82e1278abb02f   
this is MD5 hash (32 hex characters ).  
Go to VirusTotal , then paste the hash .
File type : EICAR virus test file 
size: 0kb(68bytes)
antivirus detected : EICAR - test - signature , virus:DOS/EICAR -test - file .  
yara dectections : SUSP_Just_EICAR, eicar_av_test  
Retention pulse : 50(pulse) OTX User created    
Verdict : Malicious    
Risk -level : medium (or low - medium ,since its only a test file .)  
File Scores : 6 (medium risk).   
<img width="1487" height="1105" alt="IMG_5746" src="https://github.com/user-attachments/assets/5d32a5be-7c8c-4f8a-91fa-ec1d925edf6c" />  
NOTE: when you open the same hash on virustotal , you'll see the same EICAR identification with a long list of AV detection   

<img width="3024" height="2311" alt="IMG_5744" src="https://github.com/user-attachments/assets/c83c8a46-62a2-4e97-9ea8-3c3e60fe6442" />     
  
# Note:     
confirm as the EICAR antivirus test file.   
Detected by multiple engines as EICAR-TEST-Signature / virus:DOS/EICAR_test_file.     
File size 68bytes.    
type :EICAR virus test files.     
file score on OTX:6 (medium).      
harmless by design - used only for testing av detection.      
# Task 03 : hash Analysis .  
On virustotal   
Detection engine: 62/66  
common names : EICAR-TEST-FILE  
Eicar-test-signature .
File type : Powershell 
malware family : EICAR-test-file (not real malware)  
file size : 68 bytes   
first seen : 2012-06-14   
community scores : 3794  
<img width="1500" height="1041" alt="IMG_5748" src="https://github.com/user-attachments/assets/4faff018-b672-4d32-aaf4-ea63f811dc22" />  
detected as malicious (not actually malicious ) ,malware associated is EICAR ,and we've 62 vendors that flagged this domain .  
behavior information : This info above : powershell,long-sleeps,idle,known-distribution attachment ,via-tor etc.  

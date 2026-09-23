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




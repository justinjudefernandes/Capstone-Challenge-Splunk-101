# Capstone Challenge – Splunk 101

## Scenario:
Ryan Adams, a local administrator at a small dental clinic, contacted the MahCyberDefense SOC hotline after suspecting his computer may have been compromised. He explained that around October 15 2025 at 13:00 UTC, his mouse was randomly moving so he became suspicious. As a SOC analyst, your task is to investigate this incident using Splunk. Analyze the available data to determine what occurred, identify any indicators of compromise, and document your findings in a SOC report using the provided format found in the community.

# Security Incident Investigation Report
###### Confirmed Malware Execution, Persistence, and Suspected Command-and-Control Activity

## Initial Analysis:
Following a report from Ryan Adams regarding unexpected mouse movement on his workstation, an investigation was conducted using endpoint, network, and security telemetry available within Splunk. Analysis identified the download and execution of a suspicious executable named python.exe from a non-standard directory within the user's profile. Immediately following execution, the malware performed a DNS lookup for ADDC01.KCD.local, resolving the hostname to 172.16.0.7, the internal Domain Controller. The executable subsequently established outbound communications with an external host over TCP port 8888 before initiating Microsoft RPC communications with the Domain Controller. Further analysis revealed that PowerShell later invoked schtasks.exe to create a scheduled task named PythonUpdate, configured to execute the malicious binary as SYSTEM at system startup, establishing persistence on the affected workstation.

The collected evidence confirms malicious execution, domain-aware network reconnaissance, communication with an external command-and-control server, and persistence through a scheduled task.

## Investigation Summary:
Ryan Adams, a local administrator at a small dental clinic, contacted the MahCyberDefense SOC after observing unexpected mouse movement on his workstation at approximately 13:00 UTC on 15 October 2025.

The investigation began with a review of endpoint telemetry surrounding the reported timeframe. Analysis identified that Google Chrome was launched interactively by Ryan Adams at 12:55:55 UTC. Shortly afterward, Chrome downloaded a file named python.exe into the user's Music directory (C:\Users\Ryan.Adams\Music\python.exe).

Sysmon Event ID 11 confirmed the creation of the executable, while Sysmon Event ID 15 recorded the creation of a Zone.Identifier alternate data stream, confirming that the executable originated from an external source.

At 13:00:33 UTC, Ryan Adams executed the downloaded executable using Windows Explorer. Immediately after execution, the malware performed a DNS query for ADDC01.KCD.local, successfully resolving the hostname to 172.16.0.7, the organization's internal Domain Controller. Seconds later, the malware established an outbound connection to the external IP address 157.245.46.190 over TCP port 8888, consistent with suspected command-and-control activity.

Immediately following the external connection, the malware initiated Microsoft RPC communications with 172.16.0.7, first contacting the RPC Endpoint Mapper over TCP port 135, followed by a connection to the dynamically assigned RPC port 49669. This sequence indicates that the malware intentionally resolved and communicated with the Domain Controller rather than directly connecting to a hard-coded IP address.

Approximately four minutes later, PowerShell executed schtasks.exe, creating a scheduled task named PythonUpdate configured to execute the malicious binary at system startup under the SYSTEM account, thereby establishing persistence.

### Evidence 1 – Initial Download via Google Chrome

#### Splunk Query:
```KQL Query:
index="mydfir-soc" "python.exe"
| table _time sourcetype EventCode Image TargetFilename CommandLine
| sort _time
```

#### Findings:
- At 12:57:00 UTC, Chrome created C:\Users\Ryan.Adams\Music\python.exe
- Event ID 15 recorded creation of Zone.Identifier
- Zone Identifier confirms the file originated from an external source
- Download occurred approximately three minutes before execution 

#### Screenshot:

<img width="975" height="411" alt="image" src="https://github.com/user-attachments/assets/0fbaca06-a331-479c-971c-b0703f606895" />

#### Findings Summary:
- Host: FRONTDESK-PC1
- User: Ryan Adams
- Download Source Process: chrome.exe
- File Created: python.exe
- Location: C:\Users\Ryan.Adams\Music\
- Evidence Type: Sysmon Event ID 11
- Additional Evidence: Zone.Identifier ADS
- MITRE ATT&CK: T1105 – Ingress Tool Transfer 

### Evidence 2 – Malware Execution

#### Splunk Query:

```KQL Query:
index="mydfir-soc" sourcetype=Sysmon EventCode=1 Image="*python.exe"
| table _time Image CommandLine ParentImage CurrentDirectory User ProcessGuid ParentProcessGuid
```

#### Findings:
- Executed at 13:00:33 UTC
- Launched by explorer.exe
- Executed by Ryan Adams
- Executed from a non-standard directory 

#### Screenshot:

<img width="975" height="224" alt="image" src="https://github.com/user-attachments/assets/fe67ba36-38c7-4a72-b1d7-309f0bafb9bb" />
 
#### Findings Summary:
- Process: python.exe
- Parent Process: explorer.exe
- User: Ryan Adams
- Execution Path: C:\Users\Ryan.Adams\Music\python.exe
- MITRE ATT&CK: T1204 – User Execution 

### Evidence 3 – Suspected Command-and-Control Communications

#### Splunk Query:
```KQL Query:
index="mydfir-soc" sourcetype=Sysmon EventCode=3
DestinationIp="157.245.46.190"
| table _time Image SourceIp DestinationIp DestinationPort User ProcessGuid
```

#### Findings:
- One second after execution (at 13:00:33 UTC), python.exe connected to external IP 157.245.46.190 from 172.16.0.110
- Communication occurred over TCP port 8888
- Connection timing strongly indicates malware callback activity 

#### Screenshot:

<img width="975" height="191" alt="image" src="https://github.com/user-attachments/assets/3924e18d-410b-4156-adeb-07ad459e6a8a" />

#### Findings Summary:
- Source Host: FRONTDESK-PC1
- Source Process: python.exe
- Destination IP: 157.245.46.190
- Destination Port: 8888
- Protocol: TCP
- MITRE ATT&CK: T1071 – Application Layer Protocol 

### Evidence 4 – Domain Controller Discovery and Internal RPC Communications

#### Splunk Query:

```KQL Query:
index="mydfir-soc" sourcetype=Sysmon EventCode=22
ProcessGuid="{650091ea-9af1-68ef-8e0a-000000001500}"
| table _time Image QueryName QueryResults QueryStatus
```

#### Findings:
- Immediately after execution, python.exe performed a DNS query for ADDC01.KCD.local.
- The DNS response successfully resolved the hostname to 172.16.0.7.
- This indicates that the malware identified the internal Domain Controller before initiating network communication.
- The successful lookup was immediately followed by Microsoft RPC communications to the resolved host.

#### Screenshot:

<img width="975" height="304" alt="image" src="https://github.com/user-attachments/assets/0afcb739-30aa-47d1-b5a0-05495aa5e311" />

 #### Findings Summary:
- Process: python.exe
- DNS Query: ADDC01.KCD.local
- Resolved Address: 172.16.0.7
- Result: Successful (QueryStatus = 0)
- Assessment: Malware identified the internal Domain Controller prior to initiating RPC communications.

### Evidence 5 – Internal RPC Communications

#### Splunk Query:

```KQL Query:
index="mydfir-soc" sourcetype=Sysmon EventCode=3
Image="*python.exe"
| table _time Computer User Image SourceIp DestinationIp DestinationPort Protocol ProcessGuid
| sort _time
```

#### Findings:
- Immediately after resolving ADDC01.KCD.local, the malware initiated Microsoft RPC communications with 172.16.0.7.
- Connected to the RPC Endpoint Mapper on TCP port 135.
- Established a second connection to the dynamically allocated RPC port 49669.
- Activity occurred immediately after communication with the external command-and-control server.

#### Screenshot:

<img width="975" height="301" alt="image" src="https://github.com/user-attachments/assets/ba5b27d6-3e00-4f8a-9b93-c1ec02382114" />
 
#### Findings Summary:
- Source IP: 172.16.0.110
- Destination Host: ADDC01.KCD.local
- Destination IP: 172.16.0.7
- Destination Ports: 135, 49669
- Protocol: TCP
- Assessment: Domain-aware RPC communication with the internal Domain Controller. Available telemetry confirms hostname resolution and RPC connectivity but does not demonstrate successful remote execution or compromise of the Domain Controller.

### Evidence 6 – Persistence Mechanism

#### Splunk Query:
```KQL Query:
	index="mydfir-soc" "python.exe"
	| table _time sourcetype EventCode Image TargetFilename CommandLine
	| sort -_time
```

#### Findings:
- At 13:04:59 UTC, PowerShell executed a command invoking schtasks.exe.
- The command created a scheduled task named PythonUpdate.
- The task was configured to execute C:\Users\Ryan.Adams\Music\python.exe.
- The task was configured to run at system startup. The task was configured to run under the SYSTEM account.
- This activity established persistence and would allow the malware to survive system reboots.

#### Screenshot:

<img width="975" height="241" alt="image" src="https://github.com/user-attachments/assets/393e0b50-4939-445c-bee2-79d3abc2dd38" />
 
#### Findings Summary:
- Persistence Type: Scheduled Task 
- Task Name: PythonUpdate
- Trigger: On Startup
- Account: SYSTEM
- Executable: python.exe
- MITRE ATT&CK: T1053.005 – Scheduled Task 

### Attack Timeline:
- 12:55:55 UTC – Ryan Adams launched Google Chrome via Windows Explorer.
- 12:57:00 UTC – Google Chrome created/downloaded C:\Users\Ryan.Adams\Music\python.exe.
- 12:57:18 UTC – Zone.Identifier alternate data stream was created, indicating the file originated from an external source.
- 13:00:33 UTC – Ryan Adams executed python.exe from the Music directory.
- 13:00:34 UTC – python.exe resolved ADDC01.KCD.local to 172.16.0.7 via DNS.
- 13:00:34 UTC – python.exe established an outbound connection to 157.245.46.190:8888 (suspected C2 communication).
- 13:00:34 UTC – python.exe initiated an internal RPC connection to 172.16.0.7:135.
- 13:00:35 UTC – python.exe established an additional RPC connection to 172.16.0.7:49669.
- 13:04:59 UTC – PowerShell executed a command that created the scheduled task PythonUpdate, configured to launch C:\Users\Ryan.Adams\Music\python.exe at system startup under the SYSTEM account.

### Correlation Analysis:
Correlation of endpoint, DNS, process creation, network connection, and persistence events established a complete attack sequence. The investigation confirmed that Ryan Adams launched Google Chrome, downloaded an externally sourced executable, and subsequently executed the file. Immediately following execution, the malware performed a DNS query for ADDC01.KCD.local, successfully resolving the hostname to 172.16.0.7, the organization's Domain Controller. The malware then established outbound communications with external host 157.245.46.190 over TCP port 8888, consistent with suspected command-and-control activity, before initiating Microsoft RPC communications with the resolved Domain Controller. The RPC sequence included a connection to the RPC Endpoint Mapper (TCP port 135) followed by communication over a dynamically assigned RPC port, indicating intentional interaction with a domain resource rather than an arbitrary internal host. Approximately four minutes later, PowerShell executed a command that invoked schtasks.exe to create a scheduled task named PythonUpdate. The task was configured to execute the malicious binary at system startup under the SYSTEM account, establishing persistence and ensuring execution after a reboot. The combined evidence provides high confidence that the workstation was compromised through execution of a downloaded malicious payload that demonstrated domain awareness, communicated with an external command-and-control server, and established persistence while interacting with the organization's Domain Controller.

### Triage (5W & 1H)
#### WHO:
	- Ryan Adams
	- Workstation: FRONTDESK-PC1 
#### WHAT:
	- Downloaded and executed a malicious Python executable. 
	- Performed DNS resolution of the internal Domain Controller (ADDC01.KCD.local). 
	- Established outbound communications with an external host. 
	- Initiated Microsoft RPC communications with the Domain Controller. 
	- Established persistence through a scheduled task.
#### WHEN:
•	15 October 2025 
•	12:57:00 UTC – Download 
•	13:00:33 UTC – Execution 
•	13:00:34 UTC – DNS resolution of ADDC01.KCD.local 
•	13:00:34 UTC – External callback to 157.245.46.190:8888 
•	13:00:34 UTC – Microsoft RPC communication with 172.16.0.7 
•	13:04:59 UTC – Persistence established
#### WHERE:
•	Endpoint: FRONTDESK-PC1 
•	File Path: C:\Users\Ryan.Adams\Music\python.exe 
•	External IP: 157.245.46.190
•	Domain Controller: ADDC01.KCD.local
•	Internal IP: 172.16.0.7 
#### WHY:
•	Establish unauthorized access and persistence on the endpoint. 
•	Maintain execution after system reboot. 
•	Communicate with an external command-and-control infrastructure.
•	Identify and communicate with the organization's Domain Controller, potentially to support domain reconnaissance or facilitate follow-on malicious activity.
#### HOW:
•	User launched Google Chrome. 
•	Malware was downloaded from an external source. 
•	User executed the downloaded binary. 
•	Malware resolved ADDC01.KCD.local via DNS before communicating with the Domain Controller using Microsoft RPC.
•	Malware established outbound communications and persistence through Scheduled Tasks. 

## Actions Performed:
•	Reviewed endpoint, process creation, DNS, and network telemetry surrounding the reported suspicious activity. 
•	Identified the creation of python.exe by Google Chrome within the user's profile directory. 
•	Confirmed the downloaded executable originated from an external source through analysis of the Zone.Identifier alternate data stream. 
•	Traced execution of the suspicious executable and reconstructed the complete attack sequence from download through persistence. 
•	Correlated process execution with outbound communications to external host 157.245.46.190, consistent with suspected command-and-control activity. 
•	Investigated DNS activity and confirmed that python.exe resolved ADDC01.KCD.local to 172.16.0.7 immediately before initiating internal communications. 
•	Validated the sequence of DNS resolution followed by Microsoft RPC communications with the Domain Controller, confirming intentional targeting of an internal domain resource. 
•	Investigated internal communications with ADDC01.KCD.local (172.16.0.7) to assess potential domain reconnaissance or lateral movement activity. 
•	Reviewed the execution timeline using the process GUID to correlate process creation, DNS activity, network connections, and persistence events. 
•	Confirmed persistence through creation of the scheduled task PythonUpdate. 
•	Constructed a comprehensive attack timeline using Sysmon, Zeek, Suricata, Windows Event Logs, and PowerShell telemetry. 
•	Documented indicators of compromise (IOCs), malicious artifacts, and observed attacker behaviors. 
•	Assessed the scope and impact of the activity based on available telemetry. 
•	Preserved evidence and investigation artifacts for reporting and future analysis.

## Recommendations:
•	Remove the malicious scheduled task (PythonUpdate) and any associated persistence mechanisms from affected systems. 
•	Quarantine and securely delete the malicious executable from the affected endpoint. 
•	Perform a full malware scan and endpoint health assessment on FRONTDESK-PC1. 
•	Reset credentials associated with the impacted user account and review privileged access assignments. 
•	Conduct a forensic review of ADDC01.KCD.local (172.16.0.7) to determine whether any unauthorized authentication, RPC activity, or lateral movement occurred. 
•	Review Domain Controller Security, DNS, RPC, and SMB logs for evidence of malicious activity associated with the compromised workstation. 
•	Block identified malicious IP addresses (157.245.46.190) and any related indicators of compromise at network security controls. 
•	Implement application control policies to restrict execution of binaries from user profile directories. 
•	Enhance monitoring and alerting for DNS queries targeting critical infrastructure, scheduled task creation, unusual process execution paths, Microsoft RPC activity, and outbound connections to non-standard ports. 
•	Conduct threat hunting across the environment for similar DNS, RPC, scheduled task, and command-and-control behaviors. 
•	Continue user awareness training focused on identifying suspicious downloads and executable files.

## Lessons Learned:
•	User-reported anomalies can provide valuable early indicators of malicious activity and should be investigated promptly. 
•	Correlating endpoint, DNS, and network telemetry enables more accurate reconstruction of attacker behavior and intent. 
•	Monitoring file creation, process execution, DNS resolution, and network connections is critical for identifying the complete attack chain. 
•	Executables located within user profile directories should be treated as suspicious until validated. 
•	Malware may demonstrate domain awareness by resolving and communicating with critical infrastructure such as Domain Controllers before attempting further actions. 
•	Internal RPC communications should be investigated in conjunction with DNS and authentication logs to assess potential domain reconnaissance or lateral movement. 
•	Persistence mechanisms may not always be captured through traditional Windows event logs and should be validated using multiple telemetry sources. 
•	Timely identification and containment of malicious activity reduces the likelihood of persistence and further compromise. 
•	Comprehensive logging across endpoint, DNS, network, and authentication layers significantly improves incident response and root cause analysis. 
•	Maintaining a detailed timeline of attacker activity strengthens investigative findings and supports accurate reporting. 
•	Scheduled tasks remain a frequently abused persistence mechanism and should be continuously monitored. 
•	Strong visibility into endpoint and internal network activity is essential for detecting and responding to modern threats.


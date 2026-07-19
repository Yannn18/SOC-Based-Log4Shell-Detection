# MITRE ATT&CK detection coverage map

> Complete mapping of all Wazuh detections validated through live attack simulations across the lab phases.  
> Framework: MITRE ATT&CK® Enterprise — [attack.mitre.org](https://attack.mitre.org)

---

## Coverage Summary

| Tactic               | Techniques covered   |
| -------------------- | -------------------- |
| Discovery            | T1046                |
| Initial Access       | T1190                |
| Execution            | T1059                |
| Defense Evasion      | T1211, T1574         |
| Credential Access    | T1003.008, T1552.001 |
| Lateral Movement     | T1210, T1021         |
| Privilege Escalation | T1611, T1574         |
| Command and Control  | T1105, T1071         |
| Persistence          | T1574                |
| Impact               | T1485                |

---

## Full detection matrix

| Phase   | Simulated threat vector                     | Wazuh rule ID | Type   | Alert level | ATT&CK tactic        | ATT&CK technique                  | Technique ID | Validated |
| ------- | ------------------------------------------- | ------------- | ------ | ----------- | -------------------- | --------------------------------- | ------------ | --------- |
| Phase 1 | Network Reconnaissance (Port Scan)          | 120001        | Custom | 12          | Discovery            | Network Service Discovery         | T1046        | Yes       |
| Phase 2 | Log4Shell Delivery before proxy pass        | 110050        | Custom | 15          | Initial Access       | Exploit Public-Facing Application | T1190        | Yes       |
| Phase 2 | Log4Shell JNDI execution in Container       | 110040        | Custom | 15          | Initial Access       | Exploit Public-Facing Application | T1190        | Yes       |
| Phase 3 | Java spawned shell (Log4Shell Success)      | 110030        | Custom | 14          | Execution            | Command and Scripting Interpreter | T1059        | Yes       |
| Phase 3 | Post-exploitation commands (curl, wget)     | 110031        | Custom | 14          | Command and Control  | Ingress Tool Transfer             | T1105        | Yes       |
| Phase 4 | Container filesystem overlay modification   | 100121        | Custom | 10          | Defense Evasion      | Hijack Execution Flow             | T1574        | Yes       |
| Phase 4 | Core binary modification (/bin, /etc)       | 100122        | Custom | 10          | Impact               | Data Destruction                  | T1485        | Yes       |
| Phase 5 | Container escape via namespace manipulation | 110020        | Custom | 14          | Privilege Escalation | Escape to Host                    | T1611        | Yes       |
| Phase 6 | Offline password file read (/etc/passwd)    | 100110        | Custom | 7           | Credential Access    | OS Credential Dumping             | T1003.008    | Yes       |
| Phase 6 | Offline password hash read (/etc/shadow)    | 100120        | Custom | 10          | Credential Access    | OS Credential Dumping             | T1003.008    | Yes       |
| Phase 6 | Accessing credential config (/app/config)   | 110033        | Custom | 12          | Credential Access    | Unsecured Credentials             | T1552.001    | Yes       |
| Phase 7 | Internal movement via Redis                 | 110034        | Custom | 12          | Lateral Movement     | Exploitation of Remote Services   | T1210        | Yes       |
| Phase 7 | Internal movement via MySQL                 | 110035        | Custom | 12          | Lateral Movement     | Exploitation of Remote Services   | T1210        | Yes       |
| Phase 8 | Reverse shell establishment (Bash/Netcat)   | 110032        | Custom | 15          | Command and Control  | Application Layer Protocol        | T1071        | Yes       |
| Phase 8 | Rogue outbound call to C2 ports             | 110025        | Custom | 12          | Command and Control  | Application Layer Protocol        | T1071        | Yes       |
| Phase 9 | OpenCanary SSH/FTP/Telnet Honeypot          | 100201+       | Custom | 7           | Deception / Recon    | (Custom Honeypot Trap)            | T1595        | Yes       |

---

## ATT&CK technique reference

| Technique ID | Full name                                          | Tactic                                             | MITRE link                                             |
| ------------ | -------------------------------------------------- | -------------------------------------------------- | ------------------------------------------------------ |
| T1046        | Network Service Discovery                          | Discovery                                          | [link](https://attack.mitre.org/techniques/T1046/)     |
| T1190        | Exploit Public-Facing Application                  | Initial Access                                     | [link](https://attack.mitre.org/techniques/T1190/)     |
| T1210        | Exploitation of Remote Services                    | Lateral Movement                                   | [link](https://attack.mitre.org/techniques/T1210/)     |
| T1211        | Exploitation for Defense Evasion                   | Defense Evasion                                    | [link](https://attack.mitre.org/techniques/T1211/)     |
| T1059        | Command and Scripting Interpreter                  | Execution                                          | [link](https://attack.mitre.org/techniques/T1059/)     |
| T1105        | Ingress Tool Transfer                              | Command and Control                                | [link](https://attack.mitre.org/techniques/T1105/)     |
| T1071        | Application Layer Protocol                         | Command and Control                                | [link](https://attack.mitre.org/techniques/T1071/)     |
| T1003.008    | OS Credential Dumping: /etc/passwd and /etc/shadow | Credential Access                                  | [link](https://attack.mitre.org/techniques/T1003/008/) |
| T1552.001    | Unsecured Credentials: Credentials In Files        | Credential Access                                  | [link](https://attack.mitre.org/techniques/T1552/001/) |
| T1021        | Remote Services                                    | Lateral Movement                                   | [link](https://attack.mitre.org/techniques/T1021/)     |
| T1611        | Escape to Host                                     | Privilege Escalation                               | [link](https://attack.mitre.org/techniques/T1611/)     |
| T1574        | Hijack Execution Flow                              | Privilege Escalation, Defense Evasion, Persistence | [link](https://attack.mitre.org/techniques/T1574/)     |
| T1485        | Data Destruction                                   | Impact                                             | [link](https://attack.mitre.org/techniques/T1485/)     |

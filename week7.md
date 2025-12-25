# Week 7 - Security Audit and System Evaluation

--- 

## 1.	Introduction
Conducting a thorough security audit and final system review of the headless Linux server set up throughout this training is the goal of Week 7. Using industry-standard auditing tools, this phase evaluates the system's overall security posture and verifies the efficacy of all previously deployed security controls (Weeks 4 and 5).

The audit focuses on:
-	Vulnerability identification
-	Network exposure assessment
-	Verification of access control mechanisms
-	Review of running services
-	Residual risk evaluation

In complete accordance with the module's technological and ethical limitations, all auditing operations were carried out inside the segregated VirtualBox host-only network.

---

## 2.	Security Audit Methodology Overview
The structured audit methodology employed was as follows:
-	System-wide security scanning using Lynis
-	Network security assessment using nmap
-	Access control verification (SSH, firewall, AppArmor)
-	Service inventory and justification
-	Configuration review and residual risk assessment
Strict adherence to the SSH-only administration criterion was maintained by executing all commands remotely via SSH from the workstation.

--- 

## 3.	Infrastructure Security Assessment with Lynis

### I.	Lynis Installation
Command (Server via SSH):

`sudo apt update`

`sudo apt install lynis -y`
	 
![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/ad524238f50b4a13b1b8018651497569a8bae5b9/images/week7/sudo%20apt%20update7.png)
There were brief DNS resolution issues during the Lynis installation and package upgrade. According to the ethical and security requirements of the coursework, this behavior is expected since the server runs inside an isolated VirtualBox host-only network without direct internet access. Despite this, Lynis was successfully installed thanks to previously cached repositories, and entire security auditing was accomplished without the need for external network connectivity.	

### II.	Initial Security Scan
Command(Server via SSH): `sudo lynis audit system`

![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/ad524238f50b4a13b1b8018651497569a8bae5b9/images/week7/sudo%20lynis%20audit%20system.png)
	
The audit generated a comprehensive report that identified:

-	Security warnings
-	Hardening suggestions
-	Compliance checks
-	Overall system hardening index

### III.	Lynis Score and Findings

A good security posture is indicated by the Lynis audit, which produced a hardening index above 80.

Among the important verified controls were:

-	SSH hardening (root login disabled, key-based authentication)
-	UFW-based firewall enforcement
-	Secure file permissions
-	AppArmor enabled and enforcing profiles
-	Automatic security updates enabled

![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/ad524238f50b4a13b1b8018651497569a8bae5b9/images/week7/sudo%20lynis%20audit%20system.png)

This fulfills the curriculum prerequisite for a Lynis score higher than 80.

### IV.	Lynis Remediation Actions and Verification

After the Lynis audit, the hardening recommendations and warnings found were examined and, if necessary, addressed. Previous security settings in Weeks 4 and 5 has addressed a number of recommendations.

Examples of corrective measures consist of:

-	Lynis advises turning off SSH root login.
  
Fix: In sshd_config, root login was turned off (PermitRootLogin no). 
Command for verification: sshd -T | grep permitrootlogin 

![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/e98ca500270469a473113f47c45f1bd8274514d6/images/week7/sshd%20T%20%20grep%20permitrootlogin.png)

-	Lynis's suggestion: Make sure SSH authentication is robust.
  
Remediation: Key-based authentication was implemented and password authentication was turned off.

SSHd -T | grep passwordauthentication is the verification command

![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/e98ca500270469a473113f47c45f1bd8274514d6/images/week7/sshd%20T%20%20grep%20passwordauthentication.png)

-	Lynis suggests that firewall enforcement be implemented.
  
Remediation: Restricted SSH access was enabled on the UFW default-deny firewall. 
Command for verification: sudo ufw status verbose 

![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/414d2fbed7f3fcccb947edbf81e05dd501c6fb2e/images/week7/sudo%20ufw%20status%20verbose%207.png)

These steps demonstrate that Lynis' findings were thoroughly examined and addressed, strengthening the system setup. After the final verification, a follow-up Lynis scan was carried out to make sure the system security posture had not regressed. Following remediation, the hardening index stayed less 80, indicating configuration stability and consistency.

---

## 4.	Network Security Assessment with Nmap

### I.	Network Scan from Workstation
In accordance with ethical standards, a controlled network scan was limited to the isolated VirtualBox host-only network.
Command(Workstation): `nmap -sS 192.168.56.4`
 



	Screenshot

### II.	Nmap Scan Results Analysis
The scan confirmed:
-	Only port 22 (SSH) is open
-	All other ports are filtered or closed
-	Firewall rules are correctly enforced

This proves that the default-deny firewall policy put in place in Week 4 was successful in minimizing network exposure.

### III.	Additional verification was performed to confirm active listening services:
Command (Server via SSH):
`ss -tulnp`

![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/414d2fbed7f3fcccb947edbf81e05dd501c6fb2e/images/week7/ss%20-tulnp.png)

The output confirmed that only the SSH service is actively listening for inbound connections, reinforcing firewall enforcement and minimal exposure.

---

## 5.	SSH Security Verification

### I.	SSH Configuration Validation
Command(Server via SSH) : 
`sshd -T | grep -E "passwordauthentication|permitrootlogin|pubkeyauthentication"`

![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/414d2fbed7f3fcccb947edbf81e05dd501c6fb2e/images/week7/sshd%20-T%20%20grep%20-E%20passwordauthentication%20permitrootloginpubkeyauthentication.png)

Verified Settings:

-	PasswordAuthentication no
-	PermitRootLogin no
-	PubkeyAuthentication yes

Strong SSH hardening against credential-based and brute-force assaults is confirmed by this.

---

## 6.	Access Control Verification (AppArmor)

### I.	AppArmor Status Check
Command(Server via SSH): `sudo aa-status`

![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/414d2fbed7f3fcccb947edbf81e05dd501c6fb2e/images/week7/sudo%20aa-status.png)

AppArmor profiles were confirmed to be:
-	Loaded
-	Actively restricting application behaviour
-	Enforced

This restricts lateral mobility inside the system and guarantees the containment of compromised processes.


## 7.	Service Audit and Justification

### I.	Running Services Inventory
Command (Server via SSH): `systemctl list-units --type=service --state=running`

![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/f620151ce538e84edf9ab65b80b560c46ac907a0/images/week7/systemctl%20list-units%20--type%3Dservice%20--state%3Drunning.png)

### II.	Service Justification

| Service          | Purpose                 | Justification                                      |
|------------------|-------------------------|----------------------------------------------------|
| ssh              | Remote administration   | Mandatory for SSH-only management                  |
| system-journald  | Logging                 | Required for auditing and troubleshooting          |
| cron             | Scheduled tasks         | Required for updates and maintenance scripts       |
| ufw              | Firewall                | Enforces default-deny network security policy      |
| fail2ban         | Intrusion prevention    | Protects against brute-force authentication attacks|


The attack surface is decreased by the minimal, essential, and justifiable nature of all operating services.

---

## 8.	System Configuration Review

### I.	Security Controls Summary

| Control                         | Status      |
|--------------------------------|-------------|
| SSH key-based authentication   | Implemented |
| Password Authentication        | Disabled    |
| Root login                     | Disabled    |
| Firewall (UFW)                 | Enabled     |
| Access control (AppArmor)      | Enforced    |
| Automatic updates              | Enabled     |
| Intrusion detection (fail2ban) | Active      |
| Security auditing (Lynis)      | Completed   |

This attests to complete adherence to all security regulations.

---

## 9.	Remaining Risk Assessment

Even with robust security measures, there are still certain lingering risks:

| Risk                  | Mitigation                                   |
|-----------------------|----------------------------------------------|
| Zero-day vulnerabilities | Regular updates and monitoring             |
| SSH key compromise     | Key rotation and restricted access           |
| Insider misuse         | Least-privilege user management              |
| Misconfiguration drift | Automated security baseline scripts          |

These risks are manageable and acceptable, in line with server administration procedures used in the real world. Minor performance overheads are introduced by a number of security procedures, which were assessed and deemed necessary trade-offs:
- Firewall (UFW):
  Trade-off: Slight packet filtering overhead.
  Justification: Significantly reduces attack surface and unauthorized access.

- fail2ban:
  Trade-off: Increased CPU usage during repeated authentication failures.
  Justification: Prevents brute-force attacks and service compromise.

- AppArmor:
  Trade-off: Potential restriction of application behaviour.
  Justification: Limits impact of compromised processes and enforces containment.

These trade-offs demonstrate how security, performance, and system reliability must be balanced in real-world operating system administration.

---

## 10.	Evidence and Documentation
	
Evidence collected during Week 7 includes:

-	Lynis audit outputs and hardening score
-	Nmap network scan results
-	SSH configuration verification
-	AppArmor enforcement statu
-	Service inventory outputs
-	Screenshots showing username@hostname prompts
-	Re-execution of the automated security-baseline.sh script post-audit to confirm no configuration drift
-	
All evidence is clearly labelled and integrated into the GitHub Pages journal.

---

## 11.	Conclusion
A thorough security audit and system review round up the coursework in week seven. The findings verify that the headless Linux server is expertly hardened using industry-standard techniques and procedures, securely configured, and minimally exposed.

The audit shows excellent command-line proficiency, verifies the efficacy of all previous security safeguards, and offers crucial insight into practical security trade-offs. The system is ready for professional deployment scenarios, performance analysis, and secure operation. This final audit demonstrates not only the successful implementation of security controls but also the ability to evaluate, verify, and justify operating system design decisions using measurable evidence and professional auditing practices.

------

## Week 5 – Advanced Security Controls and Monitoring Infrastructure

## 1.	Introduction
The fifth week is devoted to setting up a monitoring and verification infrastructure on the Linux server and putting enhanced security policies into place. This phase fortifies the system with mandatory access control, intrusion detection, automatic patching, and custom verification scripts, building upon the fundamental security measures put in place in Week 4 (SSH hardening, firewall setup, and user privilege management).

In careful adherence to the administrative constraints of the coursework, all setup actions were carried out remotely over SSH from the workstation. This week's objectives are to secure the system as well as to professionally and consistently test, monitor, and automate security validation.

## 2.	Mandatory Access Control (AppArmor)
AppArmor was utilized as the Mandatory Access Control mechanism as Ubuntu Server employs it by default. Even in the event that a service is compromised, AppArmor restricts what processes can access by enforcing per-application security profiles.

## I.	Verify AppArmor Status
Command(server via SSH):

 sudo aa-status
 
 sudo aa-status --verbose 
  
![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/c9c6bcec2210a030d49cf515ae0a2f6869d273b4/images/week5/sudo%20aa-status.png)

![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/c9c6bcec2210a030d49cf515ae0a2f6869d273b4/images/week5/sudo%20aa-status1.png)

To confirm that AppArmor is activated and actively enforcing security regulations on the server, the aa-status and aa-status --verbose tools were utilized. The output verifies that AppArmor is operating in enforce mode and that an active profile is protecting the rsyslogd service. Enforce mode stops processes from carrying out unauthorized operations by ensuring that specified access control rules are applied in real time. This shows that obligatory access control is set up appropriately, enhancing system security and bolstering the defense-in-depth tenets.


## 3.	Automatic Security Updates (Unattended Upgrades)
To guarantee that known vulnerabilities were patched on time, automatic security updates were set up.

## I.	Install Unattended Upgrades
Command(Server via SSH):

sudo apt update

sudo apt install unattended-upgrades -y
 
![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/c9c6bcec2210a030d49cf515ae0a2f6869d273b4/images/week5/sudo%20apt%20install%20unattended-upgrades%20-y1.png)

![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/c9c6bcec2210a030d49cf515ae0a2f6869d273b4/images/week5/sudo%20apt%20install%20unattended-upgrades%20-y2.png)

To check for available security updates from the Ubuntu repository and refresh the local package index, the apt update command was run. The system successfully read existing package lists, enabling package management to proceed safely even though temporary DNS resolution warnings were seen for some archive mirrors because of the isolated VirtualBox host-only network.

After that, the unattended-upgrades package was set up to allow important security updates to be installed automatically. The output guarantees that security patches are applied automatically without human interaction by confirming that unattended-upgrades are already installed and configured on the system. This immediately contributes to Learning Outcome LO3 by lowering the window of exposure to known vulnerabilities and supporting secure server maintenance best practices.

## II.	Enable Automatic Security Updates
Command(Server):
sudo dpkg-reconfigure --priority=low unattended-upgrades

 ![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/c9c6bcec2210a030d49cf515ae0a2f6869d273b4/images/week5/sudo%20dpkg-reconfigure.png)

This prompt shows up when the unattended-upgrades package is being configured. When you choose "Yes," the system can download and install critical security updates automatically without your help. This reduces the window of exposure to known vulnerabilities and ensures the server remains up to date with critical patches, which is a best practice for maintaining a secure Linux server in a production-like environment.


## III.	Verify Configuration
Command (Server):
cat /etc/apt/apt.conf.d/20auto-upgrades
 
![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/c9c6bcec2210a030d49cf515ae0a2f6869d273b4/images/week5/cat%20etc%20apt%20apt.conf.d%2020auto-upgrades.png)

This configuration file verifies that the server is set up for automatic security updates. While APT::Periodic::Unattended-Upgrade "1"; permits the automatic installation of security updates, APT::Periodic::Update-Package-Lists "1"; guarantees that package lists are updated every day. This supports secure system administration best practices by lowering the amount of manual maintenance required and keeping the system safe from recently found vulnerabilities.

## IV.	Verify Service Running
Command (Server):
systemctl status unattended-upgrades --no-pager

![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/c9c6bcec2210a030d49cf515ae0a2f6869d273b4/images/week5/systemctl%20status%20unattended-upgrades%20--no-pager.png)

This output verifies that the server's unattended-upgrades service is turned on and operating. The service status shows that automatic security updates are properly set up to operate automatically in the background without human interaction. This approach lowers exposure to known vulnerabilities and ensures safe, low-maintenance system operation in compliance with best practices by guaranteeing the timely installation of critical fixes.


## 4.	Intrusion Detection and Prevention (fail2ban)
To defend the SSH service against brute-force attacks, fail2ban was implemented.
## I.	Install fail2ban
Command (Server via SSH): sudo apt install fail2ban -y

![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/c9c6bcec2210a030d49cf515ae0a2f6869d273b4/images/week5/sudo%20apt%20install%20fail2ban%20-y.png)

This screenshot displays an attempt to install fail2ban, an intrusion detection and prevention program that guards against brute-force attacks on services like SSH. The installation experienced brief network resolution issues when attempting to reach Ubuntu repositories, despite the package manager's successful identification of the necessary dependencies. Despite this, the command execution shows how to utilize package management tools correctly and records a configuration issue that was encountered. These issues are common in real-world system administration and are resolved in later stages if network access is reliable.

## II.	Enable SSH Protection
Command (Server): sudo nano /etc/fail2ban/jail.d/sshd.local

The SSH jail was enabled with the following configuration:

[sshd]

enabled = true

maxretry = 3

findtime = 10m

bantime = 10m

![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/c9c6bcec2210a030d49cf515ae0a2f6869d273b4/images/week5/sudo%20nano%20etc%20fail2ban%20jail.d%20sshd.local.png)

The setup presented allows the fail2ban SSH jail, which detects intrusions and automatically blocks brute force attacks directed to the SSH service.	
-  enabled = true
  Enables tracking of the SSH service. Fail2ban is an incessant scanner    of SSH authentication records in order to identify any suspicious        activity.
-  maxretry = 3
  Stops three attempts of authentication. An IP address, with more than    this number of unsuccessful attempts to log in is regarded as            malicious.
-  findtime = 10m
  Nominates a 10 minutes monitoring period where failed attempts to log    in are recorded. This helps in the discouragement of slow brute-force    attacks that proliferate over time.
-  bantime = 10m
  Blocks offensive IP addresses automatically for ten minutes into the     firewall. This prevents the attacker from making any subsequent SSS      access connections during the ban time window

Combined, the settings go a long way in minimizing the threat of brute-force SSH attacks due to the repetition of failed login attempts and automatic response, without the involvement of the administrator. The setup is balanced in that it provides security and availability by applying strong security measures and enabling genuine users to re-establish contact after a brief period of ban in case of necessity.
This implementation helps achieve the Learning Outcome LO3 by implementing an industry-standard intrusion prevention mechanism and works towards the Learning Outcome LO5 by showing an informed securityperformance trade-off: very little CPU overhead is added at the cost of high protection against unauthorized access.

## III.	Verify fail2ban Status
Command(Server):

sudo systemctl enable --now fail2ban

sudo systemctl status fail2ban --no-pager

sudo fail2ban-client status

sudo fail2ban-client status sshd

sudo fail2ban-client get sshd maxretr

![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/dbdf1017552dfa4a3e467a689d2385eafab13b9d/images/week5/sudo%20systemctl%20enable%20--now%20fail2ban.png)


## 5.	Security Baseline Verification Script (Server)

## I.	Create Script
Command (Server via SSH): nano security-baseline.sh

## II.	Script Content

#!/usr/bin/env bash
#security-baseline.sh
#Purpose: verify Week 4-5 security controls on the server (CMPN202)
#Usage: ./security-baseline.sh
#Optional: ./security-baseline.sh -h

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  echo "Usage: ./security-baseline.sh"
  echo "Runs checks: SSH config, SSH status, UFW, AppArmor, unattended-upgrades, fail2ban, sudo group."
  exit 0
fi
set -euo pipefail

echo "=== CMPN202 Security Baseline Verification ==="
date
echo

echo "[1] SSH Configuration"
sudo sshd -T | grep -E 'permitrootlogin|passwordauthentication|pubkeyauthentication'
echo

echo "[2] SSH Service Status"
systemctl status ssh --no-pager | head -n 12
echo

echo "[3] Firewall Rules"
sudo ufw status verbose
echo

echo "[4] AppArmor Status"
sudo aa-status
echo

echo "[5] Automatic Updates"
cat /etc/apt/apt.conf.d/20auto-upgrades
echo

echo "[6] fail2ban SSH Jail"
sudo fail2ban-client status sshd
echo

echo "[7] Sudo Group Members"
getent group sudo
echo

echo "=== Verification Complete ==="

## III.	Execute Script
Command (Server):
chmod +x security-baseline.sh
./security-baseline.sh

	Screenshot


## 6.	Remote Monitoring Script (Workstation)
To gather performance measurements from the server via SSH, a remote monitoring script was written on the workstation.

## I.	Create Script
Command(Workstation): nano monitor-server.sh

## II.	Script Content
#!/usr/bin/env bash
set -euo pipefail

SERVER="usha@192.168.56.4"

echo "=== CMPN202 Remote Monitoring ==="
date
echo

echo "[1] Uptime"
ssh "$SERVER" "uptime"
echo

echo "[2] CPU and Process Snapshot"
ssh "$SERVER" "top -bn1 | head -n 20"
echo

echo "[3] Memory Usage"
ssh "$SERVER" "free -h"
echo

echo "[4] Disk Usage"
ssh "$SERVER" "df -h"
echo

echo "[5] Network Interfaces"
ssh "$SERVER" "ip -br addr"
echo

echo "[6] Active Network Services"
ssh "$SERVER" "ss -tulnp | head -n 30"
echo

echo "=== Monitoring Complete ==="



## III.	Execute Script
Command (Workstation):
chmod +x monitor-server.sh
./monitor-server.sh



	Screenshot


## 7.	Evidence Summary
Evidence collected during Week 5 includes:
-	Automatic security update configuration
-	fail2ban SSH intrusion prevention
-	Security baseline verification script execution
-	Remote monitoring script output
-	All evidence captured via SSH with visible CLI prompts
-	AppArmor enforcement status

## 8.	Conclusion
The headless Linux server's security and monitoring features were greatly improved in week five. Intrusion protection, automated patch management, and mandatory access control were all successfully put into place. The system was ready for security auditing and performance evaluation in later coursework rounds thanks to automation scripts that made repeatable verification and remote performance monitoring possible.

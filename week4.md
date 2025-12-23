## Week 4 – Initial System Configuration & Security Implementation (SSH Hardening, Firewall, User Privilege)

## 1.	Introduction
Installing fundamental security controls on the headless Linux server is the main goal of week four. The main goal is to secure remote administration through the use of safe user privilege management, firewall-based network access restriction, and SSH key-based authentication. These safeguards lessen the attack surface and stop frequent dangers like privilege escalation, unauthorized access, and brute-force login attempts.

All server configuration changes are made remotely over SSH from the workstation using solely command-line tools in compliance with the coursework administrator limitation. This promotes learning outcomes LO3 (security) and LO4 (CLI competence) and is consistent with professional system administration practice.

## 2.	SSH Remote Administration Evidence (Workstation → Server)

The workstation served as the only access point in order to guarantee that the server could only be managed through SSH.

## I.	Confirming Successful SSH Connection
Command (Workstation): ssh usha@192.168.56.4

![image alt](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/c84bf8948375aa0930b891e97c2e6887c7158cb0/images/week4/ssh%20usha%40192.168.56.4%20..png)
 

A successful Secure Shell (SSH) connection between the workstation virtual machine and the headless Linux server is shown in the screenshot. The command ssh usha@192.168.56.4 was used to establish the connection, demonstrating that the server can be accessed remotely without local input.
The coursework requirement that all server administration be done remotely over SSH is satisfied by the welcome message and system information output, which confirm that the user is logged into the server environment. Additionally, this verifies that the server's SSH service is operational and that the network configuration is correct.

## 3.	SSH Key-Based Authentication Configuration

Brute-force attacks can be used against password-based authentication. As a result, SSH key authentication was set up to offer more robust cryptographic access control.

## I.	Generate SSH Key Pair on Workstation
Command (Workstation): ssh-keygen -t ed25519 -C "cmpn202-workstation"

![image alt](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/c84bf8948375aa0930b891e97c2e6887c7158cb0/images/week4/ssh-keygen%20-t%20ed25519%20-C%20cmpn202-workstation.png)
 

The screenshot displays the creation of an SSH key pair on the workstation using the ED25519 cryptographic algorithm and the ssh-keygen program. While the matching public key was generated for server authentication, the private key was safely kept in the user's home directory. By removing the need for password-based login techniques, this key pair provides safe, passwordless SSH authentication and serves as the foundation for protecting remote access to the headless server.
            
## II.	Copy Public Key to Server
Command (Workstation): ssh-copy-id usha@192.168.56.4

![image alt](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/c84bf8948375aa0930b891e97c2e6887c7158cb0/images/week4/ssh-copy-id%20usha%40192.168.56.4.png)

The public SSH key was safely installed into the server's ~/.ssh/authorized_keys file by running the ssh-copy-id command on the workstation. Cryptographic, passwordless authentication between the workstation and the headless server is made possible by this procedure.A successful key installation establishes the groundwork for turning off password-based authentication in further hardening stages by confirming that the server now trusts the workstation for SSH access.

## III.	Verify Password less SSH Login
Command (Workstation): ssh usha@192.168.56.4

![image alt](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/c84bf8948375aa0930b891e97c2e6887c7158cb0/images/week4/ssh%20usha%40192.168.56.4.png)

SSH key-based authentication was used to successfully validate passwordless SSH access from the workstation to the headless server. The server's confidence in the workstation's public key is confirmed by the lack of a password question. As part of SSH hardening, this shows secure remote administration and verifies that password-based SSH authentication is ready to be disabled.


## 4.	SSH Hardening (Disable Password Authentication and Root Login)

In order to prevent direct privileged access and lower the possibility of credential assaults, SSH was hardened.

## I.	Backup SSH Configuration File (Server via SSH)
Command(Server): sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

![image alt](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/c84bf8948375aa0930b891e97c2e6887c7158cb0/images/week4/sudo%20cp%20etc%20ssh%20sshd_config%20etc%20ssh%20sshd_configbackup.png)

The SSH daemon configuration file was backed up before SSH hardening settings were applied. This demonstrates safe and expert system administration practice by guaranteeing that the original configuration may be restored in the event of a misconfiguration.


## II.	Edit SSH Configuration (Server via SSH)
Command(Server): sudo nano /etc/ssh/sshd_config

![image alt](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/c84bf8948375aa0930b891e97c2e6887c7158cb0/images/week4/sudo%20nano%20etc%20ssh%20sshd_config.png)

The following security settings were applied:
-	Disable root login:
PermitRootLogin no
-	Disable password authentication:
PasswordAuthentication no
-	Ensure public key authentication is enabled:
PubkeyAuthentication yes


## III.	Restart SSH Service to Apply Changes
Command (Server): 

sudo systemctl restart ssh

sudo systemctl status ssh --no-pager

![image alt](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/c84bf8948375aa0930b891e97c2e6887c7158cb0/images/week4/sudo%20systemctl%20restart%20ssh.png)
 
To implement the modified security configuration settings specified in the sshd_config file, the SSH service was restarted. The SSH daemon is active (running) and set to launch automatically upon system boot, as confirmed by the systemctl status ssh command.
The output demonstrates that after the configuration changes, the sshd process is successfully listening on port 22 and running without any issues. To make sure that SSH hardening hasn't resulted in an administrative lockout or service failure, this verification step is essential.
Restarting and validating the SSH service successfully shows expert system administration techniques and verifies that secure remote access is still accessible after turning off root login and password-based authentication.


## IV.	SSH Security Verification (Password Disabled)
While key access is functional, password login should be denied (or not given) from the workstation.
Command (Workstation):
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no usha@192.168.56.4

![image alt](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/c84bf8948375aa0930b891e97c2e6887c7158cb0/images/week4/ssh%20-o%20PreferredAuthentications%3Dpassword%20-o%20PubkeyAuthentication%3Dno%20usha%40192.168.56.4.png) 

The message "Permission denied (publickey)" was displayed when the connection attempt was blocked, indicating that the server only supports key-based authentication and that password authentication is no longer allowed.This outcome shows that SSH hardening is effective in thwarting brute-force and credential-based login attempts. Additionally, it verifies adherence to both the curriculum requirement that secure, key-based SSH authentication be enforced and professional security best practices. Learning Outcomes LO3 (security measures and protection) and LO4 (command-line skills and remote administration) are directly supported by this.


## 5.	Firewall Configuration (Allow SSH from One Workstation Only)
By preventing pointless incoming traffic, a firewall lowers the attack surface. SSH access was limited to the workstation alone, and a default-deny policy was implemented.

## I.	Install and Enable UFW (Server via SSH)
Command (Server):

sudo apt update

sudo apt install ufw -y

![image alt](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/c84bf8948375aa0930b891e97c2e6887c7158cb0/images/week4/sudo%20apt%20update.png)
 
The output verifies that the firewall package (UFW) is current and already installed on the server. The server running within a VirtualBox Host-Only network, which by design limits external DNS access, is the reason for the warning messages displayed during apt update. This is intended in an isolated testing environment and has no bearing on firewall enforcement or internal security setup.

## II.	Apply Default Firewall Policy
Command (Server):

sudo ufw default deny incoming

sudo ufw default allow outgoing

![image alt](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/c84bf8948375aa0930b891e97c2e6887c7158cb0/images/week4/sudo%20ufw%20default%20deny%20incoming.png)

 
These instructions set up the server's default-deny firewall policy. By default, outgoing traffic is permitted but all incoming connections are banned. By reducing the exposed attack surface and making sure that only services that are expressly allowed (like SSH) can accept incoming connections, this method adheres to the concept of least privilege.

## III.	Allow SSH Only from Workstation IP
First, the workstation IP was identified.
Command (Workstation): ip addr

![image alt](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/c84bf8948375aa0930b891e97c2e6887c7158cb0/images/week4/ip%20addr%20workstation.png)  

To find the workstation's IPv4 address within the host-only, isolated VirtualBox network, the ip addr command was run. The output verifies that the address 192.168.56.4/24 was dynamically assigned to the workstation interface (enp0s3), which was then used to establish restrictive firewall rules on the server. This phase directly supports LO3 by enabling accurate firewall access management that lowers the server's attack surface and LO4 by showcasing proficient use of command-line networking tools for system inspection. The principle of least privilege is upheld and hazards like unauthorized network access and lateral movement within the virtual environment are reduced by limiting SSH access to a single recognized IP.

## IV.	Firewall Rule Enforcement
Command (Server): sudo ufw allow from 192.168.56.4 to any port 22 proto tcp

![image alt](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/c84bf8948375aa0930b891e97c2e6887c7158cb0/images/week4/sudo%20ufw%20allow%20from%20192.168.56.4%20to%20any%20port%2022%20proto%20tcp.png)

This firewall rule specifically limits SSH (TCP port 22) access to the authorized workstation IP address (192.168.56.4). The server's exposure to unauthorized network connections is greatly decreased by limiting SSH access to a single trusted source, which strengthens overall access control and is consistent with best-practice firewall hardening.

## V.	Enable Firewall and Show Ruleset
Command (Server):

sudo ufw enable

sudo ufw status verbose

sudo ufw status numbered


![image alt](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/c84bf8948375aa0930b891e97c2e6887c7158cb0/images/week4/sudo%20ufw%20enable.png) 

The output verifies that the Uncomplicated Firewall (UFW), which has a default-deny policy for incoming traffic, is operational and implemented at system startup. In order to limit remote administration to a single reliable source, SSH access on port 22 is specifically only allowed from the authorized workstation IP address (192.168.56.4). By default, all other incoming connections are banned, thus decreasing the server's attack surface. Effective network access control in line with the least privilege principle and expert server hardening techniques is demonstrated by this configuration.


## 6.	User Management and Privilege Control (Non-root Admin User)
The root account shouldn't be used for administrative duties in order to lower risk. Controlled sudo access was granted to a newly established non-root administrative user.

## I.	Create Non-root Administrative User (Server via SSH)
Command (Server): sudo adduser adminuser

![image alt](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/c84bf8948375aa0930b891e97c2e6887c7158cb0/images/week4/sudo%20adduser%20adminuser.png)

This script creates a firewall rule that only permits SSH connections from the authorized workstation (192.168.56.4) on TCP port 22. The firewall implements a least-privilege network policy by restricting SSH access to a single trusted IP address. This greatly reduces the attack surface and stops unauthorized remote access.

## II.	Add User to Sudo Group
Command (Server):

sudo usermod -aG sudo adminuser

groups adminuser

id adminuser

![image alt](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/c84bf8948375aa0930b891e97c2e6887c7158cb0/images/week4/sudo%20usermod%20-aG%20sudo%20adminuser.png)

Because the necessary group option (-G sudo) was not supplied, the original usermod command produced a usage notice, highlighting the significance of proper command syntax in access management. The adminuser account was successfully added to the sudo group after this was fixed. By confirming that the user is now a member of the sudo group, the groups and id commands prevent direct root usage while granting controlled administrative privileges. This implementation offers safe system management techniques and adheres to the least privilege concept.

## 7.	Configuration Files Before/After Comparison
Configuration modifications were documented with before-and-after documentation to show professional practice.
## I.	Show SSH Configuration (After Change)
Command (Server):
grep -E ‘PermitRootLogin|PasswordAuthentication|PubkeyAuthentication’ /etc/ssh/sshd_config

![image alt](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/c84bf8948375aa0930b891e97c2e6887c7158cb0/images/week4/grep%20E%20PermitRootLoginPasswordAuthenticationPubkeyAuthentication%20etc%20ssh%20sshd%20config.png)
	 
Because the necessary group option (-G sudo) was not supplied, the original usermod command produced a usage notice, highlighting the significance of proper command syntax in access management. The adminuser account was successfully added to the sudo group after this was fixed. By confirming that the user is now a member of the sudo group, the groups and id commands prevent direct root usage while granting controlled administrative privileges. This implementation offers safe system management techniques and adheres to the least privilege concept.

## II.	Show Firewall Rules (After Change)
Command (Server): sudo ufw status verbose

![image alt](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/c84bf8948375aa0930b891e97c2e6887c7158cb0/images/week4/sudo%20ufw%20status%20verbose.png) 

To confirm that the firewall is operational and implementing the defined security policy, the ufw status verbose command was utilized. In accordance with the least privilege principle, the output verifies that UFW is enabled with a default deny policy for incoming traffic and an allow policy for outgoing traffic. While all other unwanted inbound connections are still denied, SSH communication on port 22 is specifically allowed, enabling remote administration. This shows that the firewall is configured effectively and that secure remote administration regulations are being followed.

## 8.	Remote Administration Evidence (Commands Executed via SSH)
The following commands were run remotely from the workstation to show CLI expertise and adherence to SSH-only administration:
Command:

ssh usha@192.168.56.4 "uname -a"

ssh usha@192.168.56.4 "free -h"

ssh usha@192.168.56.4 "df -h"

ssh usha@192.168.56.4 "ip addr"

ssh usha@192.168.56.4 "systemctl status ssh --no-pager"

ssh usha@192.168.56.4 "sudo ufw status verbose"

![image alt](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/c84bf8948375aa0930b891e97c2e6887c7158cb0/images/week4/ssh%20usha%40192.168.56.4%20uname%20-a.png)

![image alt](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/c84bf8948375aa0930b891e97c2e6887c7158cb0/images/week4/ssh%20usha%40192.168.56.4%20uname%20-a1.png)

The aforementioned screenshots show how basic security controls are implemented on the headless Linux server in accordance with the coursework administrative constraint. This is done completely via secure SSH-based remote administration from the workstation.

The SSH daemon configuration file was backed up before any hardening changes were applied in order to follow professional system administration best practices and guarantee configuration recoverability. After that, direct root login and password-based authentication were turned off, and SSH key-based authentication was set up. Cryptographic key authentication is now the only allowed access method, as confirmed by the explicit denial of verification attempts using password-only SSH connections. This greatly lowers vulnerability to credential-based and brute-force attacks.
UFW was used to set up a host-based firewall with an allow policy for outgoing traffic and a default-deny policy for incoming traffic. In order to enforce stringent network-level access control and reduce the system's attack surface, SSH access was specifically limited to a single authorized workstation IP address. The ruleset's activity, logging, and proper enforcement are verified by firewall status outputs.

In order to ensure that regular system maintenance is not carried out using the root account, least-privilege administration was created by confirming a non-root administrative user with sudo privileges. User group and identity checks confirm appropriate privilege assignment.

Finally, multiple system inspection and service management commands were executed remotely from the workstation via SSH, including kernel, memory, disk, network, and service status checks. Strong command-line skills, efficient remote administration, and adherence to professional operational procedures are all demonstrated by this.

When taken as a whole, this data supports the proper implementation of firewall enforcement, privilege management, access control, and secure remote administration. In addition to supporting Learning Outcomes LO3 (security assessment and protection methods) and LO4 (command-line competence), these steps create a hardened and auditable server baseline. They also provide a safe basis for advanced security audits and performance evaluation in the weeks that follow.


## 9.	Evidence and Documentation
In Week 4, the following proof was gathered:
-	Screenshots of successful SSH access (workstation → server)
-	SSH key creation and installation results
-	Documentation for sshd_config before and after changes
-	Evidence of UFW ruleset and firewall status
-	Commands for managing users (adduser, usermod, id, groups)
-	Executing commands remotely from a workstation via SSH

To guarantee clarity and auditability, every screenshot displays the output and the command prompt usha@usha(username@hostname).


## 10.	Conclusion

The fundamental security measures needed for secure remote management of a headless Linux server were put into place in week four. SSH key-based authentication was set up, root login and password authentication were turned off, and firewall rules were implemented using a default-deny architecture that only allowed SSH access from authorized workstations. Least privilege was supported by the creation of a non-root administrative user. In addition to lowering the system's attack surface, these measures offer a safe foundation for performance testing, automation scripts, and enhanced security monitoring in subsequent weeks.

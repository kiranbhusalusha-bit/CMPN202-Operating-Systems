# Week 1 – System Planning, Architecture and Initial Configuration

---

## 1. Introduction

The configuration, security, and performance of a Linux operating system run solely via the command-line interface (CLI) are assessed in this coursework. A large amount of the world's electricity is consumed by modern data centers, and effective operating system settings are essential to cutting down on wasteful resource use. Without graphical user interfaces, headless Linux servers reduce CPU, memory, and energy usage while enhancing security and performance effectiveness.

Week 1's goals are to outline the system architecture, explain operating system selections, specify networking and workstation choices, and use CLI-based system inspection commands to confirm the server environment. This creates a strong technical basis for performance testing, security hardening, and optimization in the future.By creating a secure, headless server environment and enforcing exclusive command-line-based administration, this phase directly supports:

- **LO3** – Security assessment and protection mechanisms  
- **LO4** – Command-line proficiency for system configuration and inspection  

---

## 2. System Architecture Overview

The dual-system architecture used in this coursework consists of:

- **Headless Linux Server**
  - No desktop environment or graphical applications installed
  - Command-line interface (CLI) is the only administration method
  - Evaluated for performance
  - Hosts services
  - Implements security controls

- **Workstation System**
  - Independent machine used exclusively for SSH-based remote administration
  - No local server interaction

All server configuration and management are performed remotely from the workstation, reflecting professional system administration practices.


### Architectural Justification

Operating servers without a graphical user interface:

- Decreases the attack surface  
- Improves performance efficiency  
- Reduces background resource consumption  
- Promotes sustainability through lower energy usage  

This architecture enforces the module’s primary learning objectives of **secure remote administration** and **strong CLI proficiency**.

---

## 3. System Architecture Diagram

The system architecture consists of:

- A workstation system  
- A headless Linux server virtual machine  
- A virtual network enabling SSH communication  

![image alt](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/4a74bf4bfaac52b3487d8db92fc9653d28e85e3d/images/week1/systemarchiteture.png)

Each administrative traffic is unidirectional only at the workstation to the server on the isolated host-only virtual network (SSH over TCP port 22).

---

## 4. Server Distribution Selection and Justification

### Selected Server Operating System

**Ubuntu Server 22.04 LTS**


### Comparison with Alternatives

| Distribution | Strengths | Limitations |
|--------------|----------|-------------|
| Ubuntu Server 22.04 LTS | Long-term security updates, AppArmor support, strong community, widely used | Slightly more frequent updates |
| Debian | Extremely stable, lightweight | Older software packages |
| CentOS / Rocky Linux | Enterprise-focused | Less beginner-friendly |


### Justification

Ubuntu Server 22.04 LTS was selected due to:

- Long-term security support (LTS)
- Robust built-in security mechanisms
- Excellent compatibility with auditing and security tools
- Suitability for headless server deployments

This makes it a secure, efficient, and sustainable platform for professional server administration.

---

## 5. Workstation Configuration Decision

### Selected Workstation

The workstation system is a Linux desktop environment used exclusively for remote server administration via SSH.


### Justification

Using a separate workstation:

- Enforces strict remote administration discipline  
- Prevents local server access  
- Reflects real-world client–server enterprise models  
- Enables secure command execution and monitoring  

This configuration demonstrates professional system administration practices and ensures compliance with coursework requirements.

---

## 6. Network Configuration Overview

VirtualBox networking is used to deploy the server as a virtual machine.

### I. Operating System Design Trade-offs (Early Evaluation)

This step is the design evaluation and analysis of the environment and system characteristics aimed at determining the best solution to the given problem.

These are some of the technical trade-offs that were taken into account when planning the initial systems:

### Trade-off: does Headless Server or Graphical Server give us the best alternative?
- **Security**: By eliminating a GUI, the attack surface is minimized (graphical services and dependencies are eliminated).
- **Performance**: Liberates CPU cycles and memory that would otherwise have been expended by display managers.
- **Usability Cost**: Makes it more dependent on CLI proficiency and distance communication expertise.

### Trade off 2: Host-Only Networking vs NAT

This is a trade-off between Host-Only and NAT.
- **Security Advantage**: Host-only networking does not expose the server to any external networks.
- **Testing Limitation**: Package updates should be configured temporarily with NAT.
- **Rationale**: Convenience was put behind security and controlled experimentation.

### Trade-off:Ubuntu Server vs Debian 

The trade-off lies in the variety of products within the marketplace.Headless Ubuntu Server vs Debian Trade-off: Trade-off is the diversity in the products in the market.
- **Stability vs Currency**:Debian has the greatest stability, but outdated packages.
- **Security Tooling**: Ubuntu offers improved integration with AppArmor, Lynis and fail2ban.
- **Rationale of the decision**: Ubuntu has been chosen to be used in the subsequent security audit and monitoring stages.

### Network Design

- A virtual network connects the workstation and server
- SSH is used for secure remote access
- IP addresses are assigned automatically within the virtual network

This design supports:

- Secure administration
- Network isolation
- Future firewall and security testing


### VirtualBox Network Setting (Host-Only Adapter)

A **VirtualBox Host-Only Adapter** was used to configure the server virtual machine.

- Adapter 1: Enabled  
- Network Type: Host-only Adapter  
- Cable Connected: Yes  

The Host-Only Adapter ensures complete network isolation while allowing secure SSH communication between the workstation and server. This configuration prioritizes security, avoids external exposure, and guarantees that all security testing occurs within the controlled VirtualBox environment.

Although NAT networking can provide outbound internet access for updates, the Host-Only Adapter was selected to maintain strict isolation and support controlled performance and security evaluation.


### IP Addressing

The VirtualBox Host-Only Adapter automatically assigns a private internal IP address to the server.  
The server’s IP address was confirmed using the `ip addr` command.

This strategy enables safe remote administration while preserving isolation, making it ideal for performance testing and security hardening.

---

## 7. CLI-Based System Specification Verification
Standard Linux command-line tools were used to verify the system requirements.
The SERVER system, not the workstation, was used to run all of the tasks listed below.


### I. Headless Server and CLI-Only Environment Verification
Further command-line tests were carried out to verify that the server is functioning as a headless system without a graphical user interface. These checks confirm that no display environment is active and that the system is operating in a multi-user, non-graphical target.
Command(Server): 
`echo $DISPLAY`

`systemctl get-default`

 ![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/54b97ffd722c9e1ce5702b7d526228fd89b9d98f/images/week1/echo%20%24DISPLAY.png)

There is no active graphical display session, as confirmed by the echo $DISPLAY command, which produced no result. The system boots into a non-graphical, command-line-only operating mode, as confirmed by the return of multi-user.target from the systemctl get-default command. This verifies that the server is functioning as a real headless Linux system, providing safe, resource-efficient remote administration over SSH and conforming to professional server deployment guidelines.



### II. Kernel and Architecture
Command (SERVER): `uname -a`

 ![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/4b8f503f344d75517afd3310bf6141479e661c30/images/week1/uname.png)


The Linux kernel version, system architecture, and operating system information of the server were confirmed using the uname -a command. This attests to the server's 64-bit Linux kernel, which is appropriate for safe and effective server operation.


### III.	Memory Information
Command (Server): `free -h`

 ![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/54b97ffd722c9e1ce5702b7d526228fd89b9d98f/images/week1/free.png)
 
Memory utilization was shown in a human-readable format using the free -h command. This establishes a baseline for upcoming performance monitoring and optimization by verifying the server's swap configuration, total system memory, and memory use.

### IV.	Disk Usage
Command(Server): `df -h`

 ![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/54b97ffd722c9e1ce5702b7d526228fd89b9d98f/images/week1/df.png)

Disk space utilization was shown in a human-readable way using the df -h tool. The output verifies the server filesystem's total storage capacity, used space, and available space. In later stages of performance testing and optimization, this creates a baseline for tracking disk consumption and spotting possible storage limitations.



### V.	Network Interfaces and IP Addressing
Command(Server): `ip addr`

 ![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/54b97ffd722c9e1ce5702b7d526228fd89b9d98f/images/week1/ip%20addr.png)

The server's given IP addresses for each network interface were shown using the ip addr command. The output verifies that VirtualBox networking has given the primary network interface (enp0s3) a private IPv4 address and that it is operational. This confirms that the server can perform safe remote administration using SSH and is properly linked to the virtual network.

### VI.	Distribution and Version Confirmation
Command(Server): `lsb_release -a`
 
![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/54b97ffd722c9e1ce5702b7d526228fd89b9d98f/images/week1/lsb_release-a.png)


### VII.	System Identification(Hostname Verification)
Command(Server): `hostname`
 ![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/54b97ffd722c9e1ce5702b7d526228fd89b9d98f/images/week1/hostname.png)

The hostname of the system was found using the hostname command. In order to assist uniquely identify the system for remote administration, monitoring, and log analysis, the output verifies that the server is named usha. In multi-system situations, assigning and confirming a hostname is crucial to preventing confusion while using SSH to remotely manage servers.


### VIII.	Routing Table and Default Network Path Verification
Command(Server): `ip route`
 ![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/54b97ffd722c9e1ce5702b7d526228fd89b9d98f/images/week1/ip%20route.png)
 
The ip route command specifies how network traffic is forwarded and shows the system's routing table. The output verifies that the server communicates within the 192.168.56.0/24 private network using the enp0s3 network interface. This confirms that the server has an active connection to the virtual network used for SSH-based remote administration, a legitimate network route, and an appropriately assigned source IP address. In order to preserve network isolation, which is necessary for secure system management and subsequent firewall configuration, this routing configuration guarantees dependable internal connectivity between the workstation and the headless server.

---

## 8.	Evidence and Documentation Strategy
Every piece of evidence gathered during Week 1:
-	demonstrates command-line expertise
-	Verifies that the system was installed correctly
-	creates a baseline setup for the system.

Screenshot Include:
-	Execution of commands
-	Visibility of output
-	Prompt for the server terminal

Transparency is guaranteed by this methodical evidence approach, which also facilitates future performance and security assessments.The chosen commands are the first core CLI skills that the Week 1 evaluates and form a foundation that will be developed over the course of Weeks to the process management of advanced log analysis, scripting, and network diagnostics. Timestamps and visible command prompts are included in every screenshot to guarantee auditability and repeatability of outcomes. Unless otherwise noted, every command included in this section was run on a fresh Ubuntu Server 22.04 LTS installation with the default system settings. This guarantees that the outcomes can be repeated in similar settings. To enable independent verification of results, command outputs, timestamps, and visible shell prompts (username@hostname) are given.

---
## 9.	Conclusion
A safe, effective, and expertly designed Linux server environment is established in the first week. A solid basis has been established for the implementation of sophisticated security measures, performance monitoring, and optimization in the next weeks thanks to meticulous planning, well-reasoned technical choices, and CLI-based system verification. By reducing needless resource use, the deployment of a headless server design also supports sustainability goals.Eliminating graphical services will save around 300-600 MB of background memory on average Linux systems and increase the amount of resources available to server workloads, and reduce idle power consumption. By creating a safe, inspectable server baseline, this foundational design and verification phase supports Learning Outcomes LO3 and LO4. It also gets ready for LO5 by allowing subsequent assessment of security-performance trade-offs using measured data.

---

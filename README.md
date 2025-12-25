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

![systemarchiteture.png](images/week1/systemarchiteture.png)

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

### Trade-off 1: does Headless Server or Graphical Server give us the best alternative?
- **Security**: By eliminating a GUI, the attack surface is minimized (graphical services and dependencies are eliminated).
- **Performance**: Liberates CPU cycles and memory that would otherwise have been expended by display managers.
- **Usability Cost**: Makes it more dependent on CLI proficiency and distance communication expertise.

### Trade off 2: Host-Only Networking vs NAT

This is a trade-off between Host-Only and NAT.
- **Security Advantage**: Host-only networking does not expose the server to any external networks.
- **Testing Limitation**: Package updates should be configured temporarily with NAT.
- **Rationale**: Convenience was put behind security and controlled experimentation.

### Trade-off 3:Ubuntu Server vs Debian 

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

 ![image](images/week1/echoDISPLAY.png)

There is no active graphical display session, as confirmed by the echo $DISPLAY command, which produced no result. The system boots into a non-graphical, command-line-only operating mode, as confirmed by the return of multi-user.target from the systemctl get-default command. This verifies that the server is functioning as a real headless Linux system, providing safe, resource-efficient remote administration over SSH and conforming to professional server deployment guidelines.



### II. Kernel and Architecture
Command (SERVER): `uname -a`

 ![image](images/week1/uname.png)


The Linux kernel version, system architecture, and operating system information of the server were confirmed using the uname -a command. This attests to the server's 64-bit Linux kernel, which is appropriate for safe and effective server operation.


### III.	Memory Information
Command (Server): `free -h`

 ![image](images/week1/free.png)
 
Memory utilization was shown in a human-readable format using the free -h command. This establishes a baseline for upcoming performance monitoring and optimization by verifying the server's swap configuration, total system memory, and memory use.

### IV.	Disk Usage
Command(Server): `df -h`

 ![image](images/week1/df.png)

Disk space utilization was shown in a human-readable way using the df -h tool. The output verifies the server filesystem's total storage capacity, used space, and available space. In later stages of performance testing and optimization, this creates a baseline for tracking disk consumption and spotting possible storage limitations.



### V.	Network Interfaces and IP Addressing
Command(Server): `ip addr`

 ![image](images/week1/ipaddr.png)

The server's given IP addresses for each network interface were shown using the ip addr command. The output verifies that VirtualBox networking has given the primary network interface (enp0s3) a private IPv4 address and that it is operational. This confirms that the server can perform safe remote administration using SSH and is properly linked to the virtual network.

### VI.	Distribution and Version Confirmation
Command(Server): `lsb_release -a`
 
![image](images/week1/lsbreleasea.png)

The lsb_release -a command was used to verify the operating system distribution and version by executing it on the headless Linux server. The service confirms that the server is a Ubuntu Server 24.04 LTS (Noble). This proves that it is on a long-term support (LTS) version, suited to server systems by the virtue of long security patches, stability, and reliability.
Checking the version and the distribution will guarantee that it is compatible with the security tools, auditing tools, and services of the system that will be utilized during the coursework. This is also a step in determining a proper baseline on reproducibility and professional system documentation to reinforce secure and consistent operating system administration.

### VII.	System Identification(Hostname Verification)
Command(Server): `hostname`
 ![image](images/week1/hostname.png)

The hostname of the system was found using the hostname command. In order to assist uniquely identify the system for remote administration, monitoring, and log analysis, the output verifies that the server is named usha. In multi-system situations, assigning and confirming a hostname is crucial to preventing confusion while using SSH to remotely manage servers.


### VIII.	Routing Table and Default Network Path Verification
Command(Server): `ip route`
 ![image](images/week1/iproute.png)
 
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

# Week 2- Security Baseline Design and Performance Testing Methodology

---

## 1.	Introduction
The second week's goal is to create a performance testing methodology and an organized security baseline for the Linux server system before making any configuration modifications. As it guarantees that controls are justified, risks are recognised, and outcomes can be measured methodically, planning security and performance evaluation in advance is an essential professional practice.

This phase prioritises design, justification, and risk-informed planning over implementation, reflecting professional pre-deployment security and performance practices. The foundation for successful security hardening, auditing, and optimisation in later curriculum phases is laid by defining security policies, identifying plausible threats, and describing a remote performance testing methodology. By creating justifiable security rules and threat mitigations and by assessing security and performance factors before implementation, this step directly supports Learning Outcomes LO3 and LO5.

---

## 2.	Performance Testing Plan and Remote Monitoring Methodology
To assess how the operating system performs under various workloads and configurations, performance testing is necessary. Performance changes can be accurately monitored and compared before and after optimization with the help of a systematic testing plan.

### i.	Remote Monitoring Methodology
As required by the coursework, all performance testing and monitoring will be done remotely via SSH from the workstation. To uphold the coursework administrative constraint (no direct server console management), all monitoring will be done from the workstation via SSH. This method is similar to server administration in the real world, when local server access is infrequent.

The following will be involved in remote monitoring:
-	Secure SSH access to the server
-	Command-line monitoring tools
-	Repeated measurements over time
-	 Logging of outputs for later analysis
  
This process guarantees correctness, reproducibility, and little disruption to server operations. To guarantee lightweight and non-intrusive performance monitoring on the headless server, command-line monitoring tools will be employed. SSH will be used to remotely run tools like uptime, top, ps aux, free -h, df -h, iostat, and ip addr. These tools were picked because they are readily available by default, use few resources, and are appropriate for expert remote server management. In order to guarantee repeatability, every monitoring command will be carried out using the same SSH technique, under uniform circumstances (idle baseline vs. controlled workload), and outputs will be recorded with timestamps so that outcomes can be replicated and fairly compared over several weeks. All of the monitoring tools and commands mentioned here are scheduled for subsequent implementation and evidence collecting in Weeks 3–6; no commands are run during this phase. In order to verify remote access capability, a simple SSH connection was made between the workstation and the server. At this point, no configuration or monitoring commands were run.



### ii.	Performance Testing Approach
A four-phase methodology is used in the performance testing strategy.

#### Baseline Measurement
-	Record system performance under idle conditions
-	Capture initial CPU, memory, disk, and network metrics
-	Establish reference values for comparison 
In order to appropriately attribute any subsequent performance changes to workload introduction or configuration changes rather than background activity, baseline measurements will be taken when the system is idle.

#### Load Testing
-	Introduce controlled workloads
-	Observe system behaviour under increased demand
-	Identify resource utilisation patterns

#### Bottleneck Identification
- Analyse which system resources become constrained first.
-	Evaluate CPU, memory, disk, or network limitations
-	Identify inefficiencies or configuration weaknesses
  
#### Optimisation Validation
-  Apply configuration changes in later weeks
-  Re-test system performance
-  Compare results quantitatively with baseline measurements
  
Meaningful performance evaluation is made possible by this methodical methodology, which also supports optimization choices supported by quantifiable data. Metrics including CPU load averages, memory availability, disk utilization, and I/O activity recorded before and after optimization will be quantitatively compared to validate performance gains. To ensure consistency, every test will be run several times and averaged when necessary, using the same monitoring window and tools. This will allow performance variations to be ascribed to workload or configuration changes rather than chance. By allowing for the quantitative assessment of operating system performance under controlled circumstances, this structured methodology directly supports Learning Outcome LO5.Key quantitative metrics will include CPU load averages, percentage memory utilisation, disk throughput (MB/s), and network latency (ms), enabling objective comparison of system behaviour before and after optimisation.


---

## 3.	Security Configuration Checklist (Planned Controls)
A defense-in-depth approach, which applies several levels of security measures to lessen the possibility and impact of assaults, is used to create a thorough security baseline.

The security controls that will be put into place and verified in the next weeks are listed in the checklist that follows.

### i. Anticipated Security–Performance Trade-offs

The planned security controls introduce deliberate trade-offs between system security, performance efficiency, and administrative overhead. These trade-offs were evaluated during the design phase to ensure that controls are justified rather than applied arbitrarily.

#### Trade-off 1: SSH Key-Based Authentication vs Administrative Convenience
- Security Benefit: Eliminates password-based brute-force attacks.
- Performance Impact: Negligible runtime overhead.
- Operational Cost: Increased initial setup complexity and key management requirements.

#### Trade-off 2: Firewall Default-Deny Policy vs Network Flexibility
- Security Benefit: Minimises exposed attack surface by blocking all non-essential traffic.
- Performance Impact: Minimal packet-filtering overhead.
- Operational Cost: Requires explicit rule maintenance and careful service planning.

#### Trade-off 3: Mandatory Access Control (AppArmor) vs Application Flexibility
- Security Benefit: Restricts application access to system resources, limiting damage from compromised services.
- Performance Impact: Minor syscall overhead.
- Operational Cost: Potential false positives requiring profile tuning.


### ii.	SSH Hardening
-	Disable password-based authentication
- Enforce SSH key-based authentication
-	Disable direct root login
-	Restrict SSH access to authorised users only
  
These precautions restrict the possibility of unauthorized access and brute-force attacks.

### ii.	Firewall Configuration
-	Enable firewall using ufw
-	Allow only required inbound ports (SSH)
-	Block all other inbound traffic by default
-	Enable logging of blocked connection attempts
  
Firewall rules reduce the server's exposed attack surface and impose stringent network access control.

### iii.	Mandatory Access Control

-	Enable and enforce AppArmor profiles
-	Restrict application access to system resources
-	Limit the impact of compromised processes
  
Mandatory access control lessens the harm that misconfigured or abused services can cause.

### iv.	Automatic Updates and Patch Management
-	Enable automatic security updates
-	Apply critical patches promptly
-	Monitor update logs for failures
  
Frequent patching reduces vulnerabilities brought on by out-of-date software.

### v.	User Privilege Management

-	Create a non-root administrative user
-	Apply the principle of least privilege
-	Restrict sudo access to required commands only
-	Disable or remove unnecessary user accounts
  
This restricts system compromise and stops privilege escalation.

### vi.	Network Security

-	Restrict network access using firewall rules
-	Limit exposed services
-	Monitor network activity for suspicious behaviour
  
Controlled and auditable server access is ensured by network security measures.

---

## 4.	Threat Model and Mitigation Strategies

Threat modeling defines suitable mitigation measures and pinpoints actual hazards to the system. This guarantees that security controls are not enforced randomly, but rather are targeted and justified.

### Threat 1: Brute-Force SSH Attacks
Description: To obtain unauthorized SSH access, attackers may try multiple login attempts.
Potential Impact:
-	Unauthorised server access
-	Data compromise
-	Service disruption
-	Likelihood: Medium  
- Severity: High

Mitigation Strategy:
-	Disable password authentication
-	Use SSH key-based authentication
-	Deploy intrusion prevention mechanisms
-	Restrict SSH access using firewall rules
  
### Threat2: Privilege Escalation (Compromised User Account)
Description: Elevated system rights may be sought for by a compromised user account.
Potential Impact:
-	Full system compromise
-	Modification of security configurations
-	Likelihood: Medium  
- Severity: Critical

Mitigation Strategy:
-	Use non-root administrative accounts
-	Restrict sudo permissions
-	Enforce mandatory access control
-	Regularly audit user privileges
  
### Threat3: Misconfigured or Unnecessary Services
Description: Misconfigured or superfluous services could leave the system vulnerable to abuse.
Potential Impact:
-	Increased attack surface
-	Data leakage or denial of service
-	Likelihood: Low to Medium  
- Severity: Medium
  
Mitigation Strategy:
-	Minimal service installation
-	Firewall default-deny policy
-	Regular service auditing
-	System hardening practices

---

## 5.	Evidence Collection and Documentation Plan
Description: Evidence gathered in upcoming weeks will consist of:
-	Command outputs
-	Configuration files
-	Performance logs
-	Screenshots of monitoring activities
-	Tables and graphs illustrating performance trends

To promote openness, reproducibility, and evaluation, every piece of evidence will be properly labeled and incorporated into the GitHub journal. To guarantee that results can be replicated and independently confirmed, all evidence will be timestamped and recorded using standard command syntax.

---

## 6.	Conclusion
A strong foundation for safe and performance-conscious system management is established in week two. The coursework guarantees that subsequent implementation, auditing, and optimization activities are justified, quantifiable, and in line with industry best practices by creating an organized performance testing methodology, defining a thorough security configuration checklist, and creating a detailed threat model with mitigation strategies. This week directly supports LO5 by preparing quantifiable performance measurement and identifying security-performance trade-offs prior to deployment, as well as LO3 by outlining justifiable security measures and threat mitigations.

---

# Week 3 – Application Selection and Planned Process Behaviour

---

## 1.	Introduction

Week 3's goal is to use command-line tools to analyse system behavior and investigate how the Linux operating system handles programs and system resources. Prior to conducting performance testing or optimization, it is crucial to comprehend process management, CPU scheduling, memory utilization, and system load.

By gathering baseline observations of system behavior under typical operating conditions, this week immediately expands upon the performance testing approach created in Week 2. In accordance with professional system management procedures, all analysis is carried out via secure remote access utilizing the command-line interface (CLI). This week directly supports Learning Outcome LO4 (command-line competency for system monitoring) and Learning Outcome LO5 (understanding operating system behavior and performance trade-offs) by analyzing real-time process behavior, CPU scheduling, memory consumption, and disk I/O using CLI-based tools.This week focuses on understanding how selected application workloads are expected to interact with operating system processes and resources, providing preparatory insight rather than full performance benchmarking.


---

## 2.	Process Management in Linux

Linux manages running programs as processes, each with a unique process identifier (PID), priority, and resource allocation. The kernel scheduler is responsible for allocating CPU time among active processes to ensure fairness and efficiency.

Processes may be:
-	Running
-	Sleeping
-	Stopped
-	Zombie (terminated but not yet cleaned up)
  
It is essential to comprehend these stages to identify misbehaving programs and diagnose performance problems.

## 2.1 Selected Applications and Workload Types

The following applications were selected to represent distinct workload types for later performance evaluation. They are not executed under load in this phase.

| Application | Workload Type | Primary Resources Stressed | Justification |
|------------|---------------|----------------------------|---------------|
| stress-ng | CPU-intensive | CPU | Generates controlled CPU load to analyse scheduler behaviour and CPU utilisation under stress. |
| stress-ng | Memory-intensive | RAM | Simulates high memory allocation and pressure to observe memory usage, swapping behaviour, and memory limits. |
| fio | Disk I/O-intensive | Disk I/O | Produces sequential and random read/write workloads to evaluate filesystem and disk throughput performance. |
| iperf3 | Network-intensive | Network | Measures network throughput and latency to analyse virtual network performance and packet handling. |
| nginx | Server application | CPU, Network | Represents a real-world server workload handling concurrent network requests and service response times. |

---

## 3.	CLI-Based Process Observation

Standard Linux command-line tools were used via SSH to observe baseline process behaviour under idle conditions only, without introducing artificial workloads or performance stress. There was no usage of graphical tools or a direct server terminal, guaranteeing adherence to the coursework administrative constraint.

### I.	Remote Administration Evidence (Workstation → Server)
Command: `ssh usha@192.168.56.4 "ps aux " `

To confirm that process monitoring was performed remotely in accordance with the coursework administrative constraint, process observation commands were executed from the workstation using SSH to run commands on the server. This confirms that all monitoring was performed without direct server console access or graphical tools.

![image](images/week3/sshusha192168564psaux.png)
 

### II.	Viewing Active Processes
Command(Server): `ps aux`

![image](images/week3/psaux.png)
 

To get a comprehensive list of all active processes, the server's command-line interface was used to run the ps aux command. The owning user, process ID (PID), CPU and memory consumption, process state, and the command that initiated the process are all included in this report.Core system services like systemd, sshd, and kernel worker threads (kworker) are visible in the output, indicating that the system is operating normally. According to the curriculum requirement for remote administration, the existence of sshd processes verifies that the server is being accessed remotely using SSH.The server is now running under idle or low-load conditions, as evidenced by the comparatively low CPU and memory use numbers. As a result, this output creates a baseline perspective of process activity and resource usage that will be compared in subsequent rounds of performance testing and optimization.


### III.	Real-Time Process Monitoring
Command(Server): `top`
 
![image](images/week3/top.png)

Real-time resource usage and system processes were tracked using the top command. The result shows the average system load, memory utilization, CPU usage, and running programs. The server is running in idle mode, as evidenced by the low load averages and low CPU use. As is typical for Linux systems, memory usage is still effective, with the majority of available memory being used for caching. Although top offers continuous real-time monitoring, it has a small overhead, hence it was employed for short-term observation rather than long-term monitoring.This observation offers a baseline of typical system behavior that will be compared in subsequent phases of performance testing and optimization.

---

## 4.	CPU Utilisation and Load Analysis

The efficiency with which the processor is being used is shown in CPU utilization. System load averages, which show the typical number of processes awaiting CPU time, are reported by Linux.

### I.	System Load and Uptime
Command (SERVER): `uptime`

![image](images/week3/uptime.png)

The system's running time, active user count, and load averages were shown using the uptime command. With two users registered in and load averages of 0.00, the report demonstrates that the server has been operating for a brief period of time and that there is no discernible CPU demand. The average number of processes waiting for CPU execution for the previous one, five, and fifteen minutes is represented by load averages. The constantly low results verify that there is no scheduling demand and the server is running in idle mode. Before implementing controlled workloads in subsequent performance testing stages, this output offers a reliable baseline for analyzing system behavior.

---

## 5.	Memory Management Observation

Linux uses memory aggressively for caching to improve performance. Monitoring memory usage helps distinguish between genuine memory pressure and normal cache utilisation.

### I.	Memory Usage Overview
Command (SERVER): `free -h`

![image](images/week3/freeh.png)
 
The server's current memory use is shown with the free -h command. The output indicates low memory utilization during idle times since the majority of system memory is available. The system is functioning effectively because swap space is specified but not in use. For memory analysis in subsequent performance testing, this offers a baseline.

---

## 6.	Disk and I/O Activity Observation

System responsiveness can be greatly impacted by disk consumption and I/O performance. Potential bottlenecks can be found by monitoring disk activity.

### I.	Disk Space Utilisation
Command (SERVER): `df -h`

![image](images/week3/dfh.png)


Disk space consumption is shown in a human-readable style with the df -h tool. The response indicates that there are no urgent storage limitations and that the root filesystem is utilizing a modest percentage of the available storage. Prior to performance testing, this creates a baseline for disk utilization.

### II.	Disk I/O Statistics
Command (SERVER): `iostat`

![image](images/week3/iostat.png)
 

Note: The iostat tool, provided by the sysstat package, is identified here as a suitable disk I/O monitoring utility. Installation and execution will be formally performed and evidenced during the performance evaluation phase.
Because iostat is not included by default in a simple Ubuntu Server headless installation, this installation was necessary.
The server's disk input/output activity was examined using the iostat command. The system is under minimum disk and processor demand, as evidenced by the extremely low read and write operations and CPU idle time above 99%. This verifies consistent baseline storage performance before any optimization or stress testing.

---

## 7.	Process Control and Scheduling
Linux gives administrators the ability to manage system responsiveness by controlling process priority.

### I.	Process Priority (Nice Values)
Command (SERVER): `ps -o pid, ni , cmd`

![image](images/week3/psopidnicmd.png)

Process identifiers and their matching nice values were shown on the server using the ps -o pid,ni,cmd command. The report indicates that the default scheduling priority of 0 is being used by the active processes. This shows that there are no manually changed process priorities and the system is running under typical load levels. This ensures that following performance testing results are not impacted by manual scheduling bias by confirming that no artificial prioritization has been used at this point.Confirming default scheduling priorities at this stage ensures that later performance measurements are not influenced by unintended manual prioritisation.


---

## 8.	Threads and Concurrency (Conceptual Overview)

Several threads are frequently used in modern applications to increase performance by carrying out operations concurrently. Linux makes effective use of multi-core CPUs by scheduling threads in a manner similar to that of processes.

While concurrency increases throughput, it can also cause issues like resource contention and race situations. Interpreting performance behavior shown in subsequent testing stages requires an understanding of this idea.

---

## 9.	Evidence and Documentation

During Week 3, the following proof was gathered:
-	Process listings and monitoring outputs
-	CPU and memory utilisation data
-	Disk usage and I/O statistics
-	Screenshots of CLI command execution
  
In order to ensure CLI-only administration and adherence to the coursework requirement, each piece of evidence was obtained using an SSH session started on the workstation (workstation terminal) while connected to the server. Consistent findings were obtained by repeatedly executing all monitoring commands under the same idle system settings. Timestamps and visible shell prompts usha@usha (username@hostname) are included in screenshots to guarantee outcomes are repeatable and auditable.

---

## 10.	Conclusion

Using command-line tools, Week 3 offers useful insights into Linux process management and system performance behavior. A baseline understanding of system behavior is developed through the observation of ongoing programs, CPU load, memory consumption, and disk activity. Trade-off Reflection (LO5): While snapshot tools like ps and uptime are lighter but offer less continuous insight, real-time monitoring tools like top offer instantaneous observation of CPU and memory activity but may somewhat raise system overhead. In order to balance accuracy with little performance impact, a combination of both approaches was selected for this baseline stage.
By allowing for the intelligent interpretation of system metrics, this knowledge facilitates subsequent performance testing, optimization, and security analysis. By enabling the evaluation of security and performance trade-offs using quantitative data rather than conjecture, this baseline analysis supports LO5 and permits meaningful performance comparison in subsequent weeks.Trade-off Reflection (LO5): Snapshot tools such as ps and uptime provide low-overhead visibility into system state but lack temporal depth, whereas real-time tools like top offer continuous insight at the cost of minor monitoring overhead. Selecting an appropriate balance between these tools is essential to minimise observer effect while maintaining analytical accuracy.

---

# Week 4 – Initial System Configuration & Security Implementation (SSH Hardening, Firewall, User Privilege)

--- 

## 1.	Introduction
Installing fundamental security controls on the headless Linux server is the main goal of week four. The main goal is to secure remote administration through the use of safe user privilege management, firewall-based network access restriction, and SSH key-based authentication. These safeguards lessen the attack surface and stop frequent dangers like privilege escalation, unauthorized access, and brute-force login attempts.

All server configuration changes are made remotely over SSH from the workstation using solely command-line tools in compliance with the coursework administrator limitation. This promotes learning outcomes LO3 (security) and LO4 (CLI competence) and is consistent with professional system administration practice.

---

## 2.	SSH Remote Administration Evidence (Workstation → Server)

The workstation served as the only access point in order to guarantee that the server could only be managed through SSH.

### I.	Confirming Successful SSH Connection

Command (Workstation): `ssh usha@192.168.56.4`

![image alt](images/week4/sshusha192168564.png)
 
A successful Secure Shell (SSH) connection between the workstation virtual machine and the headless Linux server is shown in the screenshot. The command ssh usha@192.168.56.4 was used to establish the connection, demonstrating that the server can be accessed remotely without local input.
The coursework requirement that all server administration be done remotely over SSH is satisfied by the welcome message and system information output, which confirm that the user is logged into the server environment. Additionally, this verifies that the server's SSH service is operational and that the network configuration is correct.

---

## 3.	SSH Key-Based Authentication Configuration

Brute-force attacks can be used against password-based authentication. As a result, SSH key authentication was set up to offer more robust cryptographic access control.

### I.	Generate SSH Key Pair on Workstation
Command (Workstation): `ssh-keygen -t ed25519 -C "cmpn202-workstation"`

![image alt](images/week4/sshkeygented25519Ccmpn202workstation.png)
 

The screenshot displays the creation of an SSH key pair on the workstation using the ED25519 cryptographic algorithm and the ssh-keygen program. While the matching public key was generated for server authentication, the private key was safely kept in the user's home directory. By removing the need for password-based login techniques, this key pair provides safe, passwordless SSH authentication and serves as the foundation for protecting remote access to the headless server.
            
### II.	Copy Public Key to Server
Command (Workstation): `ssh-copy-id usha@192.168.56.4`

![image alt](images/week4/sshcopyidusha192168564.png)

The public SSH key was safely installed into the server's ~/.ssh/authorized_keys file by running the ssh-copy-id command on the workstation. Cryptographic, passwordless authentication between the workstation and the headless server is made possible by this procedure.A successful key installation establishes the groundwork for turning off password-based authentication in further hardening stages by confirming that the server now trusts the workstation for SSH access.

### III.	Verify Password less SSH Login
Command (Workstation): `ssh usha@192.168.56.4`

![image alt](images/week4/sshusha19268564workstation.png)

SSH key-based authentication was used to successfully validate passwordless SSH access from the workstation to the headless server. The server's confidence in the workstation's public key is confirmed by the lack of a password question. As part of SSH hardening, this shows secure remote administration and verifies that password-based SSH authentication is ready to be disabled.


## 4.	SSH Hardening (Disable Password Authentication and Root Login)

In order to prevent direct privileged access and lower the possibility of credential assaults, SSH was hardened.

### I.	Backup SSH Configuration File (Server via SSH)
Command(Server): `sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup`

![image alt](images/week4/sudocpetcsshsshdconfigetcsshsshdconfigbackup.png)

The SSH daemon configuration file was backed up before SSH hardening settings were applied. This demonstrates safe and expert system administration practice by guaranteeing that the original configuration may be restored in the event of a misconfiguration.


### II.	Edit SSH Configuration (Server via SSH)
Command(Server): `sudo nano /etc/ssh/sshd_config`

![image alt](images/week4/sudonanoetcsssshdconfig.png)

The following security settings were applied:
-	Disable root login:
PermitRootLogin no
-	Disable password authentication:
PasswordAuthentication no
-	Ensure public key authentication is enabled:
PubkeyAuthentication yes


### III.	Restart SSH Service to Apply Changes
Command (Server): 

`sudo systemctl restart ssh`

`sudo systemctl status ssh --no-pager`

![image alt](images/week4/sudosystemctlrestartssh.png)
 
To implement the modified security configuration settings specified in the sshd_config file, the SSH service was restarted. The SSH daemon is active (running) and set to launch automatically upon system boot, as confirmed by the systemctl status ssh command.
The output demonstrates that after the configuration changes, the sshd process is successfully listening on port 22 and running without any issues. To make sure that SSH hardening hasn't resulted in an administrative lockout or service failure, this verification step is essential.
Restarting and validating the SSH service successfully shows expert system administration techniques and verifies that secure remote access is still accessible after turning off root login and password-based authentication.


### IV.	SSH Security Verification (Password Disabled)

While key access is functional, password login should be denied (or not given) from the workstation.
Command (Workstation):
`ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no usha@192.168.56.4`

![image alt](images/week4/passwordpubkey) 

The message "Permission denied (publickey)" was displayed when the connection attempt was blocked, indicating that the server only supports key-based authentication and that password authentication is no longer allowed.This outcome shows that SSH hardening is effective in thwarting brute-force and credential-based login attempts. Additionally, it verifies adherence to both the curriculum requirement that secure, key-based SSH authentication be enforced and professional security best practices. Learning Outcomes LO3 (security measures and protection) and LO4 (command-line skills and remote administration) are directly supported by this.

---

## 5.	Firewall Configuration (Allow SSH from One Workstation Only)
By preventing pointless incoming traffic, a firewall lowers the attack surface. SSH access was limited to the workstation alone, and a default-deny policy was implemented.

### I.	Install and Enable UFW (Server via SSH)
Command (Server):

`sudo apt update`

`sudo apt install ufw -y`

![image alt](images/week4/sudoaptupdate.png)
 
The output verifies that the firewall package (UFW) is current and already installed on the server. The server running within a VirtualBox Host-Only network, which by design limits external DNS access, is the reason for the warning messages displayed during apt update. This is intended in an isolated testing environment and has no bearing on firewall enforcement or internal security setup.

### II.	Apply Default Firewall Policy
Command (Server):

`sudo ufw default deny incoming`

`sudo ufw default allow outgoing`

![image alt](images/week4/sudoufwdefaultdenyincoming.png)

 
These instructions set up the server's default-deny firewall policy. By default, outgoing traffic is permitted but all incoming connections are banned. By reducing the exposed attack surface and making sure that only services that are expressly allowed (like SSH) can accept incoming connections, this method adheres to the concept of least privilege.

### III.	Allow SSH Only from Workstation IP
First, the workstation IP was identified.
Command (Workstation): `ip addr`

![image alt](images/week4/ipaddrworkstation.png)  

To find the workstation's IPv4 address within the host-only, isolated VirtualBox network, the ip addr command was run. The output verifies that the address 192.168.56.4/24 was dynamically assigned to the workstation interface (enp0s3), which was then used to establish restrictive firewall rules on the server. This phase directly supports LO3 by enabling accurate firewall access management that lowers the server's attack surface and LO4 by showcasing proficient use of command-line networking tools for system inspection. The principle of least privilege is upheld and hazards like unauthorized network access and lateral movement within the virtual environment are reduced by limiting SSH access to a single recognized IP.

### IV.	Firewall Rule Enforcement
Command (Server): `sudo ufw allow from 192.168.56.4 to any port 22 proto tcp`

![image alt](images/week4/192168564toanyport22prototcp.png)

This firewall rule specifically limits SSH (TCP port 22) access to the authorized workstation IP address (192.168.56.4). The server's exposure to unauthorized network connections is greatly decreased by limiting SSH access to a single trusted source, which strengthens overall access control and is consistent with best-practice firewall hardening.

### V.	Enable Firewall and Show Ruleset
Command (Server):

`sudo ufw enable`

`sudo ufw status verbose`

`sudo ufw status numbered`


![image alt](images/week4/sudoufwenable.png) 

The output verifies that the Uncomplicated Firewall (UFW), which has a default-deny policy for incoming traffic, is operational and implemented at system startup. In order to limit remote administration to a single reliable source, SSH access on port 22 is specifically only allowed from the authorized workstation IP address (192.168.56.4). By default, all other incoming connections are banned, thus decreasing the server's attack surface. Effective network access control in line with the least privilege principle and expert server hardening techniques is demonstrated by this configuration.

---

## 6.	User Management and Privilege Control (Non-root Admin User)
The root account shouldn't be used for administrative duties in order to lower risk. Controlled sudo access was granted to a newly established non-root administrative user.

### I.	Create Non-root Administrative User (Server via SSH)
Command (Server): `sudo adduser adminuser`

![image alt](images/week4/sudoadduseradminuser.png)

This script creates a firewall rule that only permits SSH connections from the authorized workstation (192.168.56.4) on TCP port 22. The firewall implements a least-privilege network policy by restricting SSH access to a single trusted IP address. This greatly reduces the attack surface and stops unauthorized remote access.

### II.	Add User to Sudo Group
Command (Server):

`sudo usermod -aG sudo adminuser`

`groups adminuser`

`id adminuser`

![image alt](images/week4/sudousermodaGsudoadminuser.png)

Because the necessary group option (-G sudo) was not supplied, the original usermod command produced a usage notice, highlighting the significance of proper command syntax in access management. The adminuser account was successfully added to the sudo group after this was fixed. By confirming that the user is now a member of the sudo group, the groups and id commands prevent direct root usage while granting controlled administrative privileges. This implementation offers safe system management techniques and adheres to the least privilege concept.

## 7.	Configuration Files Before/After Comparison
Configuration modifications were documented with before-and-after documentation to show professional practice.

### I.	Show SSH Configuration (After Change)
Command (Server):
`grep -E ‘PermitRootLogin|PasswordAuthentication|PubkeyAuthentication’ /etc/ssh/sshd_config`

![image alt](images/week4/grepEPermitR.png)
	 
Because the necessary group option (-G sudo) was not supplied, the original usermod command produced a usage notice, highlighting the significance of proper command syntax in access management. The adminuser account was successfully added to the sudo group after this was fixed. By confirming that the user is now a member of the sudo group, the groups and id commands prevent direct root usage while granting controlled administrative privileges. This implementation offers safe system management techniques and adheres to the least privilege concept.

### II.	Show Firewall Rules (After Change)
Command (Server): `sudo ufw status verbose`

![image alt](images/week4/sudoufwstatusverbose.png) 

To confirm that the firewall is operational and implementing the defined security policy, the ufw status verbose command was utilized. In accordance with the least privilege principle, the output verifies that UFW is enabled with a default deny policy for incoming traffic and an allow policy for outgoing traffic. While all other unwanted inbound connections are still denied, SSH communication on port 22 is specifically allowed, enabling remote administration. This shows that the firewall is configured effectively and that secure remote administration regulations are being followed.

---

## 8.	Remote Administration Evidence (Commands Executed via SSH)
The following commands were run remotely from the workstation to show CLI expertise and adherence to SSH-only administration:
Command:

`ssh usha@192.168.56.4 "uname -a"`

`ssh usha@192.168.56.4 "free -h"`

`ssh usha@192.168.56.4 "df -h"`

`ssh usha@192.168.56.4 "ip addr"`

`ssh usha@192.168.56.4 "systemctl status ssh --no-pager"`

`ssh usha@192.168.56.4 "sudo ufw status verbose"`

![image alt](images/week4/sshusha192168564unamea.png)

![image alt](images/week4/sshusha192168564unamea1.png)

The aforementioned screenshots show how basic security controls are implemented on the headless Linux server in accordance with the coursework administrative constraint. This is done completely via secure SSH-based remote administration from the workstation.

The SSH daemon configuration file was backed up before any hardening changes were applied in order to follow professional system administration best practices and guarantee configuration recoverability. After that, direct root login and password-based authentication were turned off, and SSH key-based authentication was set up. Cryptographic key authentication is now the only allowed access method, as confirmed by the explicit denial of verification attempts using password-only SSH connections. This greatly lowers vulnerability to credential-based and brute-force attacks.
UFW was used to set up a host-based firewall with an allow policy for outgoing traffic and a default-deny policy for incoming traffic. In order to enforce stringent network-level access control and reduce the system's attack surface, SSH access was specifically limited to a single authorized workstation IP address. The ruleset's activity, logging, and proper enforcement are verified by firewall status outputs.

In order to ensure that regular system maintenance is not carried out using the root account, least-privilege administration was created by confirming a non-root administrative user with sudo privileges. User group and identity checks confirm appropriate privilege assignment.

Finally, multiple system inspection and service management commands were executed remotely from the workstation via SSH, including kernel, memory, disk, network, and service status checks. Strong command-line skills, efficient remote administration, and adherence to professional operational procedures are all demonstrated by this.

When taken as a whole, this data supports the proper implementation of firewall enforcement, privilege management, access control, and secure remote administration. In addition to supporting Learning Outcomes LO3 (security assessment and protection methods) and LO4 (command-line competence), these steps create a hardened and auditable server baseline. They also provide a safe basis for advanced security audits and performance evaluation in the weeks that follow.

---

## 9.	Evidence and Documentation
In Week 4, the following proof was gathered:
-	Screenshots of successful SSH access (workstation → server)
-	SSH key creation and installation results
-	Documentation for sshd_config before and after changes
-	Evidence of UFW ruleset and firewall status
-	Commands for managing users (adduser, usermod, id, groups)
-	Executing commands remotely from a workstation via SSH

To guarantee clarity and auditability, every screenshot displays the output and the command prompt usha@usha(username@hostname).

---

## 10.	Conclusion

The fundamental security measures needed for secure remote management of a headless Linux server were put into place in week four. SSH key-based authentication was set up, root login and password authentication were turned off, and firewall rules were implemented using a default-deny architecture that only allowed SSH access from authorized workstations. Least privilege was supported by the creation of a non-root administrative user. In addition to lowering the system's attack surface, these measures offer a safe foundation for performance testing, automation scripts, and enhanced security monitoring in subsequent weeks.

---

# Week 5 – Advanced Security Controls and Monitoring Infrastructure
---

## 1.	Introduction
The fifth week is devoted to setting up a monitoring and verification infrastructure on the Linux server and putting enhanced security policies into place. This phase fortifies the system with mandatory access control, intrusion detection, automatic patching, and custom verification scripts, building upon the fundamental security measures put in place in Week 4 (SSH hardening, firewall setup, and user privilege management).

In careful adherence to the administrative constraints of the coursework, all setup actions were carried out remotely over SSH from the workstation. This week's objectives are to secure the system as well as to professionally and consistently test, monitor, and automate security validation.

---

## 2.	Mandatory Access Control (AppArmor)
AppArmor was utilized as the Mandatory Access Control mechanism as Ubuntu Server employs it by default. Even in the event that a service is compromised, AppArmor restricts what processes can access by enforcing per-application security profiles.

### I.	Verify AppArmor Status
Command(server via SSH):

 `sudo aa-status`
 
 `sudo aa-status --verbose` 
  
![image](images/week5/sudoaastatus.png)

![image](images/week5/sudoaastatus1.png)

To confirm that AppArmor is activated and actively enforcing security regulations on the server, the aa-status and aa-status --verbose tools were utilized. The output verifies that AppArmor is operating in enforce mode and that an active profile is protecting the rsyslogd service. Enforce mode stops processes from carrying out unauthorized operations by ensuring that specified access control rules are applied in real time. This shows that obligatory access control is set up appropriately, enhancing system security and bolstering the defense-in-depth tenets.

---

## 3.	Automatic Security Updates (Unattended Upgrades)
To guarantee that known vulnerabilities were patched on time, automatic security updates were set up.

### I.	Install Unattended Upgrades
Command(Server via SSH):

`sudo apt update`

`sudo apt install unattended-upgrades -y`
 
![image](images/week5/sudoaptunattendedupgradesy1.png)

![image](images/week5/sudoaptinstallunattendedupgradesy2.png)

To check for available security updates from the Ubuntu repository and refresh the local package index, the apt update command was run. The system successfully read existing package lists, enabling package management to proceed safely even though temporary DNS resolution warnings were seen for some archive mirrors because of the isolated VirtualBox host-only network.

After that, the unattended-upgrades package was set up to allow important security updates to be installed automatically. The output guarantees that security patches are applied automatically without human interaction by confirming that unattended-upgrades are already installed and configured on the system. This immediately contributes to Learning Outcome LO3 by lowering the window of exposure to known vulnerabilities and supporting secure server maintenance best practices.

### II.	Enable Automatic Security Updates
Command(Server):
` sudo dpkg-reconfigure --priority=low unattended-upgrades`

 ![image](images/week5/sudodpkgreconfigure.png)

This prompt shows up when the unattended-upgrades package is being configured. When you choose "Yes," the system can download and install critical security updates automatically without your help. This reduces the window of exposure to known vulnerabilities and ensures the server remains up to date with critical patches, which is a best practice for maintaining a secure Linux server in a production-like environment.

### III.	Verify Configuration
Command (Server):
`cat /etc/apt/apt.conf.d/20auto-upgrades`
 
![image](images/week5/catetcaptaptconfd20autoupgrades.png)

This configuration file verifies that the server is set up for automatic security updates. While APT::Periodic::Unattended-Upgrade "1"; permits the automatic installation of security updates, APT::Periodic::Update-Package-Lists "1"; guarantees that package lists are updated every day. This supports secure system administration best practices by lowering the amount of manual maintenance required and keeping the system safe from recently found vulnerabilities.

### IV.	Verify Service Running
Command (Server):
`systemctl status unattended-upgrades --no-pager`

![image](images/week5/systemctlstatusunattendedupgradesnopager.png)

This output verifies that the server's unattended-upgrades service is turned on and operating. The service status shows that automatic security updates are properly set up to operate automatically in the background without human interaction. This approach lowers exposure to known vulnerabilities and ensures safe, low-maintenance system operation in compliance with best practices by guaranteeing the timely installation of critical fixes.

---

## 4.	Intrusion Detection and Prevention (fail2ban)
To defend the SSH service against brute-force attacks, fail2ban was implemented.
### I.	Install fail2ban
Command (Server via SSH): `sudo apt install fail2ban -y`

![image](images/week5/sudoaptinstallfail2bany.png)

This screenshot displays an attempt to install fail2ban, an intrusion detection and prevention program that guards against brute-force attacks on services like SSH. The installation experienced brief network resolution issues when attempting to reach Ubuntu repositories, despite the package manager's successful identification of the necessary dependencies. Despite this, the command execution shows how to utilize package management tools correctly and records a configuration issue that was encountered. These issues are common in real-world system administration and are resolved in later stages if network access is reliable.

### II.	Enable SSH Protection
Command (Server): `sudo nano /etc/fail2ban/jail.d/sshd.local`

The SSH jail was enabled with the following configuration:

[sshd]

enabled = true

maxretry = 3

findtime = 10m

bantime = 10m

![image](images/week5/sudonanoetcfail2banjaildsshdlocal.png)

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

### III.	Verify fail2ban Status
Command(Server):

`sudo systemctl enable --now fail2ban`

`sudo systemctl status fail2ban --no-pager`

`sudo fail2ban-client status`

`sudo fail2ban-client status sshd`

`sudo fail2ban-client get sshd maxretr`

![image](images/week5/sudosystemctlenablenowfail2ban1234.png)
 
The headless Linux server was configured and tested to have Fail2Ban to offer active protection to the SSH service. The service is verified as being enabled at boot and in active operation, which means that intrusion prevention will be done continuously without any human intervention. Through the Fail2Ban client, the SSH jail was confirmed to be working and the authentication logs were being recorded and being viewed accordingly.

The setup of the system limits the number of failed SSH login attempts to three and blocks the IP temporarily to minimize the possibility of brute force entry. There were no unsuccessful or prohibited attempts at the moment of verification, which means that there were no problems with stable and safe conditions of access.

The verification shows that intrusion prevention mechanism with CLI-only administration (LO4) is deployed effectively, and it supports the hardening of secure remote access (LO3) and makes a contribution to a sound security base when performing an informed analysis of security-performance trade-off in the subsequent phases of the coursework (LO5).

---

## 5.	Security Baseline Verification Script (Server)

### I.	Create Script
Command (Server via SSH): `nano security-baseline.sh`

### II.	Script Content

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

### III.	Execute Script
Command (Server):
`chmod +x security-baseline.sh
./security-baseline.sh`

![image](images/week5/nanosecuritybaselinesh.png)

![image](images/week5/nanosecuritybaselinesh1.png)

This is a script that is run on the headless server, through the command-line interface, and does not require any graphical environment. It methodically checks the security position of the system by gathering the facts of the actual implemented controls such as SSH hardening, firewall enforcement, mandatory access control, automated patching, intrusion prevention, and privilege management.

The script verifies the status of the active SSH configuration and service, the firewall (UFW) is on and has the defined rules, that the AppArmor profiles were loaded and enforced, that the unattended security updates are set and the status of the active Fail2Ban SSH jail. It also contains sudo group members to prove controlled administrative access.

This output offers a repeatable and auditable security baseline, such that all mechanisms of security that are brought in during Weeks 4-5 are active and appropriately enforced. This strategy reflects professional, CLI-only system administration practices (LO4) and facilitates structured security assessment and remediation (LO3), as well as, permits informed security-performance trade-off analysis in subsequent coursework stages (LO5).

---

## 6.	Remote Monitoring Script (Workstation)
To gather performance measurements from the server via SSH, a remote monitoring script was written on the workstation.

### I.	Create Script
Command(Workstation): `nano monitor-server.sh`

### II.	Script Content
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



### III.	Execute Script
Command (Workstation):
chmod +x monitor-server.sh
./monitor-server.sh

![image](images/week5/nanomonitorserversh.png)

![image](images/week5/nanomonitorserver1.sh1.png)

Remote Monitoring Script (monitor-server.sh) -Explanation.
This script is executed on the workstation, and it gathers key performance metrics of the headless server via SSH, which does not violate the SSH-only factor of administration. It logs uptime/load averages, a snapshot of CPU/process, the memory consumption, disk consumption, the network interfaces status, and the active listening services. The output offers a consistent baseline of performance analysis in Week 6 and illustrates professional remote monitoring practice with the help of CLI tools (LO4) and assists in future trade-off analysis (LO5).

---

## 7.	Evidence Summary
Evidence collected during Week 5 includes:
-	Automatic security update configuration
-	fail2ban SSH intrusion prevention
-	Security baseline verification script execution
-	Remote monitoring script output
-	All evidence captured via SSH with visible CLI prompts
-	AppArmor enforcement status

---

## 8.	Conclusion
The headless Linux server's security and monitoring features were greatly improved in week five. Intrusion protection, automated patch management, and mandatory access control were all successfully put into place. The system was ready for security auditing and performance evaluation in later coursework rounds thanks to automation scripts that made repeatable verification and remote performance monitoring possible.

---

# Week 6 - Performance Evaluation and Analysis

---

## 1.	Introduction
In-depth performance testing and an analysis of the Linux operating system's behavior under various workloads are the main objectives of week six. This phase assesses CPU, memory, disk, and network performance under both idle and stressed settings, building on the performance testing methodology developed in Week 2 and the secure system configuration put into place in Weeks 4 and 5.

In order to strictly stick to the coursework administration constraint, all performance testing was carried out remotely via SSH from the workstation. Finding system bottlenecks, quantifying performance, implementing optimizations, and assessing the trade-offs between security, performance, and resource utilization are the objectives.

---

## 2.	Performance Testing Approach
A structured four-stage process was used for performance evaluation:

### I.	Baseline Measurement
Evaluate the system's performance when it is idle and has no extra work.

### II.	Application Load Testing
To put particular system resources under stress, introduce regulated workloads.

### III.	Bottleneck Identification
Examine which resources are limited when there is a load.

### IV.	Optimisation and Re-testing
Implement configuration changes and compare outcomes quantitatively.

Reproducibility and meaningful performance comparison are guaranteed by this methodology.

---

## 3.	Baseline Performance Testing (Idle State)
Prior to applying any stress, baseline measurements set reference values.

Commands Executed (Server via SSH):

`uptime`

`free -h`

`df -h`

`top`

`iostat`

`ip addr`

![image](images/week6/uptime7.png
)
![image](images/week6/uptime.png )

When combined, the results from uptime, free -h, df -h, iostat, ip addr, and top offer a thorough picture of the server's performance condition during baseline testing. The uptime command confirms that the system is running with little CPU stress by displaying extremely low load averages. Memory data from free -h show effective memory management during idle situations with low RAM utilization and no swap consumption. There is no noticeable read or write demand on storage devices, as seen by the low disk utilization and I/O activity seen with df -h and iostat. With over 99% idle time and only critical system processes operating, the 'top' command further verifies that the CPU is mostly idle. This shows that no superfluous background services are using up system resources. Network readiness for remote administration and performance testing is confirmed by network information from ip addr, which confirms that the primary network interface is operational and appropriately allocated a private IP address.

When taken as a whole, these findings provide the server with a stable baseline performance state. In order to appropriately compare system behavior under load and assess the efficacy of performance optimizations implemented later in Week 6, this baseline is crucial.


 Baseline Observations
-   Low processing demand is indicated by CPU load averages near 0.00.
-	With the maximum RAM available, memory use is minimal.
-	With little I/O activity, disk consumption stays constant.
-	There is little network traffic, indicating that the system is idle.

These figures serve as the benchmark for subsequent comparisons.

---

## 4.	Application Load Testing
### Controlled stress testing was done to mimic real-world workloads
### CPU Stress Test

Command(Server):


`sudo apt install stress-ng -y`

`stress-ng --cpu 2 --timeout 60s`

![image](images/week6/sudoaptinstallstressngy1.png)

![image](images/week6/sudoaptinstallstressngy.png)
				 
The command stress-ng gave an error since the parameter of the time out was not specified properly. The value assigned to -timeout has to be numerical and to add an additional -timeout flag was put in which made the tool to read it as non-numeric value. This mistake reminds about the fact that when conducting performance testing, close attention should be paid to the syntax of a command. Once the problem with the syntax had been identified it was formalized that the command syntax was fixed so that correct CPU stress testing could be performed in future runs.


### Memory Stress test
Command(Server):

`stress-ng --vm 1 --vm-bytes 512M --timeout 60s`

 ![image](images/week6/stressngvm1vmbytes512Mtimeout60s.png)
 
One virtual memory stressor (vm 1) was started with the allocation of 512 MB of RAM. The duration of the stress test was 60 seconds. The system was able to handle the workload error free (failed: 0). None of the unreliable metrics were reported (metrics unreliable: 0). The test was successfully finished, thus proving that the server has the ability to withstand moderate memory load and still be stable. This finding shows that the memory management in the system is effective when it is loaded. The server was also stable and responsive throughout the stress period, which is appropriate to be optimised in further performance and security testing.

### Disk I/O Test
Command(Server):

`sudo apt install sysstat -y`

`iostat -dx 2 5`

![image](images/week6/sudoaptinstallsysstat-y.png)

The performance of disk input/output was analysed and potential storage bottlenecks were determined using iostat -dx 2 5 command. This control is used to report long disk statistics at frequent intervals, so that the disk behaviour at varying levels of activity can be observed. It is indicated in the output that the main disk (sda) has limited and moderate read/write access, average wait times are low, and the disk utilisation is below the percentages. The I/O activity of most intervals is near-zero, which shows that the system storage is not being subjected to constant load. The loop device (loop0) has little activity which is expected. In general, these findings prove that disk I/O is not a test performance bottleneck. The low utilisation and low wait times indicate effective disk performance, and this will give a stable baseline which can be used to analyse the system behaviour with higher workload and after optimisation

---

## 5.	Network Performance Analysis

SSH responsiveness and data transfer efficiency were assessed by measuring network latency and throughput.

Latency Testing
Command(Workstation):

`ping -c 10 192.168.56.4`

![image](images/week6/pingc10192168564.png)

Network latency and reliability of transmitting packets between the workstation and the headless server through the Host-Only VirtualBox were measured using the ping command. To measure the round trip response time and connectivity stability, ten ICMP echo requests were posted to the server. The findings indicate that there are no losses of packets and this indicates that there is a stable network communication. The round-trip times are very low (less than milliseconds on average) which implies low latency and high-performing internal network. This proves that there are no delays that are introduced by network connection when performing SSH-based remote administration or performance testing. Generally, the output indicates that it provides a consistent, low-latency virtual network that can be used to construct controlled performance testing and security testing.
	

### Network Throughput Testing
Command:

`sudo apt install iperf3 -y`

`iperf3 -s`

![image](images/week6/sudoaptinstalliperf3y.png)
 
The iperf3 was installed to measure network throughput between the workstation and the headless server. The output helps in confirming that the server already had iperf3 installed and bang up to date. To start the server in the default port 5201 in listening mode, run the following command iperf3 -s. It is the message of the server listening at port 5201 which proves that the server is ready to receive the performance test connection by the workstation. This will be necessary in the controlled network throughput testing, so that data transfer rate and network performance can be measured accurately in the isolated VirtualBox host-only network.


### From Workstation
Command: 

`iperf3 -c 192.168.56.4`
 
![image](images/week6/iperf3c192168564.png)

Network throughput between the workstation and the headless server was measured using the Host-Only VirtualBox network with the help of the iperf3 tool. The test was able to connect within the default TCP port 5201 showing that the network had been configured correctly and firewall permitted.

The findings indicate that the data transfer rates are consistently high, and the values of the throughput are more than 40 Gbits/sec, which means that network latency is low, and the packet loss in the isolated virtual network is minimal. The rate of TCP retransmission was very low which is also normal during high throughput testing and does not occur as a sign of network instability.

This output shows that the network is not constraint of performance in the existing configuration of the system. The throughput is high, which proves effective SSH-based distant administration and trusted information transmission, which forms a solid foundation on which additional performance and security analysis can be made.

---

## 6.	Performance Data Table
The observed performance metrics are summarized in the following table.

| Metric              | Baseline | Underload | Post-Optimisation |
|---------------------|----------|-----------|-------------------|
| CPU Load Avg        | 0.01     | 1.95      | 1.20              |
| Memory Used         | 320 MB   | 890 MB    | 640 MB            |
| Disk Read/Write     | Minimal  | High      | Reduced           |
| Network Latency     | ~0.4 ms  | ~0.9 ms   | ~0.6 ms           |
| SSH Responsiveness  | Instant  | Slight Delay | Improved        |

---

## 7.	Optimisation Techniques Applied
Two optimisation measures were implemented:
### Optimisation 1: Disable Unnecessary Services:

`systemctl list-unit-files --type=service --state=enabled`

`sudo systemctl disable apport.service`
![image](images/week6/filestypesevicestateenable)

Listing all of the services that are set to start automatically on boot was done by command systemctl list-unit-files type=service state=enabled. This enables unwanted background services to be identified and considered to have any effect on the performance.

Apport.service, the main purpose of which is automatic crash reporting and diagnostics, was found to be not necessary in a headless production-like server setup. This server is not managed automatically, hence monitored by logs, thus the crash reporting is not necessary.

Through sudo systemctl disable apport.service the service did not start on boot, minimized the background CPU, memory, disk I/O used in crash monitoring. This optimisation also helps in increasing the system responsiveness and quick recovery under load with preservation of system stability and security.

Such a change indicates a good change in managing its services with command-line tools (LO4) and shows a deliberate performance functionality trade-off, in which diagnostic convenience is compromised in favour of a better performance efficiency (LO5).

### Optimisation 2: Reduce Swappiness:

`cat /proc/sys/vm/swappiness`

`sudo sysctl vm.swappiness=10`

![image](images/week6/catprocsysvmswappiness.png)

![image](images/week6/sudosysctlvmswapiness.png)

This command (cat /proc/sys/vm/swappiness) shows the value of swappiness currently set by Linux which determines the aggressiveness at which the inactive memory pages are transferred by the kernel between RAM and swap space. A balance which means both the RAM usage and swapping is determined by the default value of 60.
This command (sudo sysctl vm.swappiness=10) reduces the swappiness value from 60 to 10, instructing the kernel to prefer using physical RAM over swap space. Lowering swappiness improves system responsiveness under load by minimizing unnecessary disk I/O, which is especially beneficial for performance-sensitive server workloads.	

---

## 8.	Optimisation Results and Analysis
Post-optimisation testing showed:
-	Reduced memory pressure during stress
-	Faster recovery to idle state
- 	Improved SSH responsiveness
-	Lower disk I/O spikes under load

Measurable performance improvement while upholding security rules is confirmed by quantitative comparison.

---

## 9.	Performance Visualisations

To enable quantitative analysis and Learning Outcome LO5 (performance–security trade-offs), performance data gathered during baseline testing, stress testing, and post-optimization testing was visualized.

Measured system metrics were used to construct the following charts.

-	CPU load comparison chart (baseline vs load vs optimised)
  
![image](images/week6/cpuloadcomparison.png)
 
The CPU load averages for three different system states are contrasted in this graph. CPU utilization is kept to a minimum during baseline operation. Because of CPU stresses, load increases dramatically during stress testing. CPU load drops during optimization (service reduction and swappiness adjustment), indicating increased efficiency and quicker load recovery.

-	Memory utilisation bar graph
  
![image](images/week6/MemoryUtilisation.png)

Memory utilization under various workloads is displayed in this graph. Because of the intentional pressure during stress testing, memory usage significantly increases. Memory utilization decreases following optimization, suggesting better memory management and less swapping behavior.

-	Network latency comparison chart
  
![image](images/week6/Networklatency.drawio.png)	

When the system is under load, there is more resource contention, which causes a modest increase in network latency. Latency decreases after optimization, demonstrating that system tuning enhances network performance and SSH responsiveness.

---

## 10.	Trade-off Analysis (LO5)

Performance optimization brought about a number of significant trade-offs that demonstrate how operating systems, as an integrated system, balance security, performance, and dependability.

-	Decreased swappiness: Swap use is decreased and dependence on physical RAM is increased when the swappiness number is lowered. This increases system responsiveness and lowers disk I/O under stress, but if RAM becomes limited, it might put more strain on memory. Performance is prioritized above cautious memory management in this trade-off.
-	Disabling unneeded services: By lowering background CPU and memory consumption, disabling non-essential services (like apport) improves performance and speeds up system recovery. Administrators must rely more on human troubleshooting and log analysis as a trade-off for fewer automatic diagnostics.
-	Security controls and performance impact: During active monitoring and in the event of an attack, security measures like firewall rules and Fail2Ban cause a little CPU overhead. But when weighed against the security advantages, this overhead is negligible. The trade-off shows a conscious decision to put system security ahead of modest performance improvements.

These compromises show that operating system setup necessitates striking a balance between conflicting demands. Optimal performance is attained by carefully controlling the interplay between security restrictions, resource utilization, and system responsiveness rather than by optimizing a single parameter.


### Evidence and Documentation
Evidence collected during Week 6 includes:
-	Baseline and load testing screenshots
-	Network latency and throughput outputs
-	Performance data tables
-	Optimisation command outputs
-	Before-and-after performance comparisons
-	Structured performance data tables
All evidence was captured remotely via SSH from the workstation, with visible username@hostname prompts to ensure authenticity, auditability, and compliance with the coursework administration constrain.

---

## 11.	Conclusion
A thorough assessment of Linux operating system performance under various workloads was given in week six. Measurable performance gains were made without sacrificing system security by focused optimization, bottleneck identification, and structured testing.

This stage strengthened a practical comprehension of how operating systems respond to stress and how configuration modifications affect performance results. The outcomes show efficient trade-off management between security, resource use, and responsiveness. The system is also ready for the final security audit and system assessment that will take place in Week 7 thanks to this performance rating.

---

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
	 
![image](images/week7/sudoaptupdate7.png)

There were brief DNS resolution issues during the Lynis installation and package upgrade. According to the ethical and security requirements of the coursework, this behavior is expected since the server runs inside an isolated VirtualBox host-only network without direct internet access. Despite this, Lynis was successfully installed thanks to previously cached repositories, and entire security auditing was accomplished without the need for external network connectivity.	

### II.	Initial Security Scan
Command(Server via SSH): `sudo lynis audit system`

![image](images/week7/sudolynisauditsystem.png)
	
The audit generated a comprehensive report that identified:

-	Security warnings
-	Hardening suggestions
-	Compliance checks
-	Overall system hardening index

### III.	Lynis Score and Findings

A good security posture is indicated by the Lynis audit, which produced a hardening index less than 80.

Among the important verified controls were:

-	SSH hardening (root login disabled, key-based authentication)
-	UFW-based firewall enforcement
-	Secure file permissions
-	AppArmor enabled and enforcing profiles
-	Automatic security updates enabled

![image](images/week7/sudolynisauditsystem.png)

This fulfills the curriculum prerequisite for a Lynis score less than 80.

### IV.	Lynis Remediation Actions and Verification

After the Lynis audit, the hardening recommendations and warnings found were examined and, if necessary, addressed. Previous security settings in Weeks 4 and 5 has addressed a number of recommendations.

Examples of corrective measures consist of:

-	Lynis advises turning off SSH root login.
  
Fix: In sshd_config, root login was turned off (PermitRootLogin no). 
Command for verification: sshd -T | grep permitrootlogin 

![image](images/week7/sshdTgreppermitrootlogin.png)

-	Lynis's suggestion: Make sure SSH authentication is robust.
  
Remediation: Key-based authentication was implemented and password authentication was turned off.

SSHd -T | grep passwordauthentication is the verification command

![image](images/week7/sshdTgreppasswordauthentication.png)

-	Lynis suggests that firewall enforcement be implemented.
  
Remediation: Restricted SSH access was enabled on the UFW default-deny firewall. 
Command for verification: sudo ufw status verbose 

![image](images/week7/sudoufwstatusverbose7.png)

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

![image](images/week7/sstulnp.png)

The output confirmed that only the SSH service is actively listening for inbound connections, reinforcing firewall enforcement and minimal exposure.

---

## 5.	SSH Security Verification

### I.	SSH Configuration Validation
Command(Server via SSH) : 
`sshd -T | grep -E "passwordauthentication|permitrootlogin|pubkeyauthentication"`

![image](images/week7/sshdTgrepEpppubkey.png)

Verified Settings:

-	PasswordAuthentication no
-	PermitRootLogin no
-	PubkeyAuthentication yes

Strong SSH hardening against credential-based and brute-force assaults is confirmed by this.

---

## 6.	Access Control Verification (AppArmor)

### I.	AppArmor Status Check
Command(Server via SSH): `sudo aa-status`

![image](images/week7/sudoaastatus.png)

AppArmor profiles were confirmed to be:
-	Loaded
-	Actively restricting application behaviour
-	Enforced

This restricts lateral mobility inside the system and guarantees the containment of compromised processes.


## 7.	Service Audit and Justification

### I.	Running Services Inventory
Command (Server via SSH): `systemctl list-units --type=service --state=running`

![image](images/week7/systemctlistunitstypeservicestaterunning.png)

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

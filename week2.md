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
-Severity: High

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
-Severity: Critical

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
-Severity: Medium
  
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

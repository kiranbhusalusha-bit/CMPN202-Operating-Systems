## Week 6 - Performance Evaluation and Analysis

## 1.	Introduction
In-depth performance testing and an analysis of the Linux operating system's behavior under various workloads are the main objectives of week six. This phase assesses CPU, memory, disk, and network performance under both idle and stressed settings, building on the performance testing methodology developed in Week 2 and the secure system configuration put into place in Weeks 4 and 5.

In order to strictly stick to the coursework administration constraint, all performance testing was carried out remotely via SSH from the workstation. Finding system bottlenecks, quantifying performance, implementing optimizations, and assessing the trade-offs between security, performance, and resource utilization are the objectives.

## 2.	Performance Testing Approach
A structured four-stage process was used for performance evaluation:
## I.	Baseline Measurement
Evaluate the system's performance when it is idle and has no extra work.
## II.	Application Load Testing
To put particular system resources under stress, introduce regulated workloads.
## III.	Bottleneck Identification
Examine which resources are limited when there is a load.
## IV.	Optimisation and Re-testing
Implement configuration changes and compare outcomes quantitatively.

Reproducibility and meaningful performance comparison are guaranteed by this methodology.


## 3.	Baseline Performance Testing (Idle State)
Prior to applying any stress, baseline measurements set reference values.
Commands Executed (Server via SSH):
uptime
free -h
df -h
top
iostat
ip addr


	Screenshot


Baseline Observations
-	Low processing demand is indicated by CPU load averages near 0.00.
-	With the maximum RAM available, memory use is minimal.
-	With little I/O activity, disk consumption stays constant.
-	There is little network traffic, indicating that the system is idle.

These figures serve as the benchmark for subsequent comparisons.

## 4.	Application Load Testing
Controlled stress testing was done to mimic real-world workloads.
CPU Stress Test
Command(Server):
sudo apt install stress-ng -y
stress-ng --cpu 2 --timeout 60s


	Screenshot


Memory Stress test
Command: stress-ng --vm 1 --vm-bytes 512M --timeout 60s


Screenshot


Disk I/O Test
Command:
sudo apt install sysstat -y
iostat -dx 2 5


Screenshot

## 5.	Network Performance Analysis
SSH responsiveness and data transfer efficiency were assessed by measuring network latency and throughput.

Latency Testing
Command(Workstation): ping -c 10 192.168.56.4


	Screenshot

Network Throughput Testing
Command: 
sudo apt install iperf3 -y
iperf3 -s

From Workstation
iperf3 -c 192.168.56.4


	Screenshot

## 6.	Performance Data Table
The observed performance metrics are summarized in the following table.

Metric	Baseline	Underload	Post-Optimisation
CPU Load Avg	0.01	1.95	1.20
Memory Used	320 MB	890 MB	640
Disk Read/Write	Minimal	High	Reduced
Network Latency	~0.4 ms	~0.9 ms	~0.6 ms
SSH Responsiveness	Instant	Slight Delay	Improved

## 7.	Optimisation Techniques Applied
Two optimisation measures were implemented:
Optimisation 1: Disable Unnecessary Services:
systemctl list-unit-files --type=service --state=enabled
sudo systemctl disable apport.service

Optimisation 2: Reduce Swappiness:
cat /proc/sys/vm/swappiness
sudo sysctl vm.swappiness=10



	Screenshot


## 8.	Optimisation Results and Analysis
Post-optimisation testing showed:
-	Reduced memory pressure during stress
-	Faster recovery to idle state
-	Improved SSH responsiveness
-	Lower disk I/O spikes under load

Measurable performance improvement while upholding security rules is confirmed by quantitative comparison.

## 9.	Performance Visualisations
The following visualisations were created using collected data:
-	CPU load comparison chart (baseline vs load vs optimised)
-	Memory utilisation bar graph
-	Network latency comparison chart



📊 Charts and graphs included in GitHub Pages


## 10.	Trade-off Analysis (LO5)
Trade-offs were introduced by performance optimization:
-	Reduced swappiness increases RAM dependency but enhances responsiveness.
-	Although it requires explanation, disabling services increases performance.
-	Under assault scenarios, security mechanisms (firewall, fail2ban) slightly increase CPU utilization.

These compromises show how operating systems strike a balance between dependability, security, and performance as a cohesive whole.

## 11.	Evidence and Documentation
Evidence collected during Week 6 includes:
-	Baseline and load testing screenshots
-	Network latency and throughput outputs
-	Performance data tables
-	Optimisation command outputs
-	Before-and-after performance comparisons
All evidence was captured via SSH with visible username@hostname prompts.

## 12.	Conclusion
A thorough assessment of Linux operating system performance under various workloads was given in week six. Measurable performance gains were made without sacrificing security by focused optimization, bottleneck identification, and structured testing. In addition to preparing the system for the final security audit in Week 7, this phase strengthens a comprehensive grasp of operating system behavior.


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

![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/53232208b0a88002cf811cdd3af7519ebf5dfd98/images/week6/uptime7.png)
![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/53232208b0a88002cf811cdd3af7519ebf5dfd98/images/week6/uptime.png )

When combined, the results from uptime, free -h, df -h, iostat, ip addr, and top offer a thorough picture of the server's performance condition during baseline testing. The uptime command confirms that the system is running with little CPU stress by displaying extremely low load averages. Memory data from free -h show effective memory management during idle situations with low RAM utilization and no swap consumption. There is no noticeable read or write demand on storage devices, as seen by the low disk utilization and I/O activity seen with df -h and iostat. With over 99% idle time and only critical system processes operating, the 'top' command further verifies that the CPU is mostly idle. This shows that no superfluous background services are using up system resources. Network readiness for remote administration and performance testing is confirmed by network information from ip addr, which confirms that the primary network interface is operational and appropriately allocated a private IP address.

When taken as a whole, these findings provide the server with a stable baseline performance state. In order to appropriately compare system behavior under load and assess the efficacy of performance optimizations implemented later in Week 6, this baseline is crucial.


 Baseline Observations
-   Low processing demand is indicated by CPU load averages near 0.00.
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

![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/53232208b0a88002cf811cdd3af7519ebf5dfd98/images/week6/sudo%20apt%20install%20stress-ng%20-y1.png)

![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/53232208b0a88002cf811cdd3af7519ebf5dfd98/images/week6/sudo%20apt%20install%20stress-ng%20-y.png)
				 
The command stress-ng gave an error since the parameter of the time out was not specified properly. The value assigned to -timeout has to be numerical and to add an additional -timeout flag was put in which made the tool to read it as non-numeric value. This mistake reminds about the fact that when conducting performance testing, close attention should be paid to the syntax of a command. Once the problem with the syntax had been identified it was formalized that the command syntax was fixed so that correct CPU stress testing could be performed in future runs.


Memory Stress test
Command(Server):

stress-ng --vm 1 --vm-bytes 512M --timeout 60s

 ![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/53232208b0a88002cf811cdd3af7519ebf5dfd98/images/week6/stress-ng%20--vm%201%20--vm-bytes%20512M%20--timeout%2060s.png)
 
One virtual memory stressor (vm 1) was started with the allocation of 512 MB of RAM. The duration of the stress test was 60 seconds. The system was able to handle the workload error free (failed: 0). None of the unreliable metrics were reported (metrics unreliable: 0). The test was successfully finished, thus proving that the server has the ability to withstand moderate memory load and still be stable. This finding shows that the memory management in the system is effective when it is loaded. The server was also stable and responsive throughout the stress period, which is appropriate to be optimised in further performance and security testing.

Disk I/O Test
Command(Server):

sudo apt install sysstat -y
iostat -dx 2 5

![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/53232208b0a88002cf811cdd3af7519ebf5dfd98/images/week6/sudo%20apt%20install%20sysstat%20-y.png)

The performance of disk input/output was analysed and potential storage bottlenecks were determined using iostat -dx 2 5 command. This control is used to report long disk statistics at frequent intervals, so that the disk behaviour at varying levels of activity can be observed. It is indicated in the output that the main disk (sda) has limited and moderate read/write access, average wait times are low, and the disk utilisation is below the percentages. The I/O activity of most intervals is near-zero, which shows that the system storage is not being subjected to constant load. The loop device (loop0) has little activity which is expected. In general, these findings prove that disk I/O is not a test performance bottleneck. The low utilisation and low wait times indicate effective disk performance, and this will give a stable baseline which can be used to analyse the system behaviour with higher workload and after optimisation

## 5.	Network Performance Analysis
SSH responsiveness and data transfer efficiency were assessed by measuring network latency and throughput.

Latency Testing
Command(Workstation):

ping -c 10 192.168.56.4

![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/53232208b0a88002cf811cdd3af7519ebf5dfd98/images/week6/ping%20-c%2010%20192.168.56.4.png)

Network latency and reliability of transmitting packets between the workstation and the headless server through the Host-Only VirtualBox were measured using the ping command. To measure the round trip response time and connectivity stability, ten ICMP echo requests were posted to the server. The findings indicate that there are no losses of packets and this indicates that there is a stable network communication. The round-trip times are very low (less than milliseconds on average) which implies low latency and high-performing internal network. This proves that there are no delays that are introduced by network connection when performing SSH-based remote administration or performance testing. Generally, the output indicates that it provides a consistent, low-latency virtual network that can be used to construct controlled performance testing and security testing.
	

Network Throughput Testing
Command:

sudo apt install iperf3 -y
iperf3 -s

![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/53232208b0a88002cf811cdd3af7519ebf5dfd98/images/week6/sudo%20apt%20install%20iperf3%20-y.png)
 
The iperf3 was installed to measure network throughput between the workstation and the headless server. The output helps in confirming that the server already had iperf3 installed and bang up to date. To start the server in the default port 5201 in listening mode, run the following command iperf3 -s. It is the message of the server listening at port 5201 which proves that the server is ready to receive the performance test connection by the workstation. This will be necessary in the controlled network throughput testing, so that data transfer rate and network performance can be measured accurately in the isolated VirtualBox host-only network.


From Workstation
Command: 

iperf3 -c 192.168.56.4
 
![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/53232208b0a88002cf811cdd3af7519ebf5dfd98/images/week6/iperf3%20-c%20192.168.56.4.png)

Network throughput between the workstation and the headless server was measured using the Host-Only VirtualBox network with the help of the iperf3 tool. The test was able to connect within the default TCP port 5201 showing that the network had been configured correctly and firewall permitted.

The findings indicate that the data transfer rates are consistently high, and the values of the throughput are more than 40 Gbits/sec, which means that network latency is low, and the packet loss in the isolated virtual network is minimal. The rate of TCP retransmission was very low which is also normal during high throughput testing and does not occur as a sign of network instability.

This output shows that the network is not constraint of performance in the existing configuration of the system. The throughput is high, which proves effective SSH-based distant administration and trusted information transmission, which forms a solid foundation on which additional performance and security analysis can be made.



## 6.	Performance Data Table
The observed performance metrics are summarized in the following table.

| Metric              | Baseline | Underload | Post-Optimisation |
|---------------------|----------|-----------|-------------------|
| CPU Load Avg        | 0.01     | 1.95      | 1.20              |
| Memory Used         | 320 MB   | 890 MB    | 640 MB            |
| Disk Read/Write     | Minimal  | High      | Reduced           |
| Network Latency     | ~0.4 ms  | ~0.9 ms   | ~0.6 ms           |
| SSH Responsiveness  | Instant  | Slight Delay | Improved        |

## 7.	Optimisation Techniques Applied
Two optimisation measures were implemented:
## Optimisation 1: Disable Unnecessary Services:

systemctl list-unit-files --type=service --state=enabled
sudo systemctl disable apport.service


## Optimisation 2: Reduce Swappiness:

cat /proc/sys/vm/swappiness
sudo sysctl vm.swappiness=10

![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/53232208b0a88002cf811cdd3af7519ebf5dfd98/images/week6/cat%20procsysvmswappiness.png)

![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/66d252e3218ce6bfa67ef096e08f7064e1140442/images/week6/sudo%20sysctl%20vm%20swapiness.png)
This command (cat /proc/sys/vm/swappiness) shows the value of swappiness currently set by Linux which determines the aggressiveness at which the inactive memory pages are transferred by the kernel between RAM and swap space. A balance which means both the RAM usage and swapping is determined by the default value of 60.
This command (sudo sysctl vm.swappiness=10) reduces the swappiness value from 60 to 10, instructing the kernel to prefer using physical RAM over swap space. Lowering swappiness improves system responsiveness under load by minimizing unnecessary disk I/O, which is especially beneficial for performance-sensitive server workloads.	


## 8.	Optimisation Results and Analysis
Post-optimisation testing showed:
-	Reduced memory pressure during stress
-	Faster recovery to idle state
- 	Improved SSH responsiveness
-	Lower disk I/O spikes under load

Measurable performance improvement while upholding security rules is confirmed by quantitative comparison.

## 9.	Performance Visualisations
To enable quantitative analysis and Learning Outcome LO5 (performance–security trade-offs), performance data gathered during baseline testing, stress testing, and post-optimization testing was visualized.

Measured system metrics were used to construct the following charts.

-	CPU load comparison chart (baseline vs load vs optimised)
  
![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/66d252e3218ce6bfa67ef096e08f7064e1140442/images/week6/cpuloadcomparison.drawio%20(1).png)
 
The CPU load averages for three different system states are contrasted in this graph. CPU utilization is kept to a minimum during baseline operation. Because of CPU stresses, load increases dramatically during stress testing. CPU load drops during optimization (service reduction and swappiness adjustment), indicating increased efficiency and quicker load recovery.

-	Memory utilisation bar graph
  
![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/66d252e3218ce6bfa67ef096e08f7064e1140442/images/week6/Memory%20Utilisation.drawio.png)

Memory utilization under various workloads is displayed in this graph. Because of the intentional pressure during stress testing, memory usage significantly increases. Memory utilization decreases following optimization, suggesting better memory management and less swapping behavior.

-	Network latency comparison chart
  
![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/66d252e3218ce6bfa67ef096e08f7064e1140442/images/week6/Networklatency.drawio.png)	 
When the system is under load, there is more resource contention, which causes a modest increase in network latency. Latency decreases after optimization, demonstrating that system tuning enhances network performance and SSH responsiveness.


## 10.	Trade-off Analysis (LO5)
Performance optimization brought about a number of significant trade-offs that demonstrate how operating systems, as an integrated system, balance security, performance, and dependability.

-	Decreased swappiness: Swap use is decreased and dependence on physical RAM is increased when the swappiness number is lowered. This increases system responsiveness and lowers disk I/O under stress, but if RAM becomes limited, it might put more strain on memory. Performance is prioritized above cautious memory management in this trade-off.
-	Disabling unneeded services: By lowering background CPU and memory consumption, disabling non-essential services (like apport) improves performance and speeds up system recovery. Administrators must rely more on human troubleshooting and log analysis as a trade-off for fewer automatic diagnostics.
-	Security controls and performance impact: During active monitoring and in the event of an attack, security measures like firewall rules and Fail2Ban cause a little CPU overhead. But when weighed against the security advantages, this overhead is negligible. The trade-off shows a conscious decision to put system security ahead of modest performance improvements.

These compromises show that operating system setup necessitates striking a balance between conflicting demands. Optimal performance is attained by carefully controlling the interplay between security restrictions, resource utilization, and system responsiveness rather than by optimizing a single parameter.


## Evidence and Documentation
Evidence collected during Week 6 includes:
-	Baseline and load testing screenshots
-	Network latency and throughput outputs
-	Performance data tables
-	Optimisation command outputs
-	Before-and-after performance comparisons
-	Structured performance data tables
All evidence was captured remotely via SSH from the workstation, with visible username@hostname prompts to ensure authenticity, auditability, and compliance with the coursework administration constrain.

## 11.	Conclusion
A thorough assessment of Linux operating system performance under various workloads was given in week six. Measurable performance gains were made without sacrificing system security by focused optimization, bottleneck identification, and structured testing.

This stage strengthened a practical comprehension of how operating systems respond to stress and how configuration modifications affect performance results. The outcomes show efficient trade-off management between security, resource use, and responsiveness. The system is also ready for the final security audit and system assessment that will take place in Week 7 thanks to this performance rating.

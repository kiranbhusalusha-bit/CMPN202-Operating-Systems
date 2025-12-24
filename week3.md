# Week 3- Process Management, Resource Utilisation and System Behaviour

---

## 1.	Introduction

Week 3's goal is to use command-line tools to analyse system behavior and investigate how the Linux operating system handles programs and system resources. Prior to conducting performance testing or optimization, it is crucial to comprehend process management, CPU scheduling, memory utilization, and system load.

By gathering baseline observations of system behavior under typical operating conditions, this week immediately expands upon the performance testing approach created in Week 2. In accordance with professional system management procedures, all analysis is carried out via secure remote access utilizing the command-line interface (CLI). This week directly supports Learning Outcome LO4 (command-line competency for system monitoring) and Learning Outcome LO5 (understanding operating system behavior and performance trade-offs) by analyzing real-time process behavior, CPU scheduling, memory consumption, and disk I/O using CLI-based tools.

---

## 2.	Process Management in Linux

Linux manages running programs as processes, each with a unique process identifier (PID), priority, and resource allocation. The kernel scheduler is responsible for allocating CPU time among active processes to ensure fairness and efficiency.

Processes may be:
-	Running
-	Sleeping
-	Stopped
-	Zombie (terminated but not yet cleaned up)
  
It is essential to comprehend these stages to identify misbehaving programs and diagnose performance problems.

---

## 3.	CLI-Based Process Observation

Standard Linux command-line tools run remotely on the server via SSH were used to monitor system processes and resource utilisation. There was no usage of graphical tools or a direct server terminal, guaranteeing adherence to the coursework administrative constraint.

### I.	Remote Administration Evidence (Workstation → Server)
Command: `ssh usha@192.168.56.4 "ps aux " `

To confirm that process monitoring was performed remotely in accordance with the coursework administrative constraint, process observation commands were executed from the workstation using SSH to run commands on the server. This confirms that all monitoring was performed without direct server console access or graphical tools.

![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/1af295555cb2674063f6c8023999c7fd8f9c96f5/images/week3/ssh%20usha%40192.168.56.4%20ps%20aux.png)
 

### II.	Viewing Active Processes
Command(Server): `ps aux`

![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/1af295555cb2674063f6c8023999c7fd8f9c96f5/images/week3/ps%20aux.png)
 

To get a comprehensive list of all active processes, the server's command-line interface was used to run the ps aux command. The owning user, process ID (PID), CPU and memory consumption, process state, and the command that initiated the process are all included in this report.Core system services like systemd, sshd, and kernel worker threads (kworker) are visible in the output, indicating that the system is operating normally. According to the curriculum requirement for remote administration, the existence of sshd processes verifies that the server is being accessed remotely using SSH.The server is now running under idle or low-load conditions, as evidenced by the comparatively low CPU and memory use numbers. As a result, this output creates a baseline perspective of process activity and resource usage that will be compared in subsequent rounds of performance testing and optimization.


### III.	Real-Time Process Monitoring
Command(Server): `top`
 
![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/1af295555cb2674063f6c8023999c7fd8f9c96f5/images/week3/top.png)

Real-time resource usage and system processes were tracked using the top command. The result shows the average system load, memory utilization, CPU usage, and running programs. The server is running in idle mode, as evidenced by the low load averages and low CPU use. As is typical for Linux systems, memory usage is still effective, with the majority of available memory being used for caching. Although top offers continuous real-time monitoring, it has a small overhead, hence it was employed for short-term observation rather than long-term monitoring.This observation offers a baseline of typical system behavior that will be compared in subsequent phases of performance testing and optimization.

---

## 4.	CPU Utilisation and Load Analysis

The efficiency with which the processor is being used is shown in CPU utilization. System load averages, which show the typical number of processes awaiting CPU time, are reported by Linux.

### I.	System Load and Uptime
Command (SERVER): `uptime`

![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/1af295555cb2674063f6c8023999c7fd8f9c96f5/images/week3/uptime.png)

The system's running time, active user count, and load averages were shown using the uptime command. With two users registered in and load averages of 0.00, the report demonstrates that the server has been operating for a brief period of time and that there is no discernible CPU demand. The average number of processes waiting for CPU execution for the previous one, five, and fifteen minutes is represented by load averages. The constantly low results verify that there is no scheduling demand and the server is running in idle mode. Before implementing controlled workloads in subsequent performance testing stages, this output offers a reliable baseline for analyzing system behavior.

---

## 5.	Memory Management Observation

Linux uses memory aggressively for caching to improve performance. Monitoring memory usage helps distinguish between genuine memory pressure and normal cache utilisation.

### I.	Memory Usage Overview
Command (SERVER): `free -h`

![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/1af295555cb2674063f6c8023999c7fd8f9c96f5/images/week3/free%20-h.png)
 
The server's current memory use is shown with the free -h command. The output indicates low memory utilization during idle times since the majority of system memory is available. The system is functioning effectively because swap space is specified but not in use. For memory analysis in subsequent performance testing, this offers a baseline.

---

## 6.	Disk and I/O Activity Observation

System responsiveness can be greatly impacted by disk consumption and I/O performance. Potential bottlenecks can be found by monitoring disk activity.

### I.	Disk Space Utilisation
Command (SERVER): `df -h`

![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/1af295555cb2674063f6c8023999c7fd8f9c96f5/images/week3/df-h.png)


Disk space consumption is shown in a human-readable style with the df -h tool. The response indicates that there are no urgent storage limitations and that the root filesystem is utilizing a modest percentage of the available storage. Prior to performance testing, this creates a baseline for disk utilization.

### II.	Disk I/O Statistics
Command (SERVER): `iostat`

![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/1af295555cb2674063f6c8023999c7fd8f9c96f5/images/week3/iostat.png)
 

Note: Before gathering this evidence, sudo apt install sysstat -y was used to install iostat, which is supplied by the sysstat package. Because iostat is not included by default in a simple Ubuntu Server headless installation, this installation was necessary.
The server's disk input/output activity was examined using the iostat command. The system is under minimum disk and processor demand, as evidenced by the extremely low read and write operations and CPU idle time above 99%. This verifies consistent baseline storage performance before any optimization or stress testing.

---

## 7.	Process Control and Scheduling
Linux gives administrators the ability to manage system responsiveness by controlling process priority.

### I.	Process Priority (Nice Values)
Command (SERVER): `ps -o pid, ni , cmd`

![image](https://github.com/kiranbhusalusha-bit/CMPN202-Operating-Systems/blob/1af295555cb2674063f6c8023999c7fd8f9c96f5/images/week3/ps%20-o%20pid%2C%20ni%20%2C%20cmd.png)

Process identifiers and their matching nice values were shown on the server using the ps -o pid,ni,cmd command. The report indicates that the default scheduling priority of 0 is being used by the active processes. This shows that there are no manually changed process priorities and the system is running under typical load levels. This ensures that following performance testing results are not impacted by manual scheduling bias by confirming that no artificial prioritization has been used at this point.

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
By allowing for the intelligent interpretation of system metrics, this knowledge facilitates subsequent performance testing, optimization, and security analysis. By enabling the evaluation of security and performance trade-offs using quantitative data rather than conjecture, this baseline analysis supports LO5 and permits meaningful performance comparison in subsequent weeks.

---

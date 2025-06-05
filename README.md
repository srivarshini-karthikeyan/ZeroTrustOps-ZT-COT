# ZeroTrustOps-ZT-COT

ZeroTrustOps-ZT-COT is a modular and interactive cybersecurity toolkit developed to demonstrate and operationalize Zero Trust security principles. Designed with a focus on real-time security assessment and monitoring, this toolkit is intended for use in research, simulation, and educational environments related to cybersecurity.

This project was developed by Srivarshini K and Poorvaa Sri B as a collaborative effort to build a functional and extensible toolkit capable of supporting both red and blue team activities.

# Project Objective

The objective of ZeroTrustOps-ZT-COT is to integrate multiple cybersecurity tools into a single, unified command-line interface that promotes the principles of Zero Trust Architecture. These principles include continuous verification, least privilege access, real-time monitoring, and breach assumption.

# Features

1. MFA Brute Force Simulator
Simulates brute-force attacks against multi-factor authentication systems for testing purposes.

2. Port Scanner
Identifies open TCP ports on a specified target IP address.

3. Real-time Packet Sniffer
Monitors live network traffic and captures packets for analysis.

4. MAC Address Spoof Detector
Detects suspicious MAC address activity and spoofing attempts.

5. SOC Security Dashboard
Displays simulated real-time security events and metrics for monitoring purposes.

6. Firewall Configuration
Simulates firewall rules and helps in testing configurations.

7. File Integrity Monitor
Detects unauthorized changes in protected files or directories.

8. Honeypot Deployer
Deploys honeypots to attract and analyze attacker behavior.

9. Threat Intelligence Feeds
Presents real-time threat data for awareness and early warning.

10. Log Analysis and Visualization
Parses and visualizes log files to identify potential anomalies or threats.

11. Device Trust Assessment
Evaluates trustworthiness of devices based on posture and behavior.

12. Insider Threat Tracker
Tracks user activities to identify potential insider threats.

13. Hash Reverser
Attempts to reverse hashed values using known public hash databases.

14. Settings and Configuration
Enables users to customize parameters and operational settings.

# Installation

Prerequisites
1. Python 3.7 or higher
2. Operating system with terminal access (Linux or Windows preferred)
3. Required Python packages (install via requirements file)

# Setup Instructions

Clone the repository:
git clone https://github.com/yourusername/ZeroTrustOps-ZT-COT.git
cd ZeroTrustOps-ZT-COT

Install all dependencies:
pip install -r requirements.txt

Launch the toolkit:
python main.py

Usage
Upon execution, the program presents a numbered menu with all available tools. Users can select a tool by entering the corresponding number.
Example:
[+] Enter your choice (0-14):

Each tool includes its own prompts and execution flow. Follow on-screen instructions to use the selected functionality. Press 0 at any time to exit the toolkit.

# Design Philosophy

ZeroTrustOps-ZT-COT follows the core principles of Zero Trust Security:
1. Never trust, always verify
2. Apply least privilege access
3. Continuously monitor and log activity

Assume breach and design accordingly
This toolkit enables users to simulate attacks, monitor system behavior, and enforce zero trust principles in a controlled environment.

# Legal Disclaimer
This software is intended strictly for educational purposes and authorized cybersecurity research. Unauthorized use of this toolkit against systems or networks without proper authorization is prohibited. The authors assume no liability for misuse or damages resulting from the use of this software.

# Authors

This project was developed by:
1. Srivarshini K E0222051 B.Tech CSE – Cyber Security & IoT Sri Ramachandra Faculty of Engineering and Technology, Chennai
2. Poorvaa Sri B E0222033 B.Tech CSE – Cyber Security & IoT Sri Ramachandra Faculty of Engineering and Technology, Chennai
For academic, research, or collaboration inquiries, please contact the authors directly.

# SentinelForge

SentinelForge is a next-generation, multi-modal **Autonomous Endpoint Detection and Response (EDR / IPS)** platform designed to detect and neutralize advanced cyber threats in real-time. Built specifically for Hackfest, it leverages localized AI models, generative SOC intelligence, and low-level system sub-agents to create an active defense shield around monitored workstations.

![Premium Glassmorphism Demo](backend/SentinelForge-Vault/dashboard-demo-placeholder.webp)

## Features

SentinelForge operates using a central **Agentic Manager** that distributes compute across specialized AI and heuristic forensic agents:

*   **Generative SOC Supervisor**: A locally hosted HuggingFace SmolLM-135M Large Language Model that acts as an autonomous SOC analyst, ingesting raw data and determining malicious intent heuristically rather than relying on static rules.
*   **Web Threat Detection**: Actively fetches global TOR exit-node IP lists and matches outbound traffic against known C2 infrastructure and Infostealer callback destinations.
*   **Network Packet Inspection**: Uses raw POSIX sockets and K-Means clustering to sniff packets at the OS kernel level, detecting TCP SYN Floods, UDP Amplification attacks, and anomalous HTTP burst rates.
*   **Memory Integrity Scanning**: Scans live RAM and process execution trees for fileless malware injections, reflective DLL side-loading, and zombie process hollowing techniques.
*   **Live IAM Auditing**: A continuous UNIX tailer that monitors `/var/log/secure` and `auth.log` for failed SSH brute-forcing and unauthorized `sudo` privilege escalation attempts.
*   **Deception Honeypots**: Spawns fake listener ports (e.g., SSH on 8023, RDP on 3389) to trap lateral-moving worms and automated `nmap` reconnaissance scanners.
*   **Ransomware Canary Traps**: Instantly deploys hidden decoy files (`crypto_wallet.dat`, `passwords_backup.txt`) and uses the OS `watchdog` to monitor I/O events, immediately flagging Ransomware mass-encryption behavior.
*   **Physical Hardware Defense (Anti-Rubber Ducky)**: Uses `pynput` to monitor global OS keystroke timing dynamics. It calculates Characters Per Second (CPS) to detect superhuman, hardware-injected BadUSB scripts (e.g., Flipper Zero payloads).

## How to Use

Using the unified startup script, you can boot both the FastAPI backend and Next.js frontend concurrently to rapidly launch the platform.

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/shredzwho/Data-dynamos-hackfest26.git
    cd SentinelForge
    ```

2.  **Setup Backend Virtual Environment**
    ```bash
    cd backend
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    cd ..
    ```

3.  **Setup Frontend Dependencies**
    ```bash
    cd frontend
    npm install
    cd ..
    ```

4.  **Boot the Platform**
    ```bash
    chmod +x run.sh
    ./run.sh
    ```
    This script will automatically clear zombie ports, boot the AI Engine to `http://localhost:8000`, construct the Ransomware traps, and launch the React Intelligence Dashboard to `http://localhost:3000`.

### Interaction & Testing Guide
*   **Target Isolation**: Click on any Node tile in the dashboard grid. Click **"ISOLATE HOST"** to block all simulated subnet traffic, or **"AUTONOMOUS RESOLUTION"** to let the AI try to clean it.
*   **Run a Security Audit**: Click the **"Run Deep Audit"** shield button on the right-side panel to sequentially wake up agents for a manual forensic OS sweep.
*   **Simulate Ransomware**: Run `echo "hackfest_ransomware_payload" >> backend/SentinelForge-Vault/crypto_wallet.dat` in a terminal to trigger the file integrity AI.
*   **Simulate BadUSB**: Mash your keyboard as fast as humanly possible for 3 seconds in any text application to trigger the keystroke physical defense anomaly.

## Uses

SentinelForge is built for a variety of critical, real-world cybersecurity applications:

*   **Enterprise EDR**: Active endpoint defense against lateral movement, fileless malware, and credential dumping.
*   **Zero-Trust Networking**: Continuous verification of running processes and immediate network isolation of compromised or infected nodes.
*   **Automated Incident Response**: Reducing SOC analyst fatigue by automatically quarantining threats and writing autonomous mitigation action reports.
*   **Ransomware Mitigation**: Early warning detection of mass-file encryption to stop Ransomware sweeps before they lock critical volumes.
*   **Physical Breach Prevention**: Protecting workstations from malicious USB drops and automated hardware injection attacks in insecure physical environments.

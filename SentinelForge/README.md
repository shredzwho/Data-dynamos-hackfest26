# SentinelForge

SentinelForge is a next-generation, multi-modal **Autonomous Endpoint Detection and Response (EDR / IPS)** platform designed to detect and neutralize advanced cyber threats in real-time. Built specifically for Hackfest, it leverages localized AI models, generative SOC intelligence, and low-level system sub-agents to create an active defense shield around monitored workstations.

![Premium Glassmorphism Demo](backend/SentinelForge-Vault/dashboard-demo-placeholder.webp)

## Core Capabilities

SentinelForge is powered by a central **Agentic Manager** that utilizes the Actor Model pattern to distribute compute across 8 distinct, asynchronous forensic agents. 

### 1. Generative SOC Supervisor (LLM)
Instead of relying purely on static regex or hardcoded Yara rules, SentinelForge uses a quantized **HuggingFaceTB/SmolLM-135M** Large Language Model running locally over PyTorch. The LLM acts as an autonomous Security Operations Center (SOC) analyst, ingesting raw data from the 7 sub-agents and determining malicious intent heuristically.

### 2. Multi-Vector Threat Sub-Agents
The platform actively hunts for threats across all layers of the OSI model using specialized Python daemons:
*   **WebModel (Layer 7)**: Actively fetches global TOR exit-node IP lists and matches outbound traffic against known C2 infrastructure and Infostealer callback destinations.
*   **NetworkModel (Layer 3/4)**: Uses raw POSIX sockets and `scapy` to sniff packets at the OS kernel level, utilizing a K-Means clustering algorithm to detect TCP SYN Floods, UDP Amplification attacks, and anomalous HTTP burst rates (DDoS).
*   **MemoryModel (Ring 0/3)**: Scans live RAM and process execution trees for fileless malware injections, reflective DLL side-loading, and zombie process hollowing techniques.
*   **LogModel (IAM Auditing)**: Acts as a continuous UNIX tailer using `aiofiles`. It monitors `/var/log/secure` and `/var/log/auth.log` for failed SSH brute-forcing and unauthorized `sudo` privilege escalation attempts, piping the strings to the local LLM for sentiment analysis.
*   **HoneypotAgent (Deception)**: Spawns fake listener ports (e.g., SSH on 8023, RDP on 3389) to trap lateral-moving worms and automated `nmap` reconnaissance scanners.

### 3. Physical & Ransomware Defense
*   **IntegrityModel (Canary Traps)**: Instantly deploys a hidden `SentinelForge-Vault` directory containing decoy files (`crypto_wallet.dat`, `passwords_backup.txt`). It uses the OS `watchdog` to monitor I/O events, immediately flagging Ransomware mass-encryption behavior.
*   **KeystrokeModel (Anti-Rubber Ducky)**: Uses `pynput` to monitor global OS keystroke timing dynamics. It calculates the Characters Per Second (CPS) in a sliding window to detect superhuman, hardware-injected BadUSB scripts (e.g., Flipper Zero payloads).

## Software Architecture

*   **Frontend**: React (Next.js) with a custom Cinematic Cyber-Glassmorphism UI, Framer-Motion for 60fps animations, Recharts for realtime dashboard telemetry, and Socket.io-client.
*   **Backend**: Python (FastAPI/Uvicorn) with full Native Asynchronous I/O handling, PyTorch for Machine Learning, and Socket.io for duplex data pushing.
*   **Database**: SQLite with SQLAlchemy ORM (alembic configurations).

## Installation & Quickstart

Using the unified startup script, you can boot both the FastAPI backend and Next.js frontend concurrently.

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

## Interactive Dashboard Usage

*   **Real-time Telemetry**: The top KPI row provides live sparkline visual tracking for CPU Load, Network I/O, Monitored Endpoints, and Active Threats.
*   **Active Workstation Grid**: Displays all connected servers and workstations. Healthy nodes glow Green. If compromised, the node card will fracture, pulse Red, and isolate itself.
*   **Target Isolation**: Clicking any node tile brings up an action panel. You can manually fire an Isolation hook to disconnect the backend subnet, or trigger the SOC AI to attempt an autonomous resolution.
*   **Granular Agent Control**: The right sidebar allows the IT Admin to hot-swap the internal Threat Agents. If CPU load is spiking, you can disable the heavy `MemoryModel` engine while keeping `NetworkModel` online without rebooting the server.
*   **Generative Reporting**: You can run Deep, Stealth, or Smart Sweeps. Following an audit, the backend generates an interactive Threat Report and outputs it directly as a downloadable `.xlsx` Excel spreadsheet.

## License
Created internally for Hackfest. All Rights Reserved.

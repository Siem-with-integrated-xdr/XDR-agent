# XDR Agent for SIEM Server

This is a modular and high-performance Windows-based solution. Designed for real-time system visibility, proactive monitoring, and secure data transmission, this agent suite transforms raw system activities into rich, structured telemetry for deep analysis, threat detection, and response.

----------

## Table of Contents

- [Overview](#-overview)
- [Project Structure](#-project-structure)
  - [Top-Level Directory](#top-level-directory)
  - [lib/ Folder](#lib-folder)
- [Key Features](#-key-features)
- [Module Breakdown](#-module-breakdown)
- [Dependencies](#-dependencies)
- [Building the Project](#-building-the-project)
- [How to Run](#-how-to-run)
- [Logging](#-logging)
- [Minimum System Requirements](#-minimum-system-requirements)
- [License](#-license)
- [Third-Party Licenses](#-third-party-licenses)
- [Contact](#-contact)
- [Acknowledgments](#-acknowledgments)

----------

## 🔹 Overview

Built with scalability and fault tolerance in mind, this suite captures a wide spectrum of system telemetry:

- **Windows Event Logs** from Security, Application, and System channels
- **File Integrity Checks** using SHA-256 on sensitive system paths
- **File System Scanner** for real-time scanning of (created/modifed/downloaded) files
- **Network Traffic Sniffing** using WinPcap/Npcap
- **Process Spawning Events** monitored via WMI
- **System Health Metrics** including CPU, RAM, Disk, and uptime
- **Structured JSON Output** through cJSON
- **Command Execution** triggered by remote JSON actions
- **Modular Supervision** via a parent manager process
- **Secure & Compressed Transmission** using ZeroMQ, OpenSSL, and Zstd

----------

## 🔹 Project Structure

### Top-Level Directory

```
.
├── .git/                  # Git version control
├── lib/                   # SDKs and third-party libraries
├── *.exe                  # Compiled modules (one per feature)
├── *.c                    # C source code files
├── *.log                  # Runtime logs per module
├── Makefile               # Build instructions
├── config.xml             # Kafka & encryption config file
└── readme.md              # This documentation
```

### lib/ Folder

```
lib/
├── cJSON/                # JSON object building
├── librdkafka/           # Kafka communication
├── libxml2-2.9.14/       # XML parsing
├── libzmq/               # ZeroMQ messaging
├── npcap-sdk-1.15/       # Network packet capture
├── openssl-minimal/      # Encryption
└── zstd/                 # Compression
```

----------

## 🔹 Key Features

- **Modular Architecture** — Each feature operates independently as a background service.
- **JSON-Based Telemetry** — Outputs structured and filterable logs.
- **ZeroMQ Messaging** — Lightweight and fast communication.
- **Fault Recovery** — Automatic module restart by parent process.
- **Custom Logging** — Timestamped logs per module.
- **Kafka Integration** — Secure and scalable data delivery.
- **Real-Time Responsiveness** — Event-driven design using native Windows APIs.
- **Remote Action Execution** — The `action` module receives commands via ZeroMQ and executes them safely.

----------

## 🔹 Module Breakdown

| Module Name             | File                          | Functionality                                      |
|-------------------------|-------------------------------|----------------------------------------------------|
| Compressor              | `compressor.c`                | Compresses JSON messages using Zstd                |
| Encryptor               | `encryptor.c`                 | Encrypts and sends messages to Kafka               |
| Events Data Collector   | `events_data_collector.c`     | Collects Windows event logs                        |
| File Integrity Checker  | `file_integrity.c`            | Hashes and checks sensitive files                  |
| File Scanner            | `file_scanner.c`              | Scans files for malicious patterns                 |
| Network Data Collector  | `network_data_collector.c`    | Captures and formats packet data                   |
| Process Monitor         | `processes_data_collector.c`  | Tracks new processes via WMI                       |
| System Health Monitor   | `system_health.c`             | Gathers CPU, RAM, Disk, and uptime metrics         |
| Parent Process Manager  | `parent.c`                    | Launches, monitors, and recovers all modules       |
| Action Executor         | `action.c`                    | Executes predefined commands sent via ZeroMQ       |

----------

## 🔹 Dependencies

Ensure these are installed or their `.dll` files are placed in the project root or system `PATH`:

- **ZeroMQ** (`libzmq.dll`)
- **OpenSSL** (`libcrypto-3-x64.dll`, `libssl-3-x64.dll`)
- **Zstandard** (`libzstd.dll`)
- **cJSON** (`cJSON.dll`)
- **libxml2** (`libxml2.dll`)
- **librdkafka** (`librdkafka.dll`)
- **WinPcap/Npcap** (`wpcap.dll`, `Packet.dll`)

----------

## 🔹 Building the Project

### Requirements:

- C compiler (e.g., GCC via MinGW or Visual Studio)
- Environment variables or Makefile paths to `lib/` and `include/`

### Build Steps:

```bash
make all
```

Or compile manually using your IDE by linking necessary libraries.

----------

## 🔹 How to Run

1. Ensure all dependencies (DLLs) are in place.
2. Launch `subprocess_manager.exe` — it orchestrates all child modules.
3. Each module sends data to `tcp://localhost:5555`.
4. `action.exe` listens on `tcp://localhost:5557` for remote execution commands.
5. Configure receivers, log analyzers, or forwarders to consume the JSON data.
6. Adjust Kafka settings in `config.xml` if needed.

----------

## 🔹 Logging

Each module writes timestamped logs to a dedicated file:

- `compressor.log`
- `encryptor.log`
- `events.log`
- `file_integrity.log`
- `file_scanner.log`
- `network_log.log`
- `process_log.log`
- `system_health.log`
- `parent.log`
- `action.log`

----------

## 🔹 Minimum System Requirements

| Resource | Minimum Value        |
|----------|----------------------|
| OS       | Windows 10 / Server  |
| CPU      | 4-core processor     |
| Memory   | 4 GB RAM             |
| Disk     | 10 GB free           |
| Network  | Reliable TCP connection |

----------

## 🔹 License

This project is licensed under the **MIT License** for the code written in this repository. See the [LICENSE](LICENSE) file for details.

> ⚠️ Note: This license applies only to **original code** in this repository. The project uses third-party libraries under their own licenses. See below.

----------

## 🔹 Third-Party Licenses

| Library       | License                                 | Notes                                                                  |
|---------------|------------------------------------------|------------------------------------------------------------------------|
| **ZeroMQ**     | Mozilla Public License 2.0 (MPL-2.0)    | Compatible with MIT                                                   |
| **OpenSSL**    | Apache License 2.0 / OpenSSL License     | Attribution required; incompatible with GPLv2                         |
| **Zstd**       | BSD 3-Clause                             | Compatible with MIT                                                   |
| **libxml2**    | MIT License                              | Fully compatible                                                      |
| **cJSON**      | MIT License                              | Fully compatible                                                      |
| **librdkafka** | BSD 2-Clause                             | Compatible                                                            |
| **Npcap**      | Proprietary License                      | Must be installed separately; not redistributable without permission  |

> ⚠️ If you distribute binaries, make sure you **do not bundle Npcap DLLs** unless you have a license. Users should install [Npcap](https://npcap.com/) themselves.

----------

## 🔹 Contact

For inquiries, feedback, or contributions:

- **Name:** Your Name
- **Email:** your.email@example.com
- **GitHub:** [https://github.com/yourusername](https://github.com/yourusername)

----------

## 🔹 Acknowledgments

Special thanks to the developers of:

- **ZeroMQ**
- **OpenSSL**
- **Zstd**
- **librdkafka**
- **libxml2**
- **cJSON**
- **WinPcap/Npcap**

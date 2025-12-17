# Brainless Framework

**Brainless** is a modular penetration testing and security research framework inspired by Metasploit, designed **exclusively for Debian-based Linux distributions** (Debian, Ubuntu, Kali, Parrot, Linux Mint).

> ⚠️ **Legal Notice**: Brainless is intended **ONLY** for authorized security testing, research, and educational purposes. Unauthorized use against systems you do not own or have permission to test is illegal.

---

## Table of Contents

1. Introduction
2. Supported Operating Systems
3. Architecture Overview
4. Installation Guide
5. Directory Structure
6. Core Components
7. Module Types
8. Payload System
9. Exploit Development Guide
10. Auxiliary Modules
11. Post-Exploitation Modules
12. Listener & Handler
13. Command Line Interface (CLI)
14. Configuration Files
15. Database Integration
16. Logging & Reporting
17. Plugin System
18. Security & Sandboxing
19. Updating Brainless
20. Troubleshooting
21. Roadmap
22. Contribution Guidelines
23. License

---

## 1. Introduction

Brainless is a **command-line-driven penetration testing framework** that allows security professionals to:
- Develop and execute exploits
- Generate and manage payloads
- Perform reconnaissance and auxiliary tasks
- Automate post-exploitation activities

Brainless focuses on:
- Simplicity
- Clean module design
- Debian-only dependency stability

---

## 2. Supported Operating Systems

Brainless officially supports:
- Debian 11 / 12
- Ubuntu 20.04 / 22.04 / 24.04
- Kali Linux (Rolling)
- Parrot OS
- Linux Mint (Debian/Ubuntu base)

❌ **Not Supported**:
- Arch Linux
- Fedora / RHEL
- Windows
- macOS

---

## 3. Architecture Overview

Brainless uses a **modular architecture**:

```
User CLI
   ↓
Core Engine
   ↓
Module Loader
   ↓
Exploit | Payload | Auxiliary | Post Modules
   ↓
Target System
```

Key Design Principles:
- Loose coupling between modules
- Python-based core engine
- Shellcode & binary payload support

---

## 4. Installation Guide

### 4.1 Requirements

```
Python >= 3.10
pip
git
postgresql (optional but recommended)
```

### 4.2 Install Dependencies (Debian-based)

```bash
sudo apt update
sudo apt install -y python3 python3-pip git build-essential libssl-dev
```

### 4.3 Clone Brainless

```bash
git clone https://github.com/your-org/brainless.git
cd brainless
```

### 4.4 Install Python Dependencies

```bash
pip3 install -r requirements.txt
```

### 4.5 Start Brainless

```bash
sudo python3 brainless.py
```

---

## 5. Directory Structure

```
brainless/
├── brainless.py
├── core/
│   ├── engine.py
│   ├── loader.py
│   ├── session.py
│   └── database.py
├── modules/
│   ├── exploits/
│   ├── payloads/
│   ├── auxiliary/
│   └── post/
├── listeners/
├── plugins/
├── config/
│   └── brainless.conf
├── logs/
├── reports/
└── requirements.txt
```

---

## 6. Core Components

### 6.1 Core Engine
Handles:
- Command parsing
- Session control
- Module execution

### 6.2 Module Loader
- Dynamically loads Python modules
- Validates module metadata

---

## 7. Module Types

### 7.1 Exploit Modules

Used to exploit vulnerabilities.

Example:
```
modules/exploits/linux/ssh/weak_ssh.py
```

Required Fields:
- NAME
- DESCRIPTION
- AUTHOR
- TARGET
- RUN()

---

## 8. Payload System

Payloads define **what happens after exploitation**.

### Payload Types:
- Reverse Shell
- Bind Shell
- Meterpreter-like Session

Example Payload Options:
- LHOST
- LPORT
- ENCODER

---

## 9. Exploit Development Guide

Minimal exploit template:

```python
class Exploit:
    NAME = "Sample Exploit"
    DESCRIPTION = "Test exploit"
    AUTHOR = "Brainless Team"

    def run(self):
        print("Running exploit...")
```

---

## 10. Auxiliary Modules

Auxiliary modules do **not exploit systems**.

Examples:
- Port scanners
- Brute-force tools
- Service enumeration

---

## 11. Post-Exploitation Modules

Executed **after successful access**.

Examples:
- Privilege escalation checks
- Credential harvesting
- Persistence

---

## 12. Listener & Handler

The listener waits for payload connections.

Supported:
- TCP
- HTTP/HTTPS
- DNS (experimental)

---

## 13. Command Line Interface (CLI)

### Basic Commands

```
help
use exploit/linux/ssh/weak_ssh
set RHOST 192.168.1.10
set PAYLOAD reverse_tcp
run
sessions
```

---

## 14. Configuration Files

Location:
```
config/brainless.conf
```

Includes:
- Default ports
- Database settings
- Logging level

---

## 15. Database Integration

Optional PostgreSQL integration.

Stores:
- Hosts
- Services
- Credentials
- Sessions

---

## 16. Logging & Reporting

Logs stored in:
```
logs/
```

Reports:
- JSON
- HTML
- PDF (planned)

---

## 17. Plugin System

Plugins extend core functionality without modifying engine code.

Example Plugins:
- AI exploit suggester
- Auto-enumerator

---

## 18. Security & Sandboxing

- Modules run in restricted context
- Root privileges required only when necessary
- Strict dependency control (Debian only)

---

## 19. Updating Brainless

```bash
git pull
pip3 install -r requirements.txt --upgrade
```

---

## 20. Troubleshooting

Common Issues:
- Missing dependencies
- Port conflicts
- Permission denied (run with sudo)

---

## 21. Roadmap

- GUI Dashboard
- AI-based exploit matching
- Windows payloads (Linux-built)
- Encrypted C2 channels

---

## 22. Contribution Guidelines

- Follow PEP8
- Write documentation
- Test on Debian-based OS only

---

## 23. License

Brainless Framework is released under the **GPLv3 License**.

---

\*\*Author:\*\* Brainless Security Team
\*\*Version:\*\* 0.1 (Alpha)

---

# Appendix A: AI Development Prompt for Brainless Linux Tool

## Master AI Prompt (Use with ChatGPT / Gemini / Claude)

**Role:**
You are a **Senior Linux Security Engineer & Python Framework Architect** with deep experience in penetration testing frameworks (Metasploit-like tools), Debian-based Linux internals, networking, exploit development, and secure software design.

**Objective:**
Design and implement a **Debian-based Linux–only security framework** named **Brainless**, inspired by Metasploit but simpler, modular, and cleanly architected.

The framework must be:
- CLI-based
- Written primarily in **Python 3.10+**
- Modular (exploits, payloads, auxiliary, post)
- Secure, documented, and extensible
- Legal-use focused (authorized testing only)

---

## Scope & Constraints

- Supported OS: **Debian, Ubuntu, Kali, Parrot only**
- No Windows/macOS support
- No GUI initially (CLI first)
- No hardcoded credentials
- Minimal external dependencies
- PostgreSQL optional

---

## Required Deliverables

1. **Project Architecture**
   - Core engine
   - Module loader
   - Session manager
   - Listener/handler

2. **Directory Structure**
   - Clear separation of core, modules, config, logs

3. **CLI Interface**
   - Commands: help, use, set, show, run, sessions, exit
   - Interactive shell behavior

4. **Module System**
   - Python-based modules
   - Mandatory metadata (NAME, DESCRIPTION, AUTHOR)
   - Standard `run()` entry point

5. **Payload Framework**
   - Reverse TCP shell
   - Bind shell
   - Handler integration

6. **Security Practices**
   - Avoid unsafe system calls
   - Validate user input
   - Restrict root usage

7. **Documentation**
   - Inline code comments
   - README-style explanations

---

## Development Instructions

- Start by generating the **core engine skeleton**
- Then implement the **interactive CLI loop**
- Then implement the **module loader**
- Then create **one example exploit module**
- Then create **one example payload module**
- Ensure everything runs on Debian-based Linux

---

## Coding Rules

- Follow PEP8
- Use clear class-based design
- No obfuscated code
- Explain complex logic
- Use logging instead of print where possible

---

## Testing Instructions

- Test on Kali Linux or Ubuntu LTS
- Handle missing dependencies gracefully
- Provide meaningful error messages

---

## Output Format

When generating code:
- Show file name
- Then show full code
- Then explain how it works

---

## Legal Reminder

This tool is strictly for **ethical hacking, education, and authorized security testing**. Do NOT include real-world zero-day exploits or instructions for illegal usage.

---

## Final Instruction

Proceed **step by step**, do not jump ahead, and confirm functionality at each stage before moving to the next component.


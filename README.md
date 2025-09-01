# clusterapp_script_installer
Automated Bash installer for a full-stack cluster application.   Includes environment checks, dependency installation, database setup, and application configuration with both online and offline modes.

# clusterapp_installer

`clusterapp_installer` is a Bash script that automates the installation and configuration of a full-stack cluster application.  
It is designed for reproducibility and portability, supporting multiple Linux distributions and both online and offline installation modes.

✨ Features
- System requirement checks (RAM, CPU, Disk)
- Automatic OS detection (Ubuntu 18/20/22, CentOS/RHEL/Rocky 7–10)
- Installation of dependencies: OpenSSL, Python 3.10, PostgreSQL 15
- Optional Oracle Instant Client support (manual download required)
- Backend, frontend, and tasks setup
- Logging to `clusterapp_setup.log` with interactive progress indicators (spinner & progress bar)
- Supports both **online** and **offline** package installation

⚙️Requirements

Root privileges

At least 4 GB RAM, 2 CPU cores, 30 GB free disk space

Supported operating systems:

Ubuntu 18.04, 20.04, 22.04

CentOS/RHEL/Rocky 7, 8, 9, 10

📦 Installation Modes

Online installation – downloads required packages from official repositories.

Offline installation – installs from local .rpm or .deb files if available.

⚠️ Notes

Proprietary software (such as Oracle Instant Client) is not included.
Follow vendor instructions to download and place the files in the correct directory before running the script.

The script is intended as a demonstration of automation and DevOps skills.

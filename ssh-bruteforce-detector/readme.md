# SSH Brute Force Detector

A Python-based tool for monitoring and mitigating SSH brute force attempts in real time.  
This detector uses `tshark` to capture SSH traffic, identifies suspicious behavior, and blocks offending IPs with `iptables`.

---

## Features

- Real-time monitoring of SSH login attempts  
- Detection of repeated failed authentications  
- Automatic IP blocking using firewall rules  
- Configurable thresholds and block durations  
- Logging of operational events and security events  
- Optional whitelist for trusted IPs/networks  
- Graceful shutdown and automatic unblocking after timeout  
- Test mode for safe experimentation (no blocking applied)  

---

## Requirements

- **Operating System:** Linux (tested on Kali Linux)  
- **Dependencies:**  
  - Python 3.8+  
  - `tshark` (Wireshark CLI)  
  - `iptables`  
- **Python packages:** install via `pip install -r requirements.txt` (if any required)

---

## Installation

Clone the repository and run the setup script on the victim machine:

```bash
git clone https://github.com/cybersagnik/Network-Security/
cd Network-Security/ssh-bruteforce-detector
chmod +x setup_and_test.sh
./setup_and_test.sh
```
### The setup script will:

- Install required packages (Python modules, tshark if missing)

- Verify that iptables and tshark are functional

- Open SSH port if needed

- Create a testuser with a pass for ssh testing

- ⚠️ Run setup with root privileges (sudo) to ensure firewall rules can be applied.
  
---

## Configuration :

| Argument               | Description                                    | Default |
| ---------------------- | ---------------------------------------------- | ------- |
| `-i, --interface`      | Network interface to monitor                   | `any`   |
| `-t, --threshold`      | Number of failed attempts before blocking      | `5`     |
| `-w, --window`         | Time window in seconds to count attempts       | `300`   |
| `-b, --block-duration` | Duration to block IPs in seconds               | `3600`  |
| `-v, --verbose`        | Enable verbose logging                         | `False` |
| `--check`              | Check system requirements and exit             | `False` |
| `--test-mode`          | Run detector in test mode (no actual blocking) | `False` |

### Example :
```bash
sudo python3 ssh_detector.py -i eth0 -t 3 -w 180 -b 7200 -v
```
---

## Usage

### Run the detector on the victim machine :

```bash
sudo python3 ssh_detector.py
```
- Monitors SSH connections on all interfaces by default.

- Prints status periodically, showing attempts, blocked IPs, and uptime.

- Press CTRL+C to gracefully stop.

  
### Launch bruteforce from attacker machine 

```bash
hydra -l testuser -P /usr/share/wordlists/rockyou.txt ssh://<VM-IP> -t 4 -V -f
```
- Detector should log attacks and block the attacking IP automatically.
  
---

### Proof of Concept
![POC Image](https://github.com/user-attachments/assets/e95a842e-4be1-4dfa-9073-6979632fea2d)

---

## Whitelist

- Trusted IPs/networks can be added to whitelist.txt.

- Supports single IPs (192.168.0.10) or CIDR ranges (192.168.0.0/24).

- Default whitelist includes localhost (127.0.0.1) and IPv6 loopback (::1).
  
---

## Logs
### Log File	Purpose
- #### ssh_detector.log	Detailed operational logs with timestamps and debug info
- #### ssh_attacks.log	Security events including detected brute force attempts and blocked IPs

---

## Restoring System State

- To remove all firewall rules added by the detector:

```bash
chmod +x restore.sh
./restore.sh
```
- Restores system to previous state before testing.

- Recommended after testing in a VM.

---

## Troubleshooting

- Could not get lock /var/lib/apt – another package manager is running; wait or kill it.

- tshark not found – install with sudo apt-get install tshark.

- Permission issues – run with sudo to allow firewall changes.

- Interface not found – list interfaces with tshark -D and select the correct one.

---

## Disclaimer

- This tool is intended for educational and research purposes only.
- Do not deploy or test against unauthorized systems.
- The author assumes no responsibility for misuse or damage.

---

## Author

- Name: Sagnik Ray

- GitHub: cybersagnik

- Contact: raysagnik86@gmail.com

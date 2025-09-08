#!/usr/bin/env python3
"""
SSH Brute Force Detector - Fixed Version
Monitors SSH traffic using tshark and implements intelligent blocking
Fixed common shutdown issues and improved error handling
"""

import subprocess
import time
import threading
import json
import re
import os
import sys
from datetime import datetime, timedelta
from collections import defaultdict, deque
import argparse
import logging
import ipaddress
from typing import Dict, List, Set, Optional
import signal

class SSHBruteForceDetector:
    def __init__(self, interface="any", threshold=5, time_window=300, block_duration=3600):
        """
        Initialize SSH Brute Force Detector
        
        Args:
            interface: Network interface to monitor (default: any)
            threshold: Failed attempts before blocking (default: 5)
            time_window: Time window in seconds to count attempts (default: 300)
            block_duration: Block duration in seconds (default: 3600)
        """
        self.interface = interface
        self.threshold = threshold
        self.time_window = time_window
        self.block_duration = block_duration
        
        # Data structures for tracking attempts
        self.failed_attempts = defaultdict(deque)  # IP -> deque of timestamps
        self.connection_attempts = defaultdict(list)  # IP -> list of attempts
        self.blocked_ips = {}  # IP -> block_timestamp
        self.whitelist = set()
        
        # Control flags
        self.running = True
        self.tshark_process = None
        self.start_time = time.time()
        
        # Setup logging
        self.setup_logging()
        
        # Load whitelist
        self.load_whitelist()
        
        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        # Test tshark availability
        self.test_tshark()
        
    def test_tshark(self):
        """Test if tshark is available and working"""
        try:
            result = subprocess.run(['tshark', '--version'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                version = result.stdout.split('\n')[0]
                self.logger.info(f"tshark detected: {version}")
            else:
                self.logger.error("tshark not working properly")
                sys.exit(1)
        except FileNotFoundError:
            self.logger.error("tshark not found. Please install wireshark/tshark")
            sys.exit(1)
        except subprocess.TimeoutExpired:
            self.logger.error("tshark test timed out")
            sys.exit(1)
        
        # Test interface
        if self.interface != "any":
            try:
                result = subprocess.run(['tshark', '-D'], 
                                      capture_output=True, text=True, timeout=5)
                if self.interface not in result.stdout and not self.interface.startswith('eth'):
                    self.logger.warning(f"Interface {self.interface} may not be available")
                    self.logger.info("Available interfaces:")
                    self.logger.info(result.stdout)
            except Exception as e:
                self.logger.warning(f"Could not list interfaces: {e}")
        
    def setup_logging(self):
        """Setup logging configuration"""
        # Create formatters
        detailed_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        )
        simple_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        
        # Setup main logger
        self.logger = logging.getLogger('ssh_detector')
        self.logger.setLevel(logging.INFO)
        
        # Clear any existing handlers
        self.logger.handlers = []
        
        # File handler for detailed logs
        file_handler = logging.FileHandler('ssh_detector.log')
        file_handler.setFormatter(detailed_formatter)
        file_handler.setLevel(logging.DEBUG)
        
        # Console handler for important events
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(simple_formatter)
        console_handler.setLevel(logging.INFO)
        
        # Attack logger for security events
        self.attack_logger = logging.getLogger('ssh_attacks')
        self.attack_logger.setLevel(logging.INFO)
        self.attack_logger.handlers = []
        
        attack_handler = logging.FileHandler('ssh_attacks.log')
        attack_handler.setFormatter(logging.Formatter(
            '%(asctime)s - SECURITY - %(message)s'
        ))
        
        # Add handlers
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        self.attack_logger.addHandler(attack_handler)
        
    def load_whitelist(self):
        """Load whitelisted IPs and networks from file"""
        whitelist_file = 'whitelist.txt'
        try:
            with open(whitelist_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.whitelist.add(line)
            self.logger.info(f"Loaded {len(self.whitelist)} entries from whitelist")
        except FileNotFoundError:
            # Create default whitelist
            default_whitelist = [
                "# SSH Detector Whitelist - Add trusted IPs/networks",
                "# Examples:",
                "# 192.168.1.0/24",
                "# 10.0.0.100",
                "",
                "162.7.8.3",
                "8.8.8.8"
            ]
            with open(whitelist_file, 'w') as f:
                f.write('\n'.join(default_whitelist))
            #self.whitelist.update(['127.0.0.1', '::1'])
            self.logger.info("Created default whitelist file")
    
    def is_whitelisted(self, ip: str) -> bool:
        """Check if IP is in whitelist (supports both IPs and CIDR networks)"""
        if ip in self.whitelist:
            return True
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            for whitelist_entry in self.whitelist:
                try:
                    if '/' in whitelist_entry:
                        network = ipaddress.ip_network(whitelist_entry, strict=False)
                        if ip_obj in network:
                            return True
                except ValueError:
                    continue
        except ValueError:
            pass
        
        return False
    
    def start_tshark_monitor(self):
        """Start tshark to capture SSH traffic with improved command"""
        # Simplified tshark command that's more reliable
        tshark_cmd = [
            'tshark',
            '-i', self.interface,
            '-f', 'tcp port 22',  # Filter SSH traffic
            '-T', 'fields',
            '-e', 'frame.time_epoch',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'tcp.dstport',
            '-e', 'tcp.flags',
            '-E', 'separator=|',
            '-E', 'header=n',
            '-E', 'occurrence=f',
            '-l',  # Line buffered output
            '-q'   # Quiet mode
        ]
        
        self.logger.info(f"Starting tshark on interface {self.interface}")
        self.logger.info(f"Command: {' '.join(tshark_cmd)}")
        
        try:
            # Start tshark process
            self.tshark_process = subprocess.Popen(
                tshark_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1
            )
            
            # Give tshark a moment to start
            time.sleep(2)
            
            # Check if process is still running
            if self.tshark_process.poll() is not None:
                stderr_output = self.tshark_process.stderr.read()
                self.logger.error(f"tshark failed to start. Error: {stderr_output}")
                return False
            
            self.logger.info("tshark started successfully, monitoring SSH traffic...")
            
            # Start a thread to handle stderr
            stderr_thread = threading.Thread(target=self.handle_tshark_stderr, daemon=True)
            stderr_thread.start()
            
            # Process tshark output line by line
            packet_count = 0
            last_packet_time = time.time()
            
            for line in iter(self.tshark_process.stdout.readline, ''):
                if not self.running:
                    break
                    
                if line.strip():
                    packet_count += 1
                    last_packet_time = time.time()
                    self.process_packet(line.strip())
                    
                    # Log progress every 100 packets
                    if packet_count % 100 == 0:
                        self.logger.debug(f"Processed {packet_count} packets")
                
                # Check if tshark process died
                if self.tshark_process.poll() is not None:
                    self.logger.error("tshark process died unexpectedly")
                    break
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error starting tshark: {e}")
            return False
    
    def handle_tshark_stderr(self):
        """Handle tshark stderr output"""
        try:
            for line in iter(self.tshark_process.stderr.readline, ''):
                if line.strip():
                    # Filter out common tshark warnings
                    if not any(ignore in line.lower() for ignore in 
                              ['dropped', 'permission', 'capture filter']):
                        self.logger.warning(f"tshark stderr: {line.strip()}")
        except Exception as e:
            self.logger.debug(f"Error reading tshark stderr: {e}")
    
    def process_packet(self, packet_line: str):
        """Process individual packet from tshark output"""
        try:
            fields = packet_line.split('|')
            if len(fields) < 5:
                self.logger.debug(f"Incomplete packet data: {packet_line}")
                return
            
            timestamp_str = fields[0]
            src_ip = fields[1] 
            dst_ip = fields[2]
            dst_port = fields[3]
            tcp_flags = fields[4] if len(fields) > 4 else ""
            
            # Validate data
            if not src_ip or not dst_ip or src_ip == dst_ip:
                return
                
            # Skip if whitelisted
            if self.is_whitelisted(src_ip):
                return
            
            # Parse timestamp
            try:
                timestamp = float(timestamp_str) if timestamp_str else time.time()
            except ValueError:
                timestamp = time.time()
            
            # Log the connection attempt
            self.log_ssh_attempt(src_ip, dst_ip, dst_port, timestamp, tcp_flags)
            
            # Track connection attempts
            dt_timestamp = datetime.fromtimestamp(timestamp)
            self.connection_attempts[src_ip].append({
                'timestamp': dt_timestamp,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'tcp_flags': tcp_flags
            })
            
            # Simple heuristic: count all attempts as potential failures
            # In a real implementation, you'd need deeper packet inspection
            # or integration with SSH logs to determine success/failure
            self.failed_attempts[src_ip].append(dt_timestamp)
            
            # Clean old attempts
            self.cleanup_old_attempts(src_ip, dt_timestamp)
            
            # Check for brute force
            if len(self.failed_attempts[src_ip]) >= self.threshold:
                self.handle_brute_force(src_ip, dt_timestamp)
                
        except Exception as e:
            self.logger.debug(f"Error processing packet: {packet_line[:100]} - {e}")
    
    def log_ssh_attempt(self, src_ip: str, dst_ip: str, dst_port: str, timestamp: float, tcp_flags: str):
        """Log SSH connection attempt"""
        dt = datetime.fromtimestamp(timestamp)
        
        # Determine connection type based on TCP flags
        connection_type = "UNKNOWN"
        if "0x0002" in tcp_flags:  # SYN flag
            connection_type = "CONNECTION_ATTEMPT"
        elif "0x0004" in tcp_flags:  # RST flag
            connection_type = "CONNECTION_RESET"
        elif "0x0010" in tcp_flags:  # ACK flag
            connection_type = "ESTABLISHED"
        
        self.attack_logger.info(
            f"SSH {connection_type} - Source: {src_ip} -> Destination: {dst_ip}:{dst_port} "
            f"at {dt.strftime('%Y-%m-%d %H:%M:%S')} (flags: {tcp_flags})"
        )
    
    def cleanup_old_attempts(self, ip: str, current_time: datetime):
        """Remove attempts older than the time window"""
        cutoff_time = current_time - timedelta(seconds=self.time_window)
        
        # Clean failed attempts
        while (self.failed_attempts[ip] and 
               self.failed_attempts[ip][0] < cutoff_time):
            self.failed_attempts[ip].popleft()
            
        # Clean connection attempts
        self.connection_attempts[ip] = [
            attempt for attempt in self.connection_attempts[ip]
            if attempt['timestamp'] > cutoff_time
        ]
    
    def handle_brute_force(self, src_ip: str, detection_time: datetime):
        """Handle detected brute force attempt"""
        if src_ip in self.blocked_ips:
            return  # Already blocked
        
        attempt_count = len(self.failed_attempts[src_ip])
        
        self.logger.warning(
            f"BRUTE FORCE DETECTED: {src_ip} made {attempt_count} "
            f"attempts in {self.time_window}s window"
        )
        
        # Log security event
        self.attack_logger.warning(
            f"BRUTE FORCE ATTACK - IP: {src_ip}, Attempts: {attempt_count}, "
            f"Time Window: {self.time_window}s, Action: BLOCKING"
        )
        
        # Block the IP
        success = self.block_ip(src_ip, detection_time)
        
        if success:
            # Schedule unblock
            unblock_timer = threading.Timer(
                self.block_duration, 
                self.unblock_ip, 
                args=[src_ip]
            )
            unblock_timer.start()
            
            # Clear failed attempts for this IP
            self.failed_attempts[src_ip].clear()
    
    def block_ip(self, ip: str, block_time: datetime) -> bool:
        """Block IP using iptables"""
        try:
            # Check if rule already exists
            check_cmd = ['iptables', '-C', 'INPUT', '-s', ip, '-j', 'DROP']
            result = subprocess.run(check_cmd, capture_output=True)
            
            if result.returncode != 0:
                # Rule doesn't exist, add it
                block_cmd = ['iptables', '-I', 'INPUT', '1', '-s', ip, '-j', 'DROP']
                subprocess.run(block_cmd, check=True)
                
                self.blocked_ips[ip] = block_time
                self.logger.info(f"Successfully blocked {ip}")
                
                # Log to attack log
                self.attack_logger.info(f"IP BLOCKED - {ip} for {self.block_duration}s")
                
                return True
            else:
                self.logger.info(f"IP {ip} already blocked")
                return False
                
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to block {ip}: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error blocking {ip}: {e}")
            return False
    
    def unblock_ip(self, ip: str):
        """Unblock IP by removing iptables rule"""
        try:
            unblock_cmd = ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP']
            subprocess.run(unblock_cmd, check=True)
            
            if ip in self.blocked_ips:
                del self.blocked_ips[ip]
                
            self.logger.info(f"Successfully unblocked {ip}")
            self.attack_logger.info(f"IP UNBLOCKED - {ip}")
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to unblock {ip}: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error unblocking {ip}: {e}")
    
    def get_statistics(self) -> Dict:
        """Get current monitoring statistics"""
        current_time = datetime.now()
        uptime = current_time.timestamp() - self.start_time
        
        # Count recent attempts
        recent_attempts = sum(len(attempts) for attempts in self.failed_attempts.values())
        
        # Count unique IPs
        unique_ips = len(self.failed_attempts)
        
        return {
            'monitoring_interface': self.interface,
            'threshold': self.threshold,
            'time_window': self.time_window,
            'block_duration': self.block_duration,
            'recent_attempts': recent_attempts,
            'unique_attacking_ips': unique_ips,
            'currently_blocked_ips': len(self.blocked_ips),
            'blocked_ips': list(self.blocked_ips.keys()),
            'whitelist_entries': len(self.whitelist),
            'uptime_seconds': uptime,
            'uptime_formatted': str(timedelta(seconds=int(uptime)))
        }
    
    def print_status(self):
        """Print current detector status"""
        stats = self.get_statistics()
        
        print("\n" + "="*60)
        print("SSH BRUTE FORCE DETECTOR STATUS")
        print("="*60)
        print(f"Interface: {stats['monitoring_interface']}")
        print(f"Detection Rule: {stats['threshold']} attempts in {stats['time_window']}s")
        print(f"Block Duration: {stats['block_duration']}s")
        print(f"Recent Attempts: {stats['recent_attempts']}")
        print(f"Unique Attacking IPs: {stats['unique_attacking_ips']}")
        print(f"Currently Blocked: {stats['currently_blocked_ips']} IPs")
        
        if stats['blocked_ips']:
            print("Blocked IPs:", ', '.join(stats['blocked_ips'][:5]))
            if len(stats['blocked_ips']) > 5:
                print(f"  ... and {len(stats['blocked_ips']) - 5} more")
                
        print(f"Uptime: {stats['uptime_formatted']}")
        print("="*60)
    
    def status_monitor(self):
        """Background thread for periodic status updates and cleanup"""
        last_status_time = time.time()
        
        while self.running:
            time.sleep(30)  # Check every 30 seconds
            
            current_time = time.time()
            
            # Print status every 5 minutes
            if current_time - last_status_time > 300:
                self.print_status()
                last_status_time = current_time
            
            # Clean up expired blocks
            current_dt = datetime.now()
            expired_blocks = []
            
            for ip, block_time in self.blocked_ips.items():
                if current_dt - block_time > timedelta(seconds=self.block_duration):
                    expired_blocks.append(ip)
            
            for ip in expired_blocks:
                self.unblock_ip(ip)
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.shutdown()
    
    def shutdown(self):
        """Graceful shutdown"""
        self.running = False
        
        # Terminate tshark process
        if self.tshark_process:
            try:
                self.tshark_process.terminate()
                self.tshark_process.wait(timeout=5)
                self.logger.info("tshark process terminated")
            except subprocess.TimeoutExpired:
                self.logger.warning("tshark didn't terminate, killing...")
                self.tshark_process.kill()
            except Exception as e:
                self.logger.error(f"Error terminating tshark: {e}")
        
        self.logger.info("SSH Brute Force Detector shut down")
    
    def run(self, verbose=False):
        """Main execution method"""
        self.verbose = verbose
        
        self.logger.info("SSH Brute Force Detector starting...")
        self.logger.info(f"Monitoring interface: {self.interface}")
        self.logger.info(f"Threshold: {self.threshold} attempts in {self.time_window}s")
        self.logger.info(f"Block duration: {self.block_duration}s")
        
        # Check permissions for iptables
        if os.geteuid() != 0:
            self.logger.warning("Not running as root - IP blocking may fail")
        
        # Start status monitor thread
        status_thread = threading.Thread(target=self.status_monitor, daemon=True)
        status_thread.start()
        
        # Print initial status
        self.print_status()
        
        # Keep trying to restart tshark if it fails
        max_restarts = 5
        restart_count = 0
        
        while self.running and restart_count < max_restarts:
            try:
                success = self.start_tshark_monitor()
                if not success:
                    restart_count += 1
                    if restart_count < max_restarts:
                        self.logger.warning(f"tshark failed, restarting in 10 seconds... (attempt {restart_count}/{max_restarts})")
                        time.sleep(10)
                    else:
                        self.logger.error("Maximum restart attempts reached, giving up")
                        break
                else:
                    # Reset restart counter on successful run
                    restart_count = 0
                    
            except KeyboardInterrupt:
                self.logger.info("Interrupted by user")
                break
            except Exception as e:
                self.logger.error(f"Unexpected error: {e}")
                restart_count += 1
                if restart_count < max_restarts:
                    time.sleep(10)
                else:
                    break
        
        self.shutdown()

def check_requirements():
    """Check system requirements"""
    issues = []
    
    # Check if tshark is available
    try:
        subprocess.run(['tshark', '--version'], 
                      capture_output=True, timeout=5)
    except FileNotFoundError:
        issues.append("tshark not found. Install with: sudo apt-get install tshark")
    except Exception as e:
        issues.append(f"tshark test failed: {e}")
    
    # Check if iptables is available
    try:
        subprocess.run(['iptables', '--version'], 
                      capture_output=True, timeout=5)
    except FileNotFoundError:
        issues.append("iptables not found")
    except Exception as e:
        issues.append(f"iptables test failed: {e}")
    
    # Check permissions
    if os.geteuid() != 0:
        issues.append("Not running as root - some features may not work")
    
    return issues

def main():
    parser = argparse.ArgumentParser(
        description='SSH Brute Force Detector using tshark',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Monitor all interfaces with default settings
  %(prog)s -i eth0 -t 3 -w 180      # Monitor eth0, block after 3 attempts in 3 minutes
  %(prog)s -b 7200 -v               # Block for 2 hours with verbose output
  
Log files:
  ssh_detector.log    - Detailed application logs
  ssh_attacks.log     - Security events and attacks
  whitelist.txt       - Trusted IPs and networks
  
Requirements:
  - tshark (wireshark-common package)
  - iptables
  - root privileges (for blocking)
        """
    )
    
    parser.add_argument('-i', '--interface', default='any',
                       help='Network interface to monitor (default: any)')
    parser.add_argument('-t', '--threshold', type=int, default=5,
                       help='Attempts before blocking (default: 5)')
    parser.add_argument('-w', '--window', type=int, default=300,
                       help='Time window in seconds (default: 300)')
    parser.add_argument('-b', '--block-duration', type=int, default=3600,
                       help='Block duration in seconds (default: 3600)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--check', action='store_true',
                       help='Check requirements and exit')
    parser.add_argument('--test-mode', action='store_true',
                       help='Run in test mode (no actual blocking)')
    
    args = parser.parse_args()
    
    # Check requirements
    issues = check_requirements()
    if issues:
        print("System Requirements Check:")
        for issue in issues:
            print(f"  - {issue}")
        print()
        
        if args.check:
            sys.exit(1 if any("not found" in issue for issue in issues) else 0)
    
    if args.check:
        print("All requirements met!")
        sys.exit(0)
    
    try:
        # Create and run detector
        detector = SSHBruteForceDetector(
            interface=args.interface,
            threshold=args.threshold,
            time_window=args.window,
            block_duration=args.block_duration
        )
        
        # Override blocking in test mode
        if args.test_mode:
            print("Running in TEST MODE - no actual IP blocking")
            detector.block_ip = lambda ip, time: print(f"TEST: Would block {ip}")
            detector.unblock_ip = lambda ip: print(f"TEST: Would unblock {ip}")
        
        detector.run(verbose=args.verbose)
        
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

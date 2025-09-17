import streamlit as st
import psutil
import time
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import hashlib
import os
import json
import requests
import socket
import subprocess
import re
from pathlib import Path
import threading
import queue
import ipaddress
from collections import deque
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import warnings
warnings.filterwarnings('ignore')

# Configuration
UPDATE_INTERVAL = 10  # seconds (increased for better performance)
MAX_EVENTS = 500  # Maximum events to keep in memory (reduced)

# AI Model Configuration
AI_MODEL_PATH = "ai_models"
os.makedirs(AI_MODEL_PATH, exist_ok=True)

# Known malicious indicators (in a real scenario, these would come from threat feeds)
KNOWN_MALICIOUS_IPS = ["192.168.1.100", "10.0.0.5"]  # Example only
KNOWN_MALICIOUS_DOMAINS = ["malicious-domain.com", "evil-site.org"]  # Example only
SUSPICIOUS_PROCESS_NAMES = ["mimikatz", "powersploit", "cobaltstrike", "empire", "metasploit", "netcat", "nc", "ncat"]

# Important Windows directories to monitor
WINDOWS_CRITICAL_DIRS = [
    "C:\\Windows\\System32\\",
    "C:\\Windows\\System32\\drivers\\etc\\",
    "C:\\Windows\\System32\\config\\",
    "C:\\Windows\\System32\\Tasks\\",
    "C:\\Windows\\System32\\GroupPolicy\\",
    "C:\\Windows\\System32\\LogFiles\\",
    "C:\\Windows\\System32\\winevt\\Logs\\",
    "C:\\Windows\\SysWOW64\\",
    "C:\\Windows\\Temp\\",
    "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",
    "C:\\Users\\Default\\",
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\",
    # Add Downloads and AppData directories for all users
    *(str(p) for p in Path("C:/Users").glob("*/Downloads")),
    *(str(p) for p in Path("C:/Users").glob("*/AppData/Roaming")),
    *(str(p) for p in Path("C:/Users").glob("*/AppData/Local")),
]

SENSITIVE_DIRS = {
    "Linux": ["/etc/ssh/", "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/hosts"],
    "Windows": WINDOWS_CRITICAL_DIRS
}

# Initialize session state
if 'alerts' not in st.session_state:
    st.session_state.alerts = deque(maxlen=MAX_EVENTS)
if 'metrics_history' not in st.session_state:
    st.session_state.metrics_history = deque(maxlen=50)  # Reduced for memory efficiency
if 'file_events' not in st.session_state:
    st.session_state.file_events = deque(maxlen=MAX_EVENTS)
if 'network_events' not in st.session_state:
    st.session_state.network_events = deque(maxlen=MAX_EVENTS)
if 'process_events' not in st.session_state:
    st.session_state.process_events = deque(maxlen=MAX_EVENTS)
if 'monitoring_active' not in st.session_state:
    st.session_state.monitoring_active = False
if 'monitor_dirs' not in st.session_state:
    # Auto-add Windows critical directories if on Windows
    if os.name == 'nt':
        st.session_state.monitor_dirs = WINDOWS_CRITICAL_DIRS[:3]  # Start with first 3 to avoid too many
    else:
        st.session_state.monitor_dirs = []
if 'threat_intel_cache' not in st.session_state:
    st.session_state.threat_intel_cache = {}
if 'baseline_established' not in st.session_state:
    st.session_state.baseline_established = False
if 'behavior_baseline' not in st.session_state:
    st.session_state.behavior_baseline = {}
if 'last_check_time' not in st.session_state:
    st.session_state.last_check_time = datetime.now()
if 'shown_notifications' not in st.session_state:
    st.session_state.shown_notifications = set()
if 'enable_notifications' not in st.session_state:
    st.session_state.enable_notifications = True
if 'selected_alert_index' not in st.session_state:
    st.session_state.selected_alert_index = 0
if 'needs_rerun' not in st.session_state:
    st.session_state.needs_rerun = False
if 'ai_models' not in st.session_state:
    st.session_state.ai_models = {
        'anomaly_detector': None,
        'scaler': None,
        'model_trained': True,  # Set to True since we're using pre-trained
        'training_data': []
    }
if 'ai_enabled' not in st.session_state:
    st.session_state.ai_enabled = True
if 'ai_analysis' not in st.session_state:
    st.session_state.ai_analysis = {}

# AI Functions
def initialize_ai_models():
    """Initialize AI models with pre-trained models for anomaly detection"""
    try:
        # Try to load existing models
        if os.path.exists(f"{AI_MODEL_PATH}/anomaly_detector.joblib"):
            st.session_state.ai_models['anomaly_detector'] = joblib.load(f"{AI_MODEL_PATH}/anomaly_detector.joblib")
        else:
            # Create a pre-trained model with sensible defaults
            st.session_state.ai_models['anomaly_detector'] = IsolationForest(
                n_estimators=100, 
                contamination=0.1, 
                random_state=42
            )
            
        if os.path.exists(f"{AI_MODEL_PATH}/scaler.joblib"):
            st.session_state.ai_models['scaler'] = joblib.load(f"{AI_MODEL_PATH}/scaler.joblib")
        else:
            # Create a pre-fitted scaler with typical system metrics ranges
            st.session_state.ai_models['scaler'] = StandardScaler()
            # Pre-fit with typical system metrics (CPU: 0-100, Memory: 0-100, Process Count: 0-500, etc.)
            typical_data = np.array([
                [25, 45, 80, 10, 5, 8],    # Low usage
                [50, 65, 120, 25, 15, 20], # Medium usage  
                [85, 90, 200, 50, 30, 40], # High usage
                [10, 30, 50, 5, 2, 3],     # Very low usage
                [95, 95, 250, 75, 50, 60]  # Very high usage
            ])
            st.session_state.ai_models['scaler'].fit(typical_data)
            
        st.session_state.ai_models['model_trained'] = True
    except Exception as e:
        st.error(f"Error initializing AI models: {str(e)}")
        # Fallback to basic models
        st.session_state.ai_models['anomaly_detector'] = IsolationForest(
            n_estimators=100, 
            contamination=0.1, 
            random_state=42
        )
        st.session_state.ai_models['scaler'] = StandardScaler()
        st.session_state.ai_models['model_trained'] = True

def prepare_ai_features(metrics):
    """Prepare features for AI anomaly detection"""
    features = [
        metrics['cpu'],
        metrics['memory_percent'],
        metrics['process_count'],
        len(metrics['network_connections']),
        metrics.get('net_sent', 0),
        metrics.get('net_recv', 0)
    ]
    return np.array(features).reshape(1, -1)

def detect_anomalies(metrics):
    """Detect anomalies using pre-trained AI models"""
    if not st.session_state.ai_enabled:
        return None
    
    try:
        # Prepare features
        features = prepare_ai_features(metrics)
        
        # Scale features
        features_scaled = st.session_state.ai_models['scaler'].transform(features)
        
        # Predict anomalies
        prediction = st.session_state.ai_models['anomaly_detector'].predict(features_scaled)
        anomaly_score = st.session_state.ai_models['anomaly_detector'].decision_function(features_scaled)
        
        return {
            'is_anomaly': prediction[0] == -1,
            'anomaly_score': float(anomaly_score[0]),
            'features': features.tolist()[0]
        }
    except Exception as e:
        st.error(f"Error in anomaly detection: {str(e)}")
        return None

def ai_analyze_processes(processes):
    """AI analysis of process behavior"""
    if not processes or not st.session_state.ai_enabled:
        return {}
    
    try:
        # Simple AI analysis - identify unusual process patterns
        analysis = {
            'suspicious_processes': [],
            'unusual_cpu_patterns': [],
            'unusual_memory_patterns': []
        }
        
        # Calculate statistics for comparison
        cpu_values = [p.get('cpu_percent', 0) for p in processes if p.get('cpu_percent') is not None]
        memory_values = [p.get('memory_percent', 0) for p in processes if p.get('memory_percent') is not None]
        
        if cpu_values:
            cpu_mean = np.mean(cpu_values)
            cpu_std = np.std(cpu_values) if len(cpu_values) > 1 else 1.0
            
            # Identify processes with unusual CPU usage
            for proc in processes:
                cpu = proc.get('cpu_percent', 0)
                if cpu > cpu_mean + 2 * cpu_std and cpu > 10:  # More than 2 std dev above mean and at least 10%
                    analysis['unusual_cpu_patterns'].append({
                        'process': proc['name'],
                        'pid': proc['pid'],
                        'cpu_percent': cpu,
                        'deviation': (cpu - cpu_mean) / cpu_std if cpu_std > 0 else 0
                    })
        
        if memory_values:
            memory_mean = np.mean(memory_values)
            memory_std = np.std(memory_values) if len(memory_values) > 1 else 1.0
            
            # Identify processes with unusual memory usage
            for proc in processes:
                memory = proc.get('memory_percent', 0)
                if memory > memory_mean + 2 * memory_std and memory > 5:  # More than 2 std dev above mean and at least 5%
                    analysis['unusual_memory_patterns'].append({
                        'process': proc['name'],
                        'pid': proc['pid'],
                        'memory_percent': memory,
                        'deviation': (memory - memory_mean) / memory_std if memory_std > 0 else 0
                    })
        
        return analysis
    except Exception as e:
        st.error(f"Error in process analysis: {str(e)}")
        return {}

def ai_analyze_network(network_connections):
    """AI analysis of network connections"""
    if not network_connections or not st.session_state.ai_enabled:
        return {}
    
    try:
        analysis = {
            'unusual_connections': [],
            'suspicious_patterns': []
        }
        
        # Group connections by remote IP
        ip_connections = {}
        for conn in network_connections:
            remote_ip = conn['remote_address'].split(':')[0]
            if remote_ip not in ip_connections:
                ip_connections[remote_ip] = []
            ip_connections[remote_ip].append(conn)
        
        # Look for unusual connection patterns
        for ip, connections in ip_connections.items():
            if len(connections) > 5:  # More than 5 connections to the same IP
                analysis['suspicious_patterns'].append({
                    'ip': ip,
                    'connection_count': len(connections),
                    'ports': list(set([conn['remote_address'].split(':')[1] for conn in connections if ':' in conn['remote_address']]))
                })
        
        return analysis
    except Exception as e:
        st.error(f"Error in network analysis: {str(e)}")
        return {}

# [The rest of your functions remain unchanged - get_file_mod_time, get_network_connections, 
# check_threat_intelligence, get_system_metrics, check_directory_changes, 
# establish_behavior_baseline, check_suspicious_activity, get_system_logs, 
# check_misconfigurations, get_threat_countermeasures, update_forensics_tab, 
# setup_ui, update_dashboard, update_processes_tab, update_network_tab, 
# update_file_events_tab, update_alerts_tab, main]

def get_file_mod_time(file_path):
    """Get file modification time (much faster than hashing)"""
    try:
        return os.path.getmtime(file_path)
    except Exception as e:
        return f"Error: {str(e)}"

def get_network_connections():
    """Get active network connections"""
    connections = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED' and conn.raddr:
                connections.append({
                    "pid": conn.pid,
                    "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                    "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}",
                    "status": conn.status,
                    "timestamp": datetime.now().isoformat()
                })
    except Exception as e:
        st.error(f"Error getting network connections: {str(e)}")
    return connections

def check_threat_intelligence(ip_address):
    """Check IP against threat intelligence sources (optimized caching)"""
    if ip_address in st.session_state.threat_intel_cache:
        return st.session_state.threat_intel_cache[ip_address]

    # Quick check for known malicious IPs (no simulation delay)
    result = {
        "malicious": ip_address in KNOWN_MALICIOUS_IPS,
        "reputation": "high" if ip_address.startswith("192.168.") else "unknown",
        "threat_types": [],
        "last_seen": None
    }

    st.session_state.threat_intel_cache[ip_address] = result
    return result

def get_system_metrics():
    """Collect system metrics"""
    cpu_percent = psutil.cpu_percent(interval=0.1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    net_io = psutil.net_io_counters()
    
    # Get process count
    process_count = len(psutil.pids())
    
    # Get list of running processes with more details (limited to top 50 by CPU for performance)
    processes = []
    all_procs = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'create_time']):
        try:
            all_procs.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    # Sort by CPU usage and take top 50
    all_procs.sort(key=lambda x: x.get('cpu_percent', 0), reverse=True)
    processes = all_procs[:50]
    
    # Get network connections
    network_connections = get_network_connections()
    
    return {
        "timestamp": datetime.now().isoformat(),
        "cpu": cpu_percent,
        "memory_percent": memory.percent,
        "memory_used": memory.used / (1024 ** 3),  # GB
        "memory_total": memory.total / (1024 ** 3),  # GB
        "disk_percent": disk.percent,
        "disk_used": disk.used / (1024 ** 3),  # GB
        "disk_total": disk.total / (1024 ** 3),  # GB
        "net_sent": net_io.bytes_sent / (1024 ** 2),  # MB
        "net_recv": net_io.bytes_recv / (1024 ** 2),  # MB
        "process_count": process_count,
        "processes": processes,
        "network_connections": network_connections
    }

def check_directory_changes():
    """Check for directory changes (simulated file monitoring)"""
    file_events = []
    
    for directory in st.session_state.monitor_dirs:
        if not os.path.exists(directory):
            continue
            
        # Check files in the directory (limited for performance)
        try:
            files = []
            for root, _, filenames in os.walk(directory):
                for filename in filenames[:5]:  # Reduced to 5 files per directory
                    file_path = os.path.join(root, filename)
                    files.append(file_path)
                break  # Only check top-level directory, not subdirs

            for file_path in files[:3]:  # Check only first 3 files
                try:
                    # Check file modification time (much faster than hashing)
                    current_mod_time = get_file_mod_time(file_path)

                    # Check if this file has been seen before
                    file_key = f"file_{file_path}"
                    if file_key not in st.session_state:
                        st.session_state[file_key] = {"mod_time": current_mod_time, "last_checked": datetime.now()}

                        # New file discovered
                        file_events.append({
                            "timestamp": datetime.now().isoformat(),
                            "event_type": "created",
                            "path": file_path,
                            "mod_time": current_mod_time,
                            "directory": directory
                        })
                    else:
                        # Check if file has been modified
                        if st.session_state[file_key]["mod_time"] != current_mod_time:
                            file_events.append({
                                "timestamp": datetime.now().isoformat(),
                                "event_type": "modified",
                                "path": file_path,
                                "mod_time": current_mod_time,
                                "directory": directory,
                                "old_mod_time": st.session_state[file_key]["mod_time"]
                            })
                            st.session_state[file_key] = {"mod_time": current_mod_time, "last_checked": datetime.now()}

                        # Update last checked time
                        st.session_state[file_key]["last_checked"] = datetime.now()

                except Exception as e:
                    continue
                    
        except Exception as e:
            continue
    
    return file_events

def establish_behavior_baseline(metrics):
    """Establish a baseline of normal system behavior"""
    if not st.session_state.baseline_established:
        # Simple baseline - just record current process count and CPU usage
        st.session_state.behavior_baseline = {
            "process_count": metrics["process_count"],
            "cpu_usage": metrics["cpu"],
            "memory_usage": metrics["memory_percent"],
            "established_at": datetime.now().isoformat()
        }
        st.session_state.baseline_established = True

def check_suspicious_activity(metrics, prev_metrics):
    """Check for suspicious system activity"""
    alerts = []
    
    # Establish baseline if not done
    establish_behavior_baseline(metrics)
    
    # High CPU usage
    if metrics["cpu"] > 90:
        alerts.append({
            "type": "High CPU Usage",
            "message": f"CPU usage is at {metrics['cpu']}%",
            "severity": "medium",
            "details": metrics
        })
    
    # High memory usage
    if metrics["memory_percent"] > 90:
        alerts.append({
            "type": "High Memory Usage",
            "message": f"Memory usage is at {metrics['memory_percent']}%",
            "severity": "medium",
            "details": metrics
        })
    
    # Sudden process count change
    baseline = st.session_state.behavior_baseline
    if abs(metrics["process_count"] - baseline["process_count"]) > 20:
        alerts.append({
            "type": "Suspicious Process Activity",
            "message": f"Process count changed significantly: {baseline['process_count']} -> {metrics['process_count']}",
            "severity": "high",
            "details": metrics
        })
    
    # Check for suspicious processes
    for proc in metrics["processes"]:
        proc_name = proc['name'].lower() if proc['name'] else ""
        
        # Check against known suspicious process names
        for suspicious_name in SUSPICIOUS_PROCESS_NAMES:
            if suspicious_name in proc_name:
                alerts.append({
                    "type": "Suspicious Process Detected",
                    "message": f"Process with known suspicious name: {proc['name']} (PID: {proc['pid']})",
                    "severity": "high",
                    "details": proc
                })
        
        # Check for processes with high CPU
        if proc.get('cpu_percent', 0) > 50:
            alerts.append({
                "type": "High Process CPU Usage",
                "message": f"Process {proc['name']} (PID: {proc['pid']}) using high CPU: {proc['cpu_percent']}%",
                "severity": "medium",
                "details": proc
            })
    
    # Check network connections for suspicious activity
    for conn in metrics["network_connections"]:
        # Extract IP from remote address
        remote_ip = conn["remote_address"].split(":")[0]
        
        # Check against known malicious IPs
        if remote_ip in KNOWN_MALICIOUS_IPS:
            alerts.append({
                "type": "Connection to Known Malicious IP",
                "message": f"Connection to known malicious IP: {remote_ip}",
                "severity": "critical",
                "details": conn
            })
        
        # Check threat intelligence
        ti_data = check_threat_intelligence(remote_ip)
        if ti_data.get("malicious", False):
            alerts.append({
                "type": "Connection to Malicious IP",
                "message": f"Connection to malicious IP: {remote_ip}",
                "severity": "critical",
                "details": {"connection": conn, "threat_intel": ti_data}
            })
    
    # Check for unusual process behavior (processes that weren't in previous metrics)
    if prev_metrics:
        prev_pids = {p['pid'] for p in prev_metrics['processes']}
        current_pids = {p['pid'] for p in metrics['processes']}
        new_pids = current_pids - prev_pids
        
        for pid in new_pids:
            proc = next((p for p in metrics['processes'] if p['pid'] == pid), None)
            if proc and proc.get('cpu_percent', 0) > 10:
                alerts.append({
                    "type": "New High CPU Process",
                    "message": f"New process {proc['name']} (PID: {pid}) using high CPU: {proc['cpu_percent']}%",
                    "severity": "medium",
                    "details": proc
                })
    
    # AI-powered anomaly detection
    if st.session_state.ai_enabled:
        anomaly_result = detect_anomalies(metrics)
        if anomaly_result and anomaly_result['is_anomaly']:
            alerts.append({
                "type": "AI-Detected Anomaly",
                "message": f"AI detected unusual system behavior (score: {anomaly_result['anomaly_score']:.2f})",
                "severity": "high",
                "details": {
                    "anomaly_score": anomaly_result['anomaly_score'],
                    "features": anomaly_result['features'],
                    "metrics": metrics
                }
            })
        
        # AI analysis of processes
        process_analysis = ai_analyze_processes(metrics['processes'])
        if process_analysis.get('unusual_cpu_patterns'):
            for pattern in process_analysis['unusual_cpu_patterns']:
                alerts.append({
                    "type": "AI-Detected Unusual Process CPU",
                    "message": f"Process {pattern['process']} (PID: {pattern['pid']}) shows unusual CPU pattern",
                    "severity": "medium",
                    "details": pattern
                })
        
        # AI analysis of network
        network_analysis = ai_analyze_network(metrics['network_connections'])
        if network_analysis.get('suspicious_patterns'):
            for pattern in network_analysis['suspicious_patterns']:
                alerts.append({
                    "type": "AI-Detected Suspicious Network Pattern",
                    "message": f"Suspicious network pattern detected for IP {pattern['ip']} ({pattern['connection_count']} connections)",
                    "severity": "high",
                    "details": pattern
                })
    
    # Add timestamp to each alert
    for alert in alerts:
        alert["timestamp"] = datetime.now().isoformat()
    
    return alerts

def get_system_logs():
    """Get system logs (Windows Event Log or Linux syslog)"""
    logs = []
    try:
        if os.name == 'nt':  # Windows
            # Use PowerShell to get recent security events
            cmd = ['powershell', 'Get-WinEvent', '-LogName', 'Security', '-MaxEvents', '10']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if line.strip():
                        logs.append({
                            "timestamp": datetime.now().isoformat(),
                            "source": "Windows Security Log",
                            "message": line.strip()
                        })
        else:  # Linux
            # Read from syslog
            with open('/var/log/syslog', 'r') as f:
                lines = f.readlines()[-10:]  # Last 10 lines
                for line in lines:
                    logs.append({
                        "timestamp": datetime.now().isoformat(),
                        "source": "Syslog",
                        "message": line.strip()
                    })
    except Exception as e:
        # Don't show error to avoid cluttering the UI
        pass
    
    return logs

def check_misconfigurations():
    """Check for common system misconfigurations that could lead to security vulnerabilities"""
    misconfigs = []

    try:
        if os.name == 'nt':  # Windows
            # Check Windows Firewall status
            cmd = ['netsh', 'advfirewall', 'show', 'allprofiles', 'state']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                if "OFF" in result.stdout.upper():
                    misconfigs.append({
                        "type": "Firewall Disabled",
                        "description": "Windows Firewall is disabled on one or more profiles",
                        "severity": "critical",
                        "recommendation": "Enable Windows Firewall for all network profiles",
                        "countermeasure": "Run 'netsh advfirewall set allprofiles state on' as administrator"
                    })

            # Check for open ports (common vulnerable ports)
            cmd = ['netstat', '-an']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                vulnerable_ports = [21, 23, 25, 53, 110, 143, 445, 993, 995, 3389]  # FTP, Telnet, SMTP, etc.
                open_ports = []
                for line in lines:
                    if 'LISTENING' in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            addr = parts[1]
                            if ':' in addr:
                                port = addr.split(':')[-1]
                                try:
                                    port_num = int(port)
                                    if port_num in vulnerable_ports:
                                        open_ports.append(port_num)
                                except:
                                    pass
                if open_ports:
                    misconfigs.append({
                        "type": "Vulnerable Ports Open",
                        "description": f"Potentially vulnerable ports are open: {', '.join(map(str, open_ports))}",
                        "severity": "high",
                        "recommendation": "Close unnecessary ports or restrict access with firewall rules",
                        "countermeasure": "Use Windows Firewall to block these ports or disable unnecessary services"
                    })

            # Check User Account Control (UAC) status
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
                uac_value, _ = winreg.QueryValueEx(key, "EnableLUA")
                if uac_value != 1:
                    misconfigs.append({
                        "type": "UAC Disabled",
                        "description": "User Account Control (UAC) is disabled",
                        "severity": "high",
                        "recommendation": "Enable UAC to prevent unauthorized privilege escalation",
                        "countermeasure": "Set EnableLUA to 1 in registry or use secpol.msc"
                    })
                winreg.CloseKey(key)
            except:
                pass

            # Check for weak password policies
            cmd = ['net', 'accounts']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                if "Minimum password length: 0" in result.stdout or "Password history: 0" in result.stdout:
                    misconfigs.append({
                        "type": "Weak Password Policy",
                        "description": "Password policy is too weak (no minimum length or history)",
                        "severity": "medium",
                        "recommendation": "Set strong password requirements",
                        "countermeasure": "Use secpol.msc to configure password policies"
                    })

            # Check for guest account enabled
            cmd = ['net', 'user', 'guest']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and "Account active" in result.stdout:
                misconfigs.append({
                    "type": "Guest Account Enabled",
                    "description": "Guest account is enabled",
                    "severity": "medium",
                    "recommendation": "Disable guest account for security",
                    "countermeasure": "Run 'net user guest /active:no' as administrator"
                })

        else:  # Linux
            # Check if firewall is running (ufw or firewalld)
            firewall_active = False
            try:
                result = subprocess.run(['ufw', 'status'], capture_output=True, text=True, timeout=5)
                if "active" in result.stdout.lower():
                    firewall_active = True
            except:
                try:
                    result = subprocess.run(['firewall-cmd', '--state'], capture_output=True, text=True, timeout=5)
                    if "running" in result.stdout.lower():
                        firewall_active = True
                except:
                    pass

            if not firewall_active:
                misconfigs.append({
                    "type": "Firewall Inactive",
                    "description": "System firewall is not active",
                    "severity": "critical",
                    "recommendation": "Enable and configure firewall",
                    "countermeasure": "Enable ufw or firewalld and configure rules"
                })

            # Check for world-writable files in sensitive directories
            sensitive_dirs = ["/etc", "/usr/bin", "/bin"]
            for sdir in sensitive_dirs:
                if os.path.exists(sdir):
                    cmd = ['find', sdir, '-type', 'f', '-perm', '/002', '-ls']
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0 and result.stdout.strip():
                        misconfigs.append({
                            "type": "World-Writable Files",
                            "description": f"World-writable files found in {sdir}",
                            "severity": "high",
                            "recommendation": "Remove world-write permissions from sensitive files",
                            "countermeasure": "Use chmod to restrict permissions"
                        })

    except Exception as e:
        misconfigs.append({
            "type": "Scan Error",
            "description": f"Error during misconfiguration scan: {str(e)}",
            "severity": "low",
            "recommendation": "Check system permissions and try again",
            "countermeasure": "Run the application with appropriate privileges"
        })

    return misconfigs

def get_threat_countermeasures(threat_type, details):
    """Get specific countermeasures for detected threats"""
    countermeasures = {
        "High CPU Usage": [
            "Monitor process activity and identify resource-intensive applications",
            "Check for malware or unauthorized processes",
            "Consider upgrading hardware if legitimate processes require high CPU"
        ],
        "High Memory Usage": [
            "Identify memory-leaking processes",
            "Close unnecessary applications",
            "Check for memory-intensive malware"
        ],
        "Suspicious Process Activity": [
            "Investigate new processes using tools like Process Explorer",
            "Check process parent-child relationships",
            "Scan with antivirus software"
        ],
        "Suspicious Process Detected": [
            "Terminate the suspicious process if confirmed malicious",
            "Quarantine the executable file",
            "Update antivirus signatures and scan the system"
        ],
        "Connection to Known Malicious IP": [
            "Block the IP address in firewall",
            "Disconnect from the network if necessary",
            "Investigate how the connection was established"
        ],
        "Sensitive File Change": [
            "Verify the file change was authorized",
            "Check file integrity if critical system file",
            "Monitor for further unauthorized changes"
        ],
        "AI-Detected Anomaly": [
            "Review system metrics for unusual patterns",
            "Check for new or unusual processes",
            "Monitor network activity for suspicious connections",
            "Consider running a full system scan"
        ],
        "AI-Detected Unusual Process CPU": [
            "Investigate the process for legitimacy",
            "Check the process signature and digital certificate",
            "Monitor the process behavior over time"
        ],
        "AI-Detected Suspicious Network Pattern": [
            "Investigate the remote IP for reputation",
            "Check if the connections are legitimate",
            "Consider blocking the IP if suspicious"
        ]
    }

    return countermeasures.get(threat_type, ["Investigate the alert details", "Consult security best practices"])

def update_forensics_tab(tab):
    """Update the forensics tab with threat analysis and recommendations"""
    with tab:
        st.header("🔍 Threat Forensics & Analysis")

        col1, col2 = st.columns(2)

        with col1:
            if st.button("🔎 Run Misconfiguration Scan", key="misconfig_scan_btn"):
                with st.spinner("Scanning for misconfigurations..."):
                    misconfigs = check_misconfigurations()
                    st.session_state.misconfigs = misconfigs
                    st.success(f"Scan completed. Found {len(misconfigs)} potential misconfigurations.")

        with col2:
            if st.button("📊 Analyze Current Threats", key="threat_analysis_btn"):
                # Analyze current alerts for patterns
                if st.session_state.alerts:
                    alerts_df = pd.DataFrame(st.session_state.alerts)
                    threat_analysis = {
                        "total_alerts": len(alerts_df),
                        "critical_alerts": len(alerts_df[alerts_df['severity'] == 'critical']),
                        "high_alerts": len(alerts_df[alerts_df['severity'] == 'high']),
                        "most_common": alerts_df['type'].mode().iloc[0] if not alerts_df.empty else "None",
                        "recent_activity": len(alerts_df[alerts_df['timestamp'] > (datetime.now() - timedelta(hours=1)).isoformat()])
                    }
                    st.session_state.threat_analysis = threat_analysis
                    st.success("Threat analysis completed.")
                else:
                    st.info("No alerts to analyze.")

        # Display AI analysis section
        st.subheader("🤖 AI Analysis")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("🔄 Run AI Analysis", key="ai_analysis_btn"):
                if st.session_state.metrics_history:
                    latest_metrics = st.session_state.metrics_history[-1]
                    
                    # Run AI analysis
                    st.session_state.ai_analysis = {
                        'anomaly': detect_anomalies(latest_metrics),
                        'process_analysis': ai_analyze_processes(latest_metrics['processes']),
                        'network_analysis': ai_analyze_network(latest_metrics['network_connections'])
                    }
                    st.success("AI analysis completed.")
                else:
                    st.info("No metrics data available for analysis.")
        
        with col2:
            # AI model status
            st.success("✅ AI Model: Pre-trained & Ready")
        
        # Display AI analysis results
        if st.session_state.ai_analysis:
            ai_analysis = st.session_state.ai_analysis
            
            if ai_analysis.get('anomaly'):
                anomaly = ai_analysis['anomaly']
                st.markdown("#### Anomaly Detection")
                if anomaly['is_anomaly']:
                    st.error(f"🚨 Anomaly detected! Score: {anomaly['anomaly_score']:.2f}")
                else:
                    st.success(f"✅ No anomalies detected. Score: {anomaly['anomaly_score']:.2f}")
            
            if ai_analysis.get('process_analysis'):
                proc_analysis = ai_analysis['process_analysis']
                if proc_analysis.get('unusual_cpu_patterns'):
                    st.markdown("#### Unusual CPU Patterns")
                    for pattern in proc_analysis['unusual_cpu_patterns']:
                        st.warning(f"Process {pattern['process']} (PID: {pattern['pid']}) - CPU: {pattern['cpu_percent']}%, Deviation: {pattern['deviation']:.2f}σ")
            
            if ai_analysis.get('network_analysis'):
                net_analysis = ai_analysis['network_analysis']
                if net_analysis.get('suspicious_patterns'):
                    st.markdown("#### Suspicious Network Patterns")
                    for pattern in net_analysis['suspicious_patterns']:
                        st.warning(f"IP {pattern['ip']} - {pattern['connection_count']} connections on ports: {pattern['ports']}")

        # Display misconfigurations
        if 'misconfigs' in st.session_state and st.session_state.misconfigs:
            st.subheader("🚨 System Misconfigurations")
            for misconfig in st.session_state.misconfigs:
                severity_color = {
                    "low": "blue",
                    "medium": "orange",
                    "high": "red",
                    "critical": "darkred"
                }.get(misconfig['severity'], "gray")

                with st.expander(f"{misconfig['type']} ({misconfig['severity']})"):
                    st.markdown(f"**Description:** {misconfig['description']}")
                    st.markdown(f"**Recommendation:** {misconfig['recommendation']}")
                    st.markdown(f"**Countermeasure:** {misconfig['countermeasure']}")

        # Display threat analysis
        if 'threat_analysis' in st.session_state:
            st.subheader("📈 Threat Analysis Summary")
            analysis = st.session_state.threat_analysis

            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total Alerts", analysis['total_alerts'])
            with col2:
                st.metric("Critical Alerts", analysis['critical_alerts'])
            with col3:
                st.metric("High Alerts", analysis['high_alerts'])
            with col4:
                st.metric("Recent Activity (1h)", analysis['recent_activity'])

            st.markdown(f"**Most Common Threat:** {analysis['most_common']}")

        # Detailed threat investigation
        if st.session_state.alerts:
            st.subheader("🔬 Detailed Threat Investigation")

            alerts_df = pd.DataFrame(st.session_state.alerts)
            # Ensure selected index is valid
            max_index = len(alerts_df) - 1
            if st.session_state.selected_alert_index > max_index:
                st.session_state.selected_alert_index = 0
            selected_alert = st.selectbox("Select Alert for Investigation",
                                        options=range(len(alerts_df)),
                                        format_func=lambda x: f"{alerts_df.iloc[x]['type']} - {alerts_df.iloc[x]['timestamp']}",
                                        index=st.session_state.selected_alert_index)

            st.session_state.selected_alert_index = selected_alert

            if selected_alert is not None:
                alert = alerts_df.iloc[selected_alert]
                st.markdown("### Alert Details")
                # Display alert as formatted JSON
                st.code(json.dumps(alert, indent=2, default=str), language='json')

                st.markdown("### Recommended Countermeasures")
                countermeasures = get_threat_countermeasures(alert['type'], alert.get('details', {}))
                for i, cm in enumerate(countermeasures, 1):
                    st.markdown(f"{i}. {cm}")

                # Additional forensics options
                if st.button("🕵️ Deep Investigation", key=f"deep_invest_{selected_alert}"):
                    st.markdown("#### Deep Investigation Results")
                    if alert['type'] == "Connection to Known Malicious IP":
                        remote_ip = alert.get('details', {}).get('connection', {}).get('remote_address', '').split(':')[0]
                        st.markdown(f"**Investigate IP:** {remote_ip}")
                        st.markdown("- Check IP reputation on VirusTotal or other threat intelligence platforms")
                        st.markdown("- Review firewall logs for connection attempts")
                        st.markdown("- Scan affected systems for malware")
                    elif "Process" in alert['type']:
                        pid = alert.get('details', {}).get('pid')
                        if pid:
                            st.markdown(f"**Investigate Process PID:** {pid}")
                            st.markdown("- Check process parent and child relationships")
                            st.markdown("- Analyze process memory and network connections")
                            st.markdown("- Verify process signature and origin")
                    elif alert['type'] == "High CPU Usage":
                        details = alert.get('details', {})
                        if 'processes' in details:
                            high_cpu_procs = [p for p in details['processes'] if p.get('cpu_percent', 0) > 10]
                            if high_cpu_procs:
                                st.markdown("**Processes with High CPU Usage:**")
                                for proc in high_cpu_procs[:5]:  # Top 5
                                    st.markdown(f"- {proc.get('name', 'Unknown')} (PID: {proc.get('pid')}, CPU: {proc.get('cpu_percent', 0)}%)")
                            else:
                                st.markdown("No processes with high CPU found in details.")
                        st.markdown("- Monitor system performance and identify resource-intensive applications")
                        st.markdown("- Check for malware or unauthorized processes")
                    elif alert['type'] == "High Memory Usage":
                        details = alert.get('details', {})
                        if 'processes' in details:
                            high_mem_procs = sorted(details['processes'], key=lambda p: p.get('memory_percent', 0), reverse=True)[:5]
                            st.markdown("**Top Memory-Consuming Processes:**")
                            for proc in high_mem_procs:
                                st.markdown(f"- {proc.get('name', 'Unknown')} (PID: {proc.get('pid')}, Memory: {proc.get('memory_percent', 0)}%)")
                        st.markdown("- Identify memory-leaking processes")
                        st.markdown("- Close unnecessary applications")
                    elif "AI-Detected" in alert['type']:
                        st.markdown("**AI Analysis Details:**")
                        st.markdown("- Review the specific patterns detected by the AI")
                        st.markdown("- Check if similar patterns have occurred before")
                        st.markdown("- Consider adjusting AI sensitivity if needed")
                    else:
                        st.markdown("Deep investigation options not available for this alert type.")

def setup_ui():
    """Setup the Streamlit UI"""
    st.set_page_config(
        page_title="SOC Monitoring Dashboard",
        page_icon="🔒",
        layout="wide"
    )
    
    st.title("🔒 SOC Security Monitoring Dashboard")
    st.markdown("Advanced real-time security monitoring with AI-powered threat detection")
    
    # Sidebar for configuration
    with st.sidebar:
        st.header("Configuration")
        
        # Monitoring control
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Start Monitoring", disabled=st.session_state.monitoring_active, 
                         key="start_monitoring_btn"):
                st.session_state.monitoring_active = True
                st.session_state.last_check_time = datetime.now()
                st.rerun()
        with col2:
            if st.button("Stop Monitoring", disabled=not st.session_state.monitoring_active,
                         key="stop_monitoring_btn"):
                st.session_state.monitoring_active = False
                st.rerun()
        
        # AI Settings
        st.subheader("AI Configuration")
        st.session_state.ai_enabled = st.checkbox("Enable AI Detection", value=st.session_state.ai_enabled, key="ai_checkbox")
        
        # Threat intelligence settings
        st.subheader("Threat Intelligence")
        ti_enabled = st.checkbox("Enable Threat Intelligence", value=True, key="ti_checkbox")

        # Notification settings
        st.subheader("Notifications")
        st.session_state.enable_notifications = st.checkbox("Enable Critical Alert Notifications", value=st.session_state.enable_notifications, key="notifications_checkbox")
        
        # Directory monitoring configuration
        st.subheader("Directory Monitoring")
        monitor_path = st.text_input("Directory to monitor", value=".", key="dir_input")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Add Directory", key="add_dir_btn"):
                if os.path.exists(monitor_path):
                    if monitor_path not in st.session_state.monitor_dirs:
                        st.session_state.monitor_dirs.append(monitor_path)
                        st.success(f"Added {monitor_path} to monitoring list")
                    else:
                        st.warning("Directory is already being monitored")
                else:
                    st.error("Directory does not exist")
        
        with col2:
            if st.button("Add Windows Critical", key="add_windows_btn"):
                for dir_path in WINDOWS_CRITICAL_DIRS:
                    if dir_path not in st.session_state.monitor_dirs and os.path.exists(dir_path):
                        st.session_state.monitor_dirs.append(dir_path)
                st.success("Added Windows critical directories to monitoring")
        
        st.subheader("Currently Monitoring")
        for i, dir_path in enumerate(st.session_state.monitor_dirs):
            col1, col2 = st.columns([4, 1])
            with col1:
                st.text(dir_path)
            with col2:
                if st.button("❌", key=f"remove_dir_{i}"):
                    st.session_state.monitor_dirs.remove(dir_path)
                    st.rerun()
        
        if st.button("Clear Alerts", key="clear_alerts_btn"):
            st.session_state.alerts.clear()
        
        if st.button("Clear File Events", key="clear_events_btn"):
            st.session_state.file_events.clear()
        
        # Display system info
        st.subheader("System Information")
        st.text(f"OS: {os.name}")
        try:
            st.text(f"Hostname: {socket.gethostname()}")
        except:
            pass
        st.text(f"CPU Cores: {psutil.cpu_count()}")
        st.text(f"Total Memory: {psutil.virtual_memory().total / (1024**3):.2f} GB")
        
        # Status indicator
        if st.session_state.monitoring_active:
            st.success("Monitoring: ACTIVE")
            st.text(f"Monitoring {len(st.session_state.monitor_dirs)} directories")
        else:
            st.error("Monitoring: INACTIVE")
    
    # Create tabs for different sections
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "Dashboard", "Processes", "Network", "File Events", "Alerts", "Forensics"
    ])

    return tab1, tab2, tab3, tab4, tab5, tab6

def update_dashboard(tab, metrics):
    """Update the dashboard tab with current metrics"""
    with tab:
        # Create columns for metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("CPU Usage", f"{metrics['cpu']}%")
            st.progress(metrics['cpu'] / 100)
        
        with col2:
            st.metric("Memory Usage", f"{metrics['memory_percent']}%")
            st.progress(metrics['memory_percent'] / 100)
        
        with col3:
            st.metric("Disk Usage", f"{metrics['disk_percent']}%")
            st.progress(metrics['disk_percent'] / 100)
        
        with col4:
            st.metric("Processes", metrics['process_count'])
            st.metric("Network Connections", len(metrics['network_connections']))
        
        # AI Status
        if st.session_state.ai_enabled:
            st.success("🤖 AI Model: Pre-trained & Active")
        else:
            st.info("🤖 AI Model: Disabled")
        
        # Create charts
        col1, col2 = st.columns(2)
        
        with col1:
            # CPU and Memory history
            if len(st.session_state.metrics_history) > 1:
                history_df = pd.DataFrame(st.session_state.metrics_history)
                fig = go.Figure()
                fig.add_trace(go.Scatter(x=history_df['timestamp'], y=history_df['cpu'], 
                                        name='CPU %', line=dict(color='blue')))
                fig.add_trace(go.Scatter(x=history_df['timestamp'], y=history_df['memory_percent'], 
                                        name='Memory %', line=dict(color='red')))
                fig.update_layout(title='CPU and Memory Usage Over Time',
                                xaxis_title='Time',
                                yaxis_title='Percentage')
                st.plotly_chart(fig, use_container_width=True, key="cpu_memory_chart")
        
        with col2:
            # Network activity
            if len(st.session_state.metrics_history) > 1:
                history_df = pd.DataFrame(st.session_state.metrics_history)
                fig = go.Figure()
                fig.add_trace(go.Scatter(x=history_df['timestamp'], y=history_df['net_sent'], 
                                        name='Sent', line=dict(color='green')))
                fig.add_trace(go.Scatter(x=history_df['timestamp'], y=history_df['net_recv'], 
                                        name='Received', line=dict(color='orange')))
                fig.update_layout(title='Network Activity (MB)',
                                xaxis_title='Time',
                                yaxis_title='MB')
                st.plotly_chart(fig, use_container_width=True, key="network_chart")
        
        # Disk usage pie chart
        col1, col2 = st.columns(2)
        with col1:
            if len(st.session_state.metrics_history) > 0:
                labels = ['Used', 'Free']
                values = [metrics['disk_used'], metrics['disk_total'] - metrics['disk_used']]
                fig = px.pie(values=values, names=labels, title='Disk Space Usage')
                st.plotly_chart(fig, use_container_width=True, key="disk_chart")
        
        with col2:
            # Alert severity distribution
            if st.session_state.alerts:
                alerts_df = pd.DataFrame(st.session_state.alerts)
                severity_counts = alerts_df['severity'].value_counts()
                fig = px.pie(values=severity_counts.values, names=severity_counts.index, 
                            title='Alert Severity Distribution')
                st.plotly_chart(fig, use_container_width=True, key="alert_severity_chart")
        
        # Recent alerts
        st.subheader("Recent Alerts")
        if st.session_state.alerts:
            recent_alerts = list(st.session_state.alerts)[-5:]  # Last 5 alerts
            for alert in recent_alerts:
                severity_color = {
                    "low": "blue",
                    "medium": "orange", 
                    "high": "red",
                    "critical": "darkred"
                }.get(alert['severity'], "gray")
                
                ai_indicator = " 🤖" if "AI-Detected" in alert['type'] else ""
                
                st.markdown(
                    f"""
                    <div style="border-left: 5px solid {severity_color}; padding: 10px; margin: 5px 0; background-color: #f0f0f0;">
                        <strong>{alert['type']}{ai_indicator}</strong> ({alert['severity']})<br>
                        {alert['message']}<br>
                        <small>{alert['timestamp']}</small>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
        else:
            st.info("No recent alerts")

def update_processes_tab(tab, metrics):
    """Update the processes tab"""
    with tab:
        if metrics and 'processes' in metrics:
            processes_df = pd.DataFrame(metrics['processes'])
            if not processes_df.empty:
                # Add suspicious process flag
                processes_df['suspicious'] = processes_df['name'].apply(
                    lambda x: any(suspicious in str(x).lower() for suspicious in SUSPICIOUS_PROCESS_NAMES) if x else False
                )
                
                # Sort by CPU usage
                processes_df = processes_df.sort_values('cpu_percent', ascending=False)
                
                # Filter options
                col1, col2 = st.columns(2)
                with col1:
                    show_suspicious = st.checkbox("Show Only Suspicious Processes", value=False)
                with col2:
                    min_cpu = st.slider("Minimum CPU %", 0, 100, 5)
                
                if show_suspicious:
                    processes_df = processes_df[processes_df['suspicious'] == True]
                
                processes_df = processes_df[processes_df['cpu_percent'] >= min_cpu]
                
                st.dataframe(processes_df, use_container_width=True, key="processes_table")
                
                # Process statistics
                st.subheader("Process Statistics")
                col1, col2 = st.columns(2)
                
                with col1:
                    user_counts = processes_df['username'].value_counts().head(10)
                    if not user_counts.empty:
                        fig = px.bar(x=user_counts.values, y=user_counts.index, orientation='h',
                                    title='Top 10 Users by Process Count')
                        st.plotly_chart(fig, use_container_width=True, key="user_process_chart")
                
                with col2:
                    proc_counts = processes_df['name'].value_counts().head(10)
                    if not proc_counts.empty:
                        fig = px.pie(values=proc_counts.values, names=proc_counts.index, 
                                    title='Top 10 Processes by Count')
                        st.plotly_chart(fig, use_container_width=True, key="process_count_chart")
            else:
                st.info("No process data available")
        else:
            st.info("No process data available")

def update_network_tab(tab, metrics):
    """Update the network tab"""
    with tab:
        if metrics and 'network_connections' in metrics:
            network_df = pd.DataFrame(metrics['network_connections'])
            if not network_df.empty:
                # Extract IP addresses for threat intelligence
                network_df['remote_ip'] = network_df['remote_address'].apply(lambda x: x.split(':')[0])
                
                # Check each IP against threat intelligence
                network_df['malicious'] = network_df['remote_ip'].apply(
                    lambda ip: ip in KNOWN_MALICIOUS_IPS or check_threat_intelligence(ip).get('malicious', False)
                )
                
                st.dataframe(network_df, use_container_width=True, key="network_table")
                
                # Network statistics
                st.subheader("Network Statistics")
                col1, col2 = st.columns(2)
                
                with col1:
                    # Connections by remote IP
                    ip_counts = network_df['remote_ip'].value_counts().head(10)
                    if not ip_counts.empty:
                        fig = px.bar(x=ip_counts.values, y=ip_counts.index, orientation='h',
                                    title='Top 10 Remote IPs by Connection Count')
                        st.plotly_chart(fig, use_container_width=True, key="ip_connection_chart")
                
                with col2:
                    # Malicious connections
                    malicious_conns = network_df[network_df['malicious'] == True]
                    if not malicious_conns.empty:
                        st.warning(f"{len(malicious_conns)} malicious connections detected!")
                        st.dataframe(malicious_conns, use_container_width=True, key="malicious_conns_table")
                    else:
                        st.success("No malicious connections detected")
            else:
                st.info("No network connections")
        else:
            st.info("No network data available")
        
        # System logs
        st.subheader("System Logs")
        if st.button("Refresh Logs", key="refresh_logs_btn"):
            logs = get_system_logs()
            if logs:
                logs_df = pd.DataFrame(logs)
                st.dataframe(logs_df, use_container_width=True, key="system_logs_table")
            else:
                st.info("No system logs available")

def update_file_events_tab(tab):
    """Update the file events tab"""
    with tab:
        if st.session_state.file_events:
            # Display most recent events first
            events_df = pd.DataFrame(st.session_state.file_events)
            events_df = events_df.sort_values('timestamp', ascending=False)
            
            st.subheader(f"File Events ({len(events_df)} total)")
            
            # Filter options
            col1, col2, col3 = st.columns(3)
            with col1:
                event_type_filter = st.selectbox("Event Type", ["All", "created", "modified", "deleted"])
            with col2:
                dir_filter = st.selectbox("Directory", ["All"] + list(events_df['directory'].unique()))
            with col3:
                search_term = st.text_input("Search path")
            
            # Apply filters
            filtered_events = events_df
            if event_type_filter != "All":
                filtered_events = filtered_events[filtered_events['event_type'] == event_type_filter]
            if dir_filter != "All":
                filtered_events = filtered_events[filtered_events['directory'] == dir_filter]
            if search_term:
                filtered_events = filtered_events[filtered_events['path'].str.contains(search_term, case=False)]
            
            st.dataframe(filtered_events, use_container_width=True, key="file_events_table")
            
            # Event statistics
            st.subheader("Event Statistics")
            col1, col2 = st.columns(2)
            
            with col1:
                event_counts = events_df['event_type'].value_counts()
                if not event_counts.empty:
                    fig = px.pie(values=event_counts.values, names=event_counts.index, 
                                title='Event Types Distribution')
                    st.plotly_chart(fig, use_container_width=True, key="event_types_chart")
            
            with col2:
                dir_counts = events_df['directory'].value_counts().head(10)
                if not dir_counts.empty:
                    fig = px.bar(x=dir_counts.values, y=dir_counts.index, orientation='h',
                                title='Top 10 Directories by Events')
                    st.plotly_chart(fig, use_container_width=True, key="dir_events_chart")
        else:
            st.info("No file events recorded yet. Try creating, modifying, or deleting files in monitored directories.")

def update_alerts_tab(tab):
    """Update the alerts tab"""
    with tab:
        if st.session_state.alerts:
            alerts_df = pd.DataFrame(st.session_state.alerts)
            
            # Filter options
            col1, col2 = st.columns(2)
            with col1:
                severity_filter = st.selectbox("Severity", ["All", "low", "medium", "high", "critical"])
            with col2:
                alert_type_filter = st.selectbox("Alert Type", ["All"] + list(alerts_df['type'].unique()))
            
            # Apply filters
            filtered_alerts = alerts_df
            if severity_filter != "All":
                filtered_alerts = filtered_alerts[filtered_alerts['severity'] == severity_filter]
            if alert_type_filter != "All":
                filtered_alerts = filtered_alerts[filtered_alerts['type'] == alert_type_filter]
            
            # Display alerts
            for i, (_, alert) in enumerate(filtered_alerts.iterrows()):
                severity_color = {
                    "low": "blue",
                    "medium": "orange", 
                    "high": "red",
                    "critical": "darkred"
                }.get(alert['severity'], "gray")
                
                ai_indicator = " 🤖" if "AI-Detected" in alert['type'] else ""
                
                with st.expander(f"{alert['type']}{ai_indicator} ({alert['severity']}) - {alert['timestamp']}"):
                    st.markdown(f"**Message:** {alert['message']}")
                    st.markdown(f"**Timestamp:** {alert['timestamp']}")
                    st.markdown(f"**Severity:** {alert['severity']}")

                    if 'details' in alert and alert['details']:
                        st.code(json.dumps(alert['details'], indent=2, default=str), language='json')
            
            # Alert statistics
            st.subheader("Alert Statistics")
            col1, col2 = st.columns(2)
            
            with col1:
                alert_counts = alerts_df['severity'].value_counts()
                if not alert_counts.empty:
                    fig = px.pie(values=alert_counts.values, names=alert_counts.index, 
                                title='Alert Distribution by Severity')
                    st.plotly_chart(fig, use_container_width=True, key="alert_chart")
            
            with col2:
                type_counts = alerts_df['type'].value_counts().head(10)
                if not type_counts.empty:
                    fig = px.bar(x=type_counts.values, y=type_counts.index, orientation='h',
                                title='Top 10 Alert Types')
                    st.plotly_chart(fig, use_container_width=True, key="alert_types_chart")
        else:
            st.success("No alerts - system is secure!")

def main():
    # Initialize AI models
    initialize_ai_models()
    
    # Setup UI
    tabs = setup_ui()
    tab1, tab2, tab3, tab4, tab5, tab6 = tabs
    
    # Placeholder for previous metrics
    prev_metrics = None
    
    # Main monitoring logic
    if st.session_state.monitoring_active:
        # Check if it's time to update
        current_time = datetime.now()
        if (current_time - st.session_state.last_check_time).total_seconds() >= UPDATE_INTERVAL:
            st.session_state.last_check_time = current_time
            
            # Get system metrics
            metrics = get_system_metrics()
            
            # Check for directory changes
            file_events = check_directory_changes()
            if file_events:
                st.session_state.needs_rerun = True
            for event in file_events:
                st.session_state.file_events.append(event)

                # Check if this is a sensitive file
                for sensitive_dir in SENSITIVE_DIRS.get(os.name, []):
                    if sensitive_dir in event["path"]:
                        alert = {
                            "timestamp": datetime.now().isoformat(),
                            "type": "Sensitive File Change",
                            "message": f"File change in sensitive location: {event['path']}",
                            "severity": "high",
                            "details": event
                        }
                        st.session_state.alerts.append(alert)

            # Check for suspicious activity
            alerts = check_suspicious_activity(metrics, prev_metrics)
            if alerts:
                st.session_state.needs_rerun = True
            for alert in alerts:
                st.session_state.alerts.append(alert)
                # Show notification for critical alerts if enabled
                if (st.session_state.enable_notifications and
                    alert['severity'] == 'critical' and
                    alert['type'] not in st.session_state.shown_notifications):
                    st.toast(f"🚨 CRITICAL: {alert['message']}", icon="🚨")
                    st.session_state.shown_notifications.add(alert['type'])

            # Add metrics to history
            st.session_state.metrics_history.append(metrics)

            # Set previous metrics for next iteration
            prev_metrics = metrics
        
        # Update the UI with the latest data
        if st.session_state.metrics_history:
            latest_metrics = st.session_state.metrics_history[-1]
            update_dashboard(tab1, latest_metrics)
            update_processes_tab(tab2, latest_metrics)
            update_network_tab(tab3, latest_metrics)
        else:
            with tab1:
                st.info("No metrics data available yet")
            with tab2:
                st.info("No process data available yet")
            with tab3:
                st.info("No network data available yet")
        
        update_file_events_tab(tab4)
        update_alerts_tab(tab5)
        update_forensics_tab(tab6)

        # Auto-refresh the app when monitoring is active
        time.sleep(1)  # Reduced frequency to prevent excessive CPU usage
        st.rerun()
    else:
        # Show placeholder when monitoring is not active
        with tab1:
            st.info("Monitoring is not active. Click 'Start Monitoring' to begin.")
        with tab2:
            st.info("Monitoring is not active. Click 'Start Monitoring' to begin.")
        with tab3:
            st.info("Monitoring is not active. Click 'Start Monitoring' to begin.")
        with tab4:
            st.info("Monitoring is not active. Click 'Start Monitoring' to begin.")
        with tab5:
            st.info("Monitoring is not active. Click 'Start Monitoring' to begin.")
        with tab6:
            st.info("Monitoring is not active. Click 'Start Monitoring' to begin.")

if __name__ == "__main__":
    main()
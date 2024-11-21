from autogen import AssistantAgent, UserProxyAgent
import os
import socket
import psutil
import json
from datetime import datetime
import hashlib
import re

def scan_ports(ip: str, ports: list) -> dict:
    """Actually scan ports on a given IP address"""
    results = {}
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        sock.close()
        results[port] = result == 0
    return results

def get_active_connections() -> list:
    """Get real active network connections"""
    try:
        connections = {}
        # Group connections by process
        for conn in psutil.net_connections(kind='inet'):
            try:
                process_name = psutil.Process(conn.pid).name() if conn.pid else "Unknown"
                if process_name not in connections:
                    connections[process_name] = {
                        'pid': conn.pid,
                        'connections': []
                    }
                
                remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "None"
                connections[process_name]['connections'].append({
                    'local': f"{conn.laddr.ip}:{conn.laddr.port}",
                    'remote': remote_addr,
                    'status': conn.status
                })
            except Exception as e:
                continue
        # Format output more concisely
        return [{
            'process': name,
            'pid': info['pid'],
            'connection_count': len(info['connections']),
            'active_connections': info['connections'][:5],  # Limit to first 5 connections
            'total_established': sum(1 for c in info['connections'] if c['status'] == 'ESTABLISHED')
        } for name, info in connections.items()]
        
    except Exception as e:
        return [{"error": f"Failed to get connections: {str(e)}"}]

def get_process_details(pid: int) -> dict:
    """Get detailed information about a process including file hashes"""
    try:
        process = psutil.Process(pid)
        with open(process.exe(), 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        
        return {
            'pid': pid,
            'name': process.name(),
            'exe': process.exe(),
            'cmdline': process.cmdline(),
            'status': process.status(),
            'cpu_percent': process.cpu_percent(),
            'memory_percent': process.memory_percent(),
            'connections': process.connections(),
            'open_files': process.open_files(),
            'sha256': file_hash,
            'created_time': datetime.fromtimestamp(process.create_time()).isoformat()
        }
    except Exception as e:
        return {"error": f"Failed to analyze process {pid}: {str(e)}"}

def scan_file_for_ioc(file_path: str) -> dict:
    """Scan a file for indicators of compromise"""
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            
        return {
            'sha256': hashlib.sha256(content).hexdigest(),
            'md5': hashlib.md5(content).hexdigest(),
            'file_size': len(content),
            'magic_bytes': content[:4].hex(),
            'strings': [s for s in re.findall(b'[\\x20-\\x7E]{4,}', content)],
            'has_pe_header': content[:2] == b'MZ',
            'creation_time': datetime.fromtimestamp(os.path.getctime(file_path)).isoformat(),
            'modification_time': datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
        }
    except Exception as e:
        return {"error": f"Failed to analyze file {file_path}: {str(e)}"}

def create_security_agents():
    llm_config = {
        "config_list": [{
            "model": "gpt-4",
            "api_key": os.environ.get("OPENAI_API_KEY")
        }],
        "functions": [{
            "name": "scan_ports",
            "description": "Scan specific ports on an IP address",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "IP address to scan"
                    },
                    "ports": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "List of ports to scan"
                    }
                },
                "required": ["ip", "ports"]
            }
        }, {
            "name": "get_active_connections",
            "description": "Get list of all active network connections",
            "parameters": {
                "type": "object",
                "properties": {}
            }
        }, {
            "name": "get_process_details",
            "description": "Get detailed information about a process including file hashes",
            "parameters": {
                "type": "object",
                "properties": {
                    "pid": {
                        "type": "integer",
                        "description": "Process ID to analyze"
                    }
                },
                "required": ["pid"]
            }
        }, {
            "name": "scan_file_for_ioc",
            "description": "Scan a file for indicators of compromise",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the file to analyze"
                    }
                },
                "required": ["file_path"]
            }
        }]
    }

    network_monitor = AssistantAgent(
        name="NetworkMonitor",
        llm_config=llm_config,
        system_message="""You are a network security specialist with access to real network monitoring capabilities:
        
        1. Use scan_ports(ip, ports) to check for open ports on suspicious IPs
           - Common ports to check: 20-23 (FTP/Telnet), 80/443 (HTTP/S), 3389 (RDP), 22 (SSH)
           
        2. Use get_active_connections() to analyze current network connections
           - Look for suspicious remote addresses
           - Check for unusual port numbers
           - Monitor connection states
        
        When investigating:
        1. Always check both open ports AND active connections
        2. Report specific findings with timestamps
        3. Flag any suspicious patterns
        4. Make clear recommendations""",
        function_map={
            "scan_ports": scan_ports,
            "get_active_connections": get_active_connections
        }
    )

    security_admin = UserProxyAgent(
        name="SecurityAdmin",
        llm_config=llm_config,
        system_message="""You are the security administrator. Based on NetworkMonitor's findings:
        1. Evaluate the severity of detected issues
        2. Recommend specific actions (block IPs, close ports, terminate processes)
        3. Document all decisions with justification
        4. Determine if incident needs escalation""",
        human_input_mode="NEVER"
    )


    malware_analyst = AssistantAgent(
        name="MalwareAnalyst",
        llm_config=llm_config,
        system_message="""You are a malware analysis specialist. Your responsibilities:

        1. Analyze suspicious processes:
           - Check process behavior and relationships
           - Examine file hashes against known malware databases
           - Monitor unusual system calls or network connections
           - Identify potential process injection or hollowing

        2. Investigate suspicious files:
           - Analyze file characteristics and magic bytes
           - Check for known malicious indicators
           - Identify potentially obfuscated code or suspicious strings
           - Look for signs of packed or encrypted malware

        3. Correlate with network activity:
           - Link suspicious processes to network connections
           - Identify command & control (C2) patterns
           - Detect data exfiltration attempts

        When suspicious activity is found:
        1. Document all IOCs (Indicators of Compromise)
        2. Determine malware family if possible
        3. Recommend immediate containment steps
        4. Provide remediation guidance""",
        function_map={
            "get_process_details": get_process_details,
            "scan_file_for_ioc": scan_file_for_ioc
        }
    )

    return {
        "network_monitor": network_monitor,
        "malware_analyst": malware_analyst,
        "security_admin": security_admin
    } 
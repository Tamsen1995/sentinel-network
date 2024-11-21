from autogen import AssistantAgent, UserProxyAgent
import os
import socket
import psutil
import json
from datetime import datetime

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
        connections = []
        for conn in psutil.net_connections(kind='inet'):
            try:
                connections.append({
                    'timestamp': datetime.now().isoformat(),
                    'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                    'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status,
                    'pid': conn.pid,
                    'process_name': psutil.Process(conn.pid).name() if conn.pid else None
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return connections
    except Exception as e:
        return [{"error": f"Failed to get connections: {str(e)}"}]

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

    return {
        "network_monitor": network_monitor,
        "security_admin": security_admin
    } 
import os
import logging
from dotenv import load_dotenv
from agents import create_security_agents
from handlers import SecurityIncidentHandler

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)

def main():
    # Create security agents
    agents = create_security_agents()
    
    # Initialize incident handler
    incident_handler = SecurityIncidentHandler(agents)
    
    # Test with a sample incident
    sample_incident = {
        "type": "Network Scan",
        "source": "External IP: 192.168.1.100",
        "severity": "High",
        "details": "Multiple port scans detected in last 5 minutes"
    }
    
    # Handle the incident
    incident_handler.handle_incident(sample_incident)

if __name__ == "__main__":
    main() 
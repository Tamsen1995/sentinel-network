from autogen import GroupChat, GroupChatManager
import logging
import os

class SecurityIncidentHandler:
    def __init__(self, agents):
        self.agents = agents
        self.setup_group_chat()

    def setup_group_chat(self):
        # Basic LLM config for the group chat manager
        llm_config = {
            "config_list": [{
                "model": "gpt-4",
                "api_key": os.environ.get("OPENAI_API_KEY")
            }]
        }

  
        self.security_team = GroupChat(
            agents=list(self.agents.values()),
            messages=[],
            max_round=5,
            speaker_selection_method="round_robin",
            allow_repeat_speaker=False
        )
        
        self.manager = GroupChatManager(
            groupchat=self.security_team,
            llm_config=llm_config
        )

    def handle_incident(self, incident_data: dict):
        try:
            incident_message = f"""SECURITY INCIDENT REPORT
Type: {incident_data.get('type')}
Source: {incident_data.get('source')}
Severity: {incident_data.get('severity')}
Details: {incident_data.get('details')}

Required Actions:
1. NetworkMonitor: Analyze the security incident and provide initial assessment
2. MalwareAnalyst: Investigate associated processes and files for malicious indicator
3. SecurityAdmin: Review findings and recommend specific actions

Please proceed with the investigation."""
            
            self.manager.initiate_chat(
                self.agents["network_monitor"],
                message=incident_message
            )
            
        except Exception as e:
            logging.error(f"Error handling security incident: {str(e)}") 
import os
import json
import logging
try:
    import google.generativeai as genai
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False
import sqlite3

logger = logging.getLogger("RAGEngine")

class RAGEngine:
    def __init__(self, db_path):
        self.db_path = db_path
        self.api_key = None
        self.model = None

    def configure(self, api_key):
        if not GENAI_AVAILABLE:
            logger.error("google-generativeai is not installed.")
            return False
            
        if not api_key:
            return False
            
        try:
            genai.configure(api_key=api_key)
            # Use gemini-1.5-flash for fast and cost-effective text generation
            self.model = genai.GenerativeModel('gemini-1.5-flash')
            self.api_key = api_key
            logger.info("RAG Engine configured successfully with Gemini API.")
            return True
        except Exception as e:
            logger.error(f"Failed to configure Gemini API: {e}")
            return False

    def is_ready(self):
        return self.model is not None

    def _get_recent_alerts_context(self, limit=50):
        """Fetches recent alerts to provide context for the LLM."""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT timestamp, alert_type, severity, source_ip, dest_ip, description FROM alerts ORDER BY timestamp DESC LIMIT ?", 
                (limit,)
            ).fetchall()
            conn.close()
            
            if not rows:
                return "No recent alerts found in the database."
                
            context = "Recent Network Alerts:\n"
            for row in rows:
                context += f"- [{row['timestamp']}] {row['severity']} | {row['alert_type']} | Src: {row['source_ip']} | Dst: {row['dest_ip']} | {row['description']}\n"
            return context
        except Exception as e:
            logger.error(f"Error fetching alerts context: {e}")
            return "Error retrieving context from database."

    def analyze_alert(self, alert_data):
        """Analyzes a specific alert using the LLM."""
        if not self.is_ready():
            return {"error": "RAG Engine is not configured. Please add Gemini API Key in settings."}

        # Fetch recent alerts as context to see if this is part of a larger pattern
        context = self._get_recent_alerts_context(limit=20)
        
        prompt = f"""
        You are an expert Security Operations Center (SOC) AI Assistant.
        Please analyze the following network intrusion alert and provide a brief threat assessment and recommended mitigation steps.
        
        [Target Alert to Analyze]
        Type: {alert_data.get('alert_type')}
        Severity: {alert_data.get('severity')}
        Source IP: {alert_data.get('source_ip')}
        Destination IP: {alert_data.get('dest_ip')}
        Description: {alert_data.get('description')}
        Time: {alert_data.get('timestamp')}
        
        [Additional Network Context (Recent Alerts)]
        {context}
        
        Provide the response in the following structured Markdown format:
        **Threat Assessment:** (Brief 2-3 sentence analysis of what is likely happening, correlating with recent alerts if relevant)
        
        **Actionable Mitigation:** (Specific steps the analyst or system should take, e.g., iptables rules, network isolation)
        """
        
        try:
            response = self.model.generate_content(prompt)
            return {"analysis": response.text}
        except Exception as e:
            logger.error(f"Error generating alert analysis: {e}")
            return {"error": str(e)}

    def chat(self, user_query):
        """Answers a user's SOC query using recent alerts as context."""
        if not self.is_ready():
            return {"error": "RAG Engine is not configured. Please add Gemini API Key in settings."}

        context = self._get_recent_alerts_context(limit=100)
        
        prompt = f"""
        You are an expert Security Operations Center (SOC) AI Assistant responding to a security analyst.
        You have access to the recent network alerts context below.
        
        [Recent Network Alerts Context]
        {context}
        
        Analyst Query: "{user_query}"
        
        Please provide a concise, accurate, and helpful response to the analyst's query based ONLY on the provided context (if applicable) and your general cybersecurity knowledge. Use Markdown for formatting.
        """
        
        try:
            response = self.model.generate_content(prompt)
            return {"response": response.text}
        except Exception as e:
            logger.error(f"Error generating chat response: {e}")
            return {"error": str(e)}

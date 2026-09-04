import requests
import json
import re

class AIAnalyzer:
    def __init__(self, model="llama3.2"):
        """Initialize with local Ollama model"""
        self.model = model
        self.ollama_url = "http://localhost:11434/api/chat"
        self.fallback_enabled = True

    def analyze_threat(self, threat_data):
        """Analyze threat using local Ollama model with detailed recommendations"""
        try:
            prompt = self._build_detailed_prompt(threat_data)
            
            response = requests.post(
                self.ollama_url,
                json={
                    "model": self.model,
                    "messages": [
                        {
                            "role": "system", 
                            "content": """You are a senior cybersecurity analyst with 10+ years of experience. 
                            Provide detailed, actionable threat analysis. Always return valid JSON with these exact keys:
                            - explanation: Detailed explanation of the threat
                            - risk_assessment: Impact assessment with severity level
                            - recommendations: Bullet points of specific actions
                            - additional_context: Industry context and best practices
                            - immediate_actions: First 5 minutes response actions
                            - long_term_actions: Prevention measures"""
                        },
                        {
                            "role": "user", 
                            "content": prompt
                        }
                    ],
                    "stream": False,
                    "temperature": 0.3
                },
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                analysis_text = result.get("message", {}).get("content", "")
                return self._parse_detailed_analysis(analysis_text)
            else:
                return self._get_detailed_fallback(threat_data)
                
        except requests.exceptions.ConnectionError:
            return self._get_detailed_fallback(threat_data)
        except Exception as e:
            print(f"Error analyzing threat: {e}")
            return self._get_detailed_fallback(threat_data)

    def _build_detailed_prompt(self, threat_data):
        """Build detailed structured prompt for local model"""
        prompt = f"""Analyze this security incident and provide detailed cybersecurity recommendations.

Security Event Details:
- Threat Type: {threat_data.get('type', 'Unknown')}
- Severity Level: {threat_data.get('severity', 'Unknown')}
- Source IP: {threat_data.get('source_ip', 'Unknown')}
- Details: {threat_data.get('details', 'No details available')}

Provide a comprehensive analysis in valid JSON format with these exact keys:
1. "explanation": Detailed explanation of the threat, attack vector, and potential impact
2. "risk_assessment": Risk level, affected systems, and business impact
3. "recommendations": Specific, actionable steps (as a string with bullet points)
4. "immediate_actions": What to do in the first 5-10 minutes (as a string with bullet points)
5. "long_term_actions": Prevention and mitigation strategies (as a string with bullet points)
6. "additional_context": Industry best practices, related attack patterns, and references

Return ONLY valid JSON. Example format:
{{
    "explanation": "This SQL injection attempt targets the login form, attempting to bypass authentication by manipulating the WHERE clause. If successful, the attacker could gain unauthorized access without valid credentials.",
    "risk_assessment": "CRITICAL - Database compromise, data breach, unauthorized access to sensitive data",
    "recommendations": "- Immediately block the source IP at the firewall\n- Conduct a thorough review of all login forms for SQL injection vulnerabilities\n- Implement input validation and parameterized queries\n- Enable detailed logging for all authentication attempts",
    "immediate_actions": "- Block IP 192.168.1.50 at the network level\n- Review recent database queries for anomalies\n- Check for any successful unauthorized access\n- Escalate to incident response team",
    "long_term_actions": "- Implement Web Application Firewall (WAF)\n- Regular security scanning and penetration testing\n- Developer training on secure coding practices\n- Implement Least Privilege access control",
    "additional_context": "SQL injection remains one of the OWASP Top 10 vulnerabilities. Attackers often use automated tools to find injection points. Implementation of prepared statements is the most effective prevention."
}}"""
        return prompt

    def _parse_detailed_analysis(self, analysis_text):
        """Parse detailed AI response into structured format"""
        try:
            json_match = re.search(r'\{.*\}', analysis_text, re.DOTALL)
            if json_match:
                json_str = json_match.group()
                json_str = re.sub(r'```json\s*', '', json_str)
                json_str = re.sub(r'```\s*', '', json_str)
                data = json.loads(json_str)
                
                return {
                    'explanation': data.get('explanation', 'Detailed analysis available.'),
                    'risk_assessment': data.get('risk_assessment', 'Risk assessment completed.'),
                    'recommendations': data.get('recommendations', 'Follow standard security procedures.'),
                    'immediate_actions': data.get('immediate_actions', 'Block IP and investigate.'),
                    'long_term_actions': data.get('long_term_actions', 'Implement security best practices.'),
                    'additional_context': data.get('additional_context', ''),
                    'full_analysis': analysis_text
                }
            else:
                return self._get_detailed_fallback({})
        except json.JSONDecodeError:
            return self._get_detailed_fallback({})

    def _get_detailed_fallback(self, threat_data):
        """Provide detailed fallback analysis"""
        threat_type = threat_data.get('type', 'security')
        source_ip = threat_data.get('source_ip', 'unknown')
        
        return {
            'explanation': f"A {threat_type} was detected from IP {source_ip}. This requires immediate investigation to prevent potential security breaches.",
            'risk_assessment': f"High risk - The {threat_type} indicates active targeting of your systems. Potential for data breach or system compromise.",
            'recommendations': f"""- Immediately block source IP {source_ip}
- Review relevant logs for related activities
- Implement additional monitoring for this threat type
- Escalate to security team for investigation""",
            'immediate_actions': f"""- Block IP {source_ip} at firewall
- Check for any successful exploitation
- Enable verbose logging for this source
- Notify security team""",
            'long_term_actions': """- Conduct security audit
- Implement preventive controls
- Regular security training for team
- Update incident response playbook""",
            'additional_context': "This type of attack is common in targeted campaigns. Timely response is critical to prevent escalation.",
            'full_analysis': "Detailed AI analysis not available. Following standard security procedures recommended."
        }

    def generate_threat_summary(self, threat_data):
        """Generate concise threat summary"""
        try:
            prompt = f"""Create a ONE SENTENCE summary of this security threat:

Threat: {threat_data.get('type', 'Unknown')}
Source: {threat_data.get('source_ip', 'Unknown')}
Severity: {threat_data.get('severity', 'Unknown')}
Details: {threat_data.get('details', '')}

Return ONLY one sentence summary, no extra text."""
            
            response = requests.post(
                self.ollama_url,
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "user", "content": prompt}
                    ],
                    "stream": False,
                    "temperature": 0.2
                },
                timeout=20
            )
            
            if response.status_code == 200:
                result = response.json()
                summary = result.get("message", {}).get("content", "")
                return summary[:150]
            else:
                return f"Security alert: {threat_data.get('type', 'Threat')} detected from {threat_data.get('source_ip', 'unknown')}."
                
        except:
            return f"Security alert: {threat_data.get('type', 'Threat')} detected from {threat_data.get('source_ip', 'unknown')}."
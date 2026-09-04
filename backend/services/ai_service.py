import openai
import requests
import json
import re
from config import Config
import logging

logger = logging.getLogger(__name__)

class AIService:
    """AI Service for threat analysis"""
    
    def __init__(self):
        self.provider = Config.AI_PROVIDER
        self.openai_api_key = Config.OPENAI_API_KEY
        self.openai_model = Config.OPENAI_MODEL
        self.ollama_url = Config.OLLAMA_URL
        self.ollama_model = Config.OLLAMA_MODEL
        self.max_tokens = Config.OPENAI_MAX_TOKENS
        self.temperature = Config.OPENAI_TEMPERATURE
        
        if self.provider == 'openai' and self.openai_api_key:
            openai.api_key = self.openai_api_key
    
    def analyze_threat(self, threat_data):
        """Analyze a threat using the configured AI provider"""
        if self.provider == 'openai':
            return self._analyze_with_openai(threat_data)
        else:
            return self._analyze_with_ollama(threat_data)
    
    def _analyze_with_openai(self, threat_data):
        """Analyze threat using OpenAI API"""
        try:
            prompt = self._build_prompt(threat_data)
            
            response = openai.ChatCompletion.create(
                model=self.openai_model,
                messages=[
                    {
                        "role": "system",
                        "content": """You are a senior cybersecurity analyst with 10+ years of experience. 
                        Analyze the security event and provide detailed, actionable insights.
                        Return your response as valid JSON with these exact keys:
                        - explanation: Detailed explanation of the threat
                        - risk_assessment: Impact assessment with severity
                        - recommendations: Specific actions to take
                        - immediate_actions: First 5-10 minutes response
                        - long_term_actions: Prevention and mitigation
                        - additional_context: Industry context and best practices"""
                    },
                    {"role": "user", "content": prompt}
                ],
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                timeout=30
            )
            
            analysis_text = response.choices[0].message.content.strip()
            return self._parse_analysis(analysis_text)
            
        except openai.error.AuthenticationError:
            logger.error("OpenAI authentication failed - check API key")
            return self._get_fallback_analysis(threat_data, "OpenAI API key is invalid")
        except openai.error.RateLimitError:
            logger.error("OpenAI rate limit exceeded")
            return self._get_fallback_analysis(threat_data, "Rate limit exceeded")
        except openai.error.Timeout:
            logger.error("OpenAI request timeout")
            return self._get_fallback_analysis(threat_data, "Request timeout")
        except Exception as e:
            logger.error(f"OpenAI analysis error: {e}")
            return self._get_fallback_analysis(threat_data, str(e))
    
    def _analyze_with_ollama(self, threat_data):
        """Analyze threat using local Ollama"""
        try:
            prompt = self._build_prompt(threat_data)
            
            response = requests.post(
                f"{self.ollama_url}/api/chat",
                json={
                    "model": self.ollama_model,
                    "messages": [
                        {
                            "role": "system",
                            "content": """You are a senior cybersecurity analyst. Return your analysis as valid JSON with these exact keys:
                            - explanation, risk_assessment, recommendations, immediate_actions, long_term_actions, additional_context"""
                        },
                        {"role": "user", "content": prompt}
                    ],
                    "stream": False,
                    "temperature": 0.3
                },
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                analysis_text = result.get("message", {}).get("content", "")
                return self._parse_analysis(analysis_text)
            else:
                logger.error(f"Ollama error: {response.status_code}")
                return self._get_fallback_analysis(threat_data, f"Ollama error: {response.status_code}")
                
        except requests.exceptions.ConnectionError:
            logger.error("Ollama not running - start with 'ollama serve'")
            return self._get_fallback_analysis(threat_data, "Ollama is not running")
        except requests.exceptions.Timeout:
            logger.error("Ollama request timeout")
            return self._get_fallback_analysis(threat_data, "Request timeout")
        except Exception as e:
            logger.error(f"Ollama analysis error: {e}")
            return self._get_fallback_analysis(threat_data, str(e))
    
    def _build_prompt(self, threat_data):
        """Build the analysis prompt"""
        return f"""
        Analyze this security event and provide detailed recommendations:

        Security Event Details:
        - Threat Type: {threat_data.get('type', 'Unknown')}
        - Severity: {threat_data.get('severity', 'Unknown')}
        - Source IP: {threat_data.get('source_ip', 'Unknown')}
        - Details: {threat_data.get('details', 'No details available')}
        - Confidence: {threat_data.get('confidence', 0)}%

        Provide a comprehensive analysis with actionable recommendations.
        """
    
    def _parse_analysis(self, analysis_text):
        """Parse AI response into structured format"""
        try:
            # Try to extract JSON
            json_match = re.search(r'\{.*\}', analysis_text, re.DOTALL)
            if json_match:
                json_str = json_match.group()
                json_str = re.sub(r'```json\s*', '', json_str)
                json_str = re.sub(r'```\s*', '', json_str)
                data = json.loads(json_str)
                
                return {
                    'explanation': data.get('explanation', 'Analysis completed.'),
                    'risk_assessment': data.get('risk_assessment', 'Risk assessment available.'),
                    'recommendations': data.get('recommendations', 'Follow standard security procedures.'),
                    'immediate_actions': data.get('immediate_actions', 'Immediate action required.'),
                    'long_term_actions': data.get('long_term_actions', 'Long-term prevention needed.'),
                    'additional_context': data.get('additional_context', ''),
                    'full_analysis': analysis_text
                }
            else:
                return self._get_fallback_analysis({}, "Unable to parse AI response")
        except json.JSONDecodeError:
            return self._get_fallback_analysis({}, "Invalid JSON response")
    
    def _get_fallback_analysis(self, threat_data, error_message=None):
        """Provide fallback analysis when AI is unavailable"""
        threat_type = threat_data.get('type', 'security')
        source_ip = threat_data.get('source_ip', 'unknown')
        severity = threat_data.get('severity', 'Medium')
        
        explanation = f"A {threat_type} was detected from IP {source_ip}."
        if error_message:
            explanation += f" AI analysis unavailable: {error_message}"
        
        return {
            'explanation': explanation,
            'risk_assessment': f"{severity} risk requiring investigation.",
            'recommendations': f"Block IP {source_ip} and investigate the activity.",
            'immediate_actions': f"Block IP {source_ip}, review logs, and escalate to security team.",
            'long_term_actions': "Implement preventive controls and monitor for recurrence.",
            'additional_context': "Manual investigation recommended.",
            'full_analysis': f"AI analysis unavailable. Fallback response used. Reason: {error_message or 'Service unavailable'}"
        }
    
    def generate_summary(self, threat_data):
        """Generate a concise threat summary"""
        if self.provider == 'openai':
            return self._generate_summary_openai(threat_data)
        else:
            return self._generate_summary_ollama(threat_data)
    
    def _generate_summary_openai(self, threat_data):
        """Generate summary using OpenAI"""
        try:
            prompt = f"Create a ONE SENTENCE summary of this threat: {threat_data.get('type', 'Threat')} from {threat_data.get('source_ip', 'unknown')}. Severity: {threat_data.get('severity', 'Medium')}."
            
            response = openai.ChatCompletion.create(
                model=self.openai_model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity analyst."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=60,
                temperature=0.2,
                timeout=15
            )
            
            return response.choices[0].message.content.strip()[:200]
        except:
            return f"Security alert: {threat_data.get('type', 'Threat')} detected from {threat_data.get('source_ip', 'unknown')}"
    
    def _generate_summary_ollama(self, threat_data):
        """Generate summary using Ollama"""
        try:
            prompt = f"One sentence summary of {threat_data.get('type', 'Threat')} from {threat_data.get('source_ip', 'unknown')}. Severity: {threat_data.get('severity', 'Medium')}."
            
            response = requests.post(
                f"{self.ollama_url}/api/chat",
                json={
                    "model": self.ollama_model,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                    "temperature": 0.2
                },
                timeout=15
            )
            
            if response.status_code == 200:
                result = response.json()
                return result.get("message", {}).get("content", "")[:200]
        except:
            pass
        
        return f"Security alert: {threat_data.get('type', 'Threat')} detected from {threat_data.get('source_ip', 'unknown')}"
import requests
import json

def test_ollama():
    """Test if Ollama is working"""
    
    # Test 1: Check if Ollama is running
    try:
        response = requests.get("http://localhost:11434/api/tags")
        if response.status_code == 200:
            models = response.json()
            print("✅ Ollama is running!")
            print("📦 Available models:", [m['name'] for m in models.get('models', [])])
        else:
            print("❌ Ollama not responding")
            return
    except:
        print("❌ Ollama is not running. Please start Ollama first.")
        print("   Run: ollama serve")
        return
    
    # Test 2: Send a test query
    print("\n🧪 Testing AI analysis...")
    
    test_threat = {
        'type': 'Brute Force Attack',
        'severity': 'High',
        'source_ip': '192.168.1.100',
        'details': '5 failed login attempts in 2 minutes'
    }
    
    try:
        response = requests.post(
            "http://localhost:11434/api/chat",
            json={
                "model": "llama3.2",
                "messages": [
                    {
                        "role": "system", 
                        "content": "You are a cybersecurity expert. Analyze threats professionally."
                    },
                    {
                        "role": "user",
                        "content": f"Analyze this threat: {json.dumps(test_threat)}. Return analysis in 2-3 sentences."
                    }
                ],
                "stream": False
            },
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            analysis = result.get("message", {}).get("content", "")
            print("✅ AI Analysis:")
            print("-" * 50)
            print(analysis)
            print("-" * 50)
        else:
            print(f"❌ Error: {response.status_code}")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    test_ollama()
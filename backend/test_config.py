from config import Config

print("=" * 50)
print("CONFIGURATION CHECK")
print("=" * 50)

print(f"AI Provider: {Config.AI_PROVIDER}")
print(f"Ollama URL: {Config.OLLAMA_URL}")
print(f"Ollama Model: {Config.OLLAMA_MODEL}")
print(f"MongoDB URI: {Config.MONGO_URI}")
print(f"MongoDB DB: {Config.MONGO_DB_NAME}")
print(f"Brute Force Threshold: {Config.BRUTE_FORCE_THRESHOLD}")
print(f"Brute Force Window: {Config.BRUTE_FORCE_WINDOW_MINUTES} minutes")
print(f"Port Scan Threshold: {Config.PORT_SCAN_THRESHOLD}")
print(f"CORS Origins: {Config.CORS_ORIGINS}")

print("=" * 50)
print("OpenAI Config (if using):")
print(f"API Key: {'✅ Set' if Config.OPENAI_API_KEY else '❌ Not Set'}")
print(f"Model: {Config.OPENAI_MODEL}")
print("=" * 50)
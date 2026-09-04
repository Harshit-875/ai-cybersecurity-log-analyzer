from database.mongo_db import MongoDB
from config import Config

print("MongoDB URI:", Config.MONGO_URI)
print("Database Name:", Config.MONGO_DB_NAME)

mongo = MongoDB()
if mongo.is_connected():
    print("✅ MongoDB connected successfully!")
    print(f"📁 Database: {mongo.db.name}")
    print(f"📊 Collections: {mongo.db.list_collection_names()}")
else:
    print("❌ MongoDB not connected")
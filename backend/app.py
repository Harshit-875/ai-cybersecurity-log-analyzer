from flask import Flask
from flask_cors import CORS
from routes.log_routes import log_bp
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

# Register blueprints
app.register_blueprint(log_bp, url_prefix='/api')

@app.route('/')
def index():
    return {"message": "AI Cybersecurity Log Analyzer API"}

if __name__ == '__main__':
    app.run(debug=True, port=5000)
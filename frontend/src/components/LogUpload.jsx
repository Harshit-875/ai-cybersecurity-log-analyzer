import React, { useState } from 'react';
import axios from 'axios';
import toast, { Toaster } from 'react-hot-toast';

function LogUpload({ onAnalysisComplete }) {
  const [logText, setLogText] = useState('');
  const [loading, setLoading] = useState(false);
  const [fileName, setFileName] = useState('');

  const handleFileUpload = (event) => {
    const file = event.target.files[0];
    if (file) {
      setFileName(file.name);
      const reader = new FileReader();
      reader.onload = (e) => {
        setLogText(e.target.result);
        toast.success(`File loaded: ${file.name}`);
      };
      reader.readAsText(file);
    }
  };

  const handleAnalyze = async () => {
    if (!logText.trim()) {
      toast.error('Please enter or upload log data');
      return;
    }

    setLoading(true);
    try {
      const response = await axios.post('http://localhost:5000/api/analyze', {
        logs: logText
      });

      if (response.data.status === 'success') {
        toast.success('Analysis complete!');
        onAnalysisComplete(response.data);
      } else {
        toast.error('Analysis failed');
      }
    } catch (error) {
      console.error('Analysis error:', error);
      if (error.code === 'ECONNREFUSED') {
        toast.error('Backend not running. Please start Flask server.');
      } else {
        toast.error('Error analyzing logs. Check console for details.');
      }
    } finally {
      setLoading(false);
    }
  };

  const sampleLogs = `2026-09-03 18:42:10 IP=192.168.1.100 user=admin status=401 Failed login attempt
2026-09-03 18:42:12 IP=192.168.1.100 user=admin status=401 Failed login attempt
2026-09-03 18:42:14 IP=192.168.1.100 user=admin status=401 Failed login attempt
2026-09-03 18:42:16 IP=192.168.1.100 user=admin status=401 Failed login attempt
2026-09-03 18:42:18 IP=192.168.1.100 user=admin status=401 Failed login attempt
2026-09-03 18:43:22 IP=10.0.0.50 GET /login?id=' OR '1'='1' -- 
2026-09-03 18:44:15 IP=192.168.1.200 user=john status=200 Login successful
2026-09-03 18:45:30 IP=10.0.0.50 GET /search?q=<script>alert('XSS')</script>
2026-09-03 18:46:10 IP=192.168.1.100 Connection to port 22
2026-09-03 18:46:11 IP=192.168.1.100 Connection to port 23
2026-09-03 18:46:12 IP=192.168.1.100 Connection to port 25
2026-09-03 18:46:13 IP=192.168.1.100 Connection to port 80
2026-09-03 18:46:14 IP=192.168.1.100 Connection to port 443`;

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <Toaster position="top-right" />
      <h2 className="text-2xl font-bold mb-4">📤 Upload Log Files</h2>
      
      <div className="space-y-4">
        {/* File Upload Area */}
        <div className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center hover:border-blue-500 transition">
          <input
            type="file"
            id="file-upload"
            className="hidden"
            onChange={handleFileUpload}
            accept=".log,.txt,.csv"
          />
          <label htmlFor="file-upload" className="cursor-pointer">
            <div className="text-4xl mb-2">📁</div>
            <p className="text-gray-600">Click to upload or drag and drop</p>
            <p className="text-gray-400 text-sm">Supports .log, .txt, .csv files</p>
            {fileName && (
              <p className="text-green-600 mt-2">✓ {fileName}</p>
            )}
          </label>
        </div>

        {/* Or manual input */}
        <div>
          <p className="text-gray-600 mb-2">Or paste your logs manually:</p>
          <textarea
            className="w-full h-48 p-4 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent font-mono text-sm"
            placeholder="Paste your log entries here..."
            value={logText}
            onChange={(e) => setLogText(e.target.value)}
          />
        </div>

        {/* Sample logs button */}
        <div>
          <button
            onClick={() => setLogText(sampleLogs)}
            className="text-blue-600 hover:text-blue-800 text-sm underline"
          >
            Load Sample Logs
          </button>
        </div>

        {/* Analyze Button */}
        <button
          onClick={handleAnalyze}
          disabled={loading || !logText.trim()}
          className={`w-full py-3 rounded-lg font-semibold transition ${
            loading || !logText.trim()
              ? 'bg-gray-300 text-gray-500 cursor-not-allowed'
              : 'bg-blue-600 text-white hover:bg-blue-700'
          }`}
        >
          {loading ? (
            <span className="flex items-center justify-center">
              <svg className="animate-spin h-5 w-5 mr-3 text-white" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
              </svg>
              Analyzing...
            </span>
          ) : (
            '🔍 Analyze Logs'
          )}
        </button>
      </div>
    </div>
  );
}

export default LogUpload;
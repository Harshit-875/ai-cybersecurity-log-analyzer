import React, { useState } from 'react';
import Dashboard from './components/Dashboard';
import LogUpload from './components/LogUpload';
import ThreatList from './components/ThreatList';

function App() {
  const [activeTab, setActiveTab] = useState('upload');
  const [analyzedData, setAnalyzedData] = useState(null);

  const handleAnalysisComplete = (data) => {
    setAnalyzedData(data);
    setActiveTab('results');
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="bg-gray-900 text-white p-6 shadow-lg">
        <div className="container mx-auto">
          <h1 className="text-3xl font-bold">🔒 Cybersecurity Log Analyzer</h1>
          <p className="text-gray-400 mt-2">AI-Powered Threat Detection System</p>
        </div>
      </header>

      <div className="container mx-auto p-6">
        {/* Navigation Tabs */}
        <div className="flex space-x-4 mb-6 bg-white rounded-lg shadow p-2">
          <button
            onClick={() => setActiveTab('upload')}
            className={`px-6 py-2 rounded-lg transition ${
              activeTab === 'upload' 
                ? 'bg-blue-600 text-white' 
                : 'hover:bg-gray-100'
            }`}
          >
            📤 Upload Logs
          </button>
          <button
            onClick={() => setActiveTab('results')}
            className={`px-6 py-2 rounded-lg transition ${
              activeTab === 'results' 
                ? 'bg-blue-600 text-white' 
                : 'hover:bg-gray-100'
            }`}
          >
            📊 Results
          </button>
        </div>

        {/* Content */}
        {activeTab === 'upload' && (
          <LogUpload onAnalysisComplete={handleAnalysisComplete} />
        )}
        
        {activeTab === 'results' && analyzedData && (
          <>
            <Dashboard data={analyzedData} />
            <div className="mt-8">
              <ThreatList threats={analyzedData.data || []} />
            </div>
          </>
        )}

        {activeTab === 'results' && !analyzedData && (
          <div className="bg-white rounded-lg shadow p-12 text-center">
            <p className="text-gray-500">No analysis results yet. Upload logs to get started.</p>
            <button
              onClick={() => setActiveTab('upload')}
              className="mt-4 px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
            >
              Upload Logs
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
import React, { useState } from 'react';

function ThreatList({ threats }) {
  const [filter, setFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [expandedThreat, setExpandedThreat] = useState(null);

  const getSeverityColor = (severity) => {
    const colors = {
      'Critical': 'bg-red-600',
      'High': 'bg-orange-500',
      'Medium': 'bg-yellow-500',
      'Low': 'bg-green-500'
    };
    return colors[severity] || 'bg-gray-500';
  };

  const getSeverityBadgeColor = (severity) => {
    const colors = {
      'Critical': 'bg-red-100 text-red-800 border-red-300',
      'High': 'bg-orange-100 text-orange-800 border-orange-300',
      'Medium': 'bg-yellow-100 text-yellow-800 border-yellow-300',
      'Low': 'bg-green-100 text-green-800 border-green-300'
    };
    return colors[severity] || 'bg-gray-100 text-gray-800 border-gray-300';
  };

  const getSeverityIcon = (severity) => {
    const icons = {
      'Critical': '🔴',
      'High': '🟠',
      'Medium': '🟡',
      'Low': '🟢'
    };
    return icons[severity] || '⚪';
  };

  const filteredThreats = threats.filter(threat => {
    const matchesFilter = filter === 'all' || threat.severity === filter;
    const matchesSearch = threat.threat_type?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      threat.source_ip?.includes(searchTerm) ||
      threat.summary?.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesFilter && matchesSearch;
  });

  const totalThreats = threats.filter(t => t.threat_type !== 'Normal Activity').length;
  const criticalThreats = threats.filter(t => t.severity === 'Critical').length;
  const highThreats = threats.filter(t => t.severity === 'High').length;

  const toggleExpand = (index) => {
    if (expandedThreat === index) {
      setExpandedThreat(null);
    } else {
      setExpandedThreat(index);
    }
  };

  // Format AI analysis for display
  const formatAIAnalysis = (analysis) => {
    if (!analysis) return null;

    // If analysis is a string, try to parse it
    if (typeof analysis === 'string') {
      try {
        const parsed = JSON.parse(analysis);
        return parsed;
      } catch {
        return { explanation: analysis };
      }
    }
    return analysis;
  };

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <div className="flex justify-between items-center mb-4">
        <h3 className="text-xl font-bold">🚨 Detected Threats</h3>
        <div className="flex space-x-4 text-sm">
          <span className="text-gray-600">Total: <span className="font-bold">{totalThreats}</span></span>
          <span className="text-red-600">Critical: <span className="font-bold">{criticalThreats}</span></span>
          <span className="text-orange-500">High: <span className="font-bold">{highThreats}</span></span>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-4 mb-4">
        <div className="flex-1 min-w-[200px]">
          <input
            type="text"
            placeholder="Search threats..."
            className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
        <div className="flex gap-2 flex-wrap">
          <button
            onClick={() => setFilter('all')}
            className={`px-4 py-2 rounded-lg transition ${filter === 'all' ? 'bg-blue-600 text-white' : 'bg-gray-100 hover:bg-gray-200'
              }`}
          >
            All
          </button>
          <button
            onClick={() => setFilter('Critical')}
            className={`px-4 py-2 rounded-lg transition ${filter === 'Critical' ? 'bg-red-600 text-white' : 'bg-gray-100 hover:bg-gray-200'
              }`}
          >
            Critical
          </button>
          <button
            onClick={() => setFilter('High')}
            className={`px-4 py-2 rounded-lg transition ${filter === 'High' ? 'bg-orange-500 text-white' : 'bg-gray-100 hover:bg-gray-200'
              }`}
          >
            High
          </button>
          <button
            onClick={() => setFilter('Medium')}
            className={`px-4 py-2 rounded-lg transition ${filter === 'Medium' ? 'bg-yellow-500 text-white' : 'bg-gray-100 hover:bg-gray-200'
              }`}
          >
            Medium
          </button>
          <button
            onClick={() => setFilter('Low')}
            className={`px-4 py-2 rounded-lg transition ${filter === 'Low' ? 'bg-green-500 text-white' : 'bg-gray-100 hover:bg-gray-200'
              }`}
          >
            Low
          </button>
        </div>
      </div>

      {/* Threat Cards */}
      <div className="space-y-4">
        {filteredThreats.length === 0 ? (
          <div className="text-center py-8 text-gray-500">
            No threats found matching the current filters
          </div>
        ) : (
          filteredThreats.map((threat, index) => {
            const isExpanded = expandedThreat === index;
            const aiAnalysis = formatAIAnalysis(threat.ai_analysis);

            return (
              <div
                key={index}
                className="border border-gray-200 rounded-lg hover:shadow-md transition cursor-pointer"
                onClick={() => toggleExpand(index)}
              >
                {/* Card Header - Always Visible */}
                <div className="p-4">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2 flex-wrap">
                        <span className={`px-3 py-1 rounded-full text-sm font-semibold border ${getSeverityBadgeColor(threat.severity)}`}>
                          {getSeverityIcon(threat.severity)} {threat.severity}
                        </span>
                        <span className="text-gray-500 text-sm">•</span>
                        <span className="text-gray-600 text-sm">
                          {threat.timestamp ? new Date(threat.timestamp).toLocaleString() : 'Unknown time'}
                        </span>
                        <span className="text-gray-500 text-sm">•</span>
                        <span className="text-gray-600 text-sm font-mono bg-gray-100 px-2 py-0.5 rounded">
                          {threat.source_ip || 'Unknown IP'}
                        </span>
                      </div>

                      <h4 className="text-lg font-semibold text-gray-800 flex items-center gap-2">
                        {threat.threat_type}
                        {threat.detection_type === 'rule_based_and_ai' && (
                          <span className="text-xs bg-blue-100 text-blue-800 px-2 py-0.5 rounded-full">
                            🤖 AI Enhanced
                          </span>
                        )}
                      </h4>

                      <p className="text-gray-600 mt-1">{threat.summary}</p>

                      <div className="mt-2 flex items-center gap-2 text-sm text-blue-600">
                        <span>Click for details</span>
                        <svg
                          className={`w-4 h-4 transition-transform ${isExpanded ? 'rotate-180' : ''}`}
                          fill="none"
                          stroke="currentColor"
                          viewBox="0 0 24 24"
                        >
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7" />
                        </svg>
                      </div>
                    </div>

                    <div className="ml-4">
                      <span className={`w-3 h-3 rounded-full inline-block ${getSeverityColor(threat.severity)}`}></span>
                    </div>
                  </div>
                </div>

                {/* Expanded Details - Only shown when clicked */}
                {isExpanded && (
                  <div className="border-t border-gray-200 p-4 bg-gray-50 rounded-b-lg">
                    <div className="space-y-4">
                      {/* Raw Log Section */}
                      {threat.raw_log && (
                        <div>
                          <h5 className="text-sm font-semibold text-gray-700 mb-1">📄 Raw Log Entry</h5>
                          <div className="bg-gray-800 text-gray-100 p-3 rounded-lg font-mono text-sm overflow-x-auto">
                            {threat.raw_log}
                          </div>
                        </div>
                      )}

                      {/* AI Analysis Section */}
                      {aiAnalysis && (
                        <div>
                          <h5 className="text-sm font-semibold text-gray-700 mb-2">🤖 AI Analysis</h5>

                          <div className="space-y-3">
                            {/* Explanation */}
                            {aiAnalysis.explanation && (
                              <div className="bg-blue-50 border-l-4 border-blue-500 p-3 rounded-r-lg">
                                <p className="text-sm font-medium text-blue-800">📝 Explanation</p>
                                <p className="text-sm text-gray-700 mt-1">{aiAnalysis.explanation}</p>
                              </div>
                            )}

                            {/* Risk Assessment */}
                            {aiAnalysis.risk_assessment && (
                              <div className="bg-orange-50 border-l-4 border-orange-500 p-3 rounded-r-lg">
                                <p className="text-sm font-medium text-orange-800">⚠️ Risk Assessment</p>
                                <p className="text-sm text-gray-700 mt-1">{aiAnalysis.risk_assessment}</p>
                              </div>
                            )}

                            {/* Recommendations - Enhanced */}
                            {(aiAnalysis.recommendations || threat.recommendation) && (
                              <div className="bg-green-50 border-l-4 border-green-500 p-3 rounded-r-lg">
                                <p className="text-sm font-medium text-green-800">
                                  💡 Recommendations
                                </p>

                                <p className="text-sm text-gray-700 mt-1">
                                  {aiAnalysis.recommendations || threat.recommendation}
                                </p>
                              </div>
                            )}

                            {/* Additional Context */}
                            {aiAnalysis.additional_context && (
                              <div className="bg-purple-50 border-l-4 border-purple-500 p-3 rounded-r-lg">
                                <p className="text-sm font-medium text-purple-800">📚 Additional Context</p>
                                <p className="text-sm text-gray-700 mt-1">{aiAnalysis.additional_context}</p>
                              </div>
                            )}

                            {/* Full Analysis (if available) */}
                            {aiAnalysis.full_analysis && (
                              <div>
                                <p className="text-sm font-medium text-gray-700 mb-1">📋 Full Analysis</p>
                                <div className="bg-gray-100 p-3 rounded-lg text-sm text-gray-700 max-h-48 overflow-y-auto whitespace-pre-wrap">
                                  {aiAnalysis.full_analysis}
                                </div>
                              </div>
                            )}
                          </div>
                        </div>
                      )}

                      {/* Fallback if no AI analysis */}
                      {!aiAnalysis && (
                        <div className="bg-yellow-50 border border-yellow-200 p-4 rounded-lg">
                          <p className="text-sm text-yellow-800">
                            ⚠️ Detailed AI analysis not available.
                            {threat.recommendation && ` Recommendation: ${threat.recommendation}`}
                          </p>
                        </div>
                      )}

                      {/* Detection Type Badge */}
                      <div className="flex items-center gap-2 text-xs text-gray-500 mt-2">
                        <span>🔍 Detection Method:</span>
                        <span className="bg-gray-200 px-2 py-0.5 rounded">
                          {threat.detection_type || 'Rule-based'}
                        </span>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

export default ThreatList;
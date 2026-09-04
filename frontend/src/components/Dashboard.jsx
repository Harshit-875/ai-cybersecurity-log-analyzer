import React from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, PieChart, Pie, Cell } from 'recharts';

const COLORS = ['#ef4444', '#f59e0b', '#8b5cf6', '#3b82f6', '#10b981'];

function Dashboard({ data }) {
  const stats = data || {};
  const threatData = stats.threat_types || {};
  const severityData = stats.severity_breakdown || {};
  
  // Prepare data for charts
  const threatChartData = Object.keys(threatData).map(key => ({
    name: key,
    value: threatData[key]
  }));

  const severityChartData = Object.keys(severityData).map(key => ({
    name: key,
    value: severityData[key]
  }));

  return (
    <div className="space-y-6">
      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-500 text-sm">Total Logs Analyzed</p>
              <p className="text-3xl font-bold text-blue-600">{stats.total_logs_analyzed || 0}</p>
            </div>
            <div className="text-4xl">📊</div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-500 text-sm">Suspicious Events</p>
              <p className="text-3xl font-bold text-red-600">{stats.suspicious_events || 0}</p>
            </div>
            <div className="text-4xl">🚨</div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-500 text-sm">Critical Threats</p>
              <p className="text-3xl font-bold text-red-700">{severityData.Critical || 0}</p>
            </div>
            <div className="text-4xl">⚠️</div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-500 text-sm">Detection Rate</p>
              <p className="text-3xl font-bold text-green-600">
                {stats.total_logs_analyzed > 0 
                  ? Math.round((stats.suspicious_events / stats.total_logs_analyzed) * 100)
                  : 0}%
              </p>
            </div>
            <div className="text-4xl">🎯</div>
          </div>
        </div>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold mb-4">Threat Type Distribution</h3>
          {threatChartData.length > 0 ? (
            <BarChart width={400} height={300} data={threatChartData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="name" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Bar dataKey="value" fill="#3b82f6" />
            </BarChart>
          ) : (
            <p className="text-gray-500 text-center py-8">No data available</p>
          )}
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold mb-4">Severity Distribution</h3>
          {severityChartData.length > 0 ? (
            <PieChart width={400} height={300}>
              <Pie
                data={severityChartData}
                cx={200}
                cy={150}
                labelLine={false}
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                outerRadius={100}
                fill="#8884d8"
                dataKey="value"
              >
                {severityChartData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          ) : (
            <p className="text-gray-500 text-center py-8">No data available</p>
          )}
        </div>
      </div>
    </div>
  );
}

export default Dashboard;
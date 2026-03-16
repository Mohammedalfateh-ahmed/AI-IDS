import React, { useState, useEffect } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';

const SeverityDistributionChart = ({ alerts }) => {
  const [severityData, setSeverityData] = useState([]);

  useEffect(() => {
    if (!alerts || alerts.length === 0) {
      setSeverityData([]);
      return;
    }

    const severityCounts = {
      'Critical': 0,
      'High': 0,
      'Medium': 0,
      'Low': 0
    };

    alerts.forEach(alert => {
      const severity = alert.severity;
      if (severityCounts.hasOwnProperty(severity)) {
        severityCounts[severity]++;
      }
    });

    const data = Object.entries(severityCounts).map(([severity, count]) => ({
      severity,
      count,
      percentage: alerts.length > 0 ? ((count / alerts.length) * 100).toFixed(1) : 0
    }));

    setSeverityData(data);
  }, [alerts]);

  const getSeverityColor = (severity) => {
    const colors = {
      'Critical': '#dc2626',
      'High': '#f59e0b',
      'Medium': '#eab308',
      'Low': '#3b82f6'
    };
    return colors[severity] || '#6b7280';
  };

  const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-white p-3 border border-gray-300 rounded shadow-lg">
          <p className="font-semibold text-gray-900">{payload[0].payload.severity}</p>
          <p className="text-sm text-gray-600">Count: {payload[0].value}</p>
          <p className="text-sm text-gray-600">Percentage: {payload[0].payload.percentage}%</p>
        </div>
      );
    }
    return null;
  };

  if (!severityData || severityData.length === 0 || severityData.every(d => d.count === 0)) {
    return (
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Severity Distribution</h3>
        <div className="flex items-center justify-center h-64 text-gray-500">
          No attack data available
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <h3 className="text-lg font-semibold text-gray-900 mb-4">Severity Distribution</h3>
      <ResponsiveContainer width="100%" height={300}>
        <BarChart data={severityData}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="severity" tick={{ fontSize: 12 }} />
          <YAxis tick={{ fontSize: 12 }} />
          <Tooltip content={<CustomTooltip />} />
          <Bar dataKey="count" radius={[8, 8, 0, 0]}>
            {severityData.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={getSeverityColor(entry.severity)} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
      <div className="mt-4 grid grid-cols-4 gap-4">
        {severityData.map((item, index) => (
          <div key={index} className="text-center">
            <div 
              className="text-2xl font-bold mb-1" 
              style={{ color: getSeverityColor(item.severity) }}
            >
              {item.count}
            </div>
            <div className="text-xs text-gray-600">{item.severity}</div>
            <div className="text-xs text-gray-500">{item.percentage}%</div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default SeverityDistributionChart;
import React, { useState, useEffect } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, Cell } from 'recharts';

const TopIPsChart = ({ alerts }) => {
  const [topIPs, setTopIPs] = useState([]);

  useEffect(() => {
    if (!alerts || alerts.length === 0) {
      setTopIPs([]);
      return;
    }

    const ipCounts = {};
    alerts.forEach(alert => {
      const ip = alert.source_ip;
      if (ip && ip !== 'Unknown') {
        ipCounts[ip] = (ipCounts[ip] || 0) + 1;
      }
    });

    const sortedIPs = Object.entries(ipCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([ip, count]) => ({
        ip,
        attacks: count,
        displayIP: ip.length > 15 ? ip.substring(0, 12) + '...' : ip
      }));

    setTopIPs(sortedIPs);
  }, [alerts]);

  const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-white p-3 border border-gray-300 rounded shadow-lg">
          <p className="font-semibold text-gray-900">{payload[0].payload.ip}</p>
          <p className="text-sm text-gray-600">Attacks: {payload[0].value}</p>
        </div>
      );
    }
    return null;
  };

  const getBarColor = (index) => {
    const colors = [
      '#ef4444',
      '#f97316',
      '#f59e0b',
      '#eab308',
      '#84cc16',
      '#22c55e',
      '#06b6d4',
      '#3b82f6',
      '#6366f1',
      '#8b5cf6'
    ];
    return colors[index % colors.length];
  };

  if (!topIPs || topIPs.length === 0) {
    return (
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Top 10 Source IPs</h3>
        <div className="flex items-center justify-center h-64 text-gray-500">
          No attack data available
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <h3 className="text-lg font-semibold text-gray-900 mb-4">Top 10 Source IPs</h3>
      <ResponsiveContainer width="100%" height={350}>
        <BarChart data={topIPs} layout="vertical">
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis type="number" tick={{ fontSize: 12 }} />
          <YAxis 
            dataKey="displayIP" 
            type="category" 
            tick={{ fontSize: 11 }}
            width={100}
          />
          <Tooltip content={<CustomTooltip />} />
          <Bar dataKey="attacks" radius={[0, 8, 8, 0]}>
            {topIPs.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={getBarColor(index)} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};

export default TopIPsChart;
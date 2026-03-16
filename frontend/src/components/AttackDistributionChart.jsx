import React from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts';

const COLORS = {
  'neptune': '#ef4444',
  'smurf': '#f97316',
  'pod': '#f59e0b',
  'teardrop': '#eab308',
  'back': '#84cc16',
  'land': '#22c55e',
  'portsweep': '#06b6d4',
  'satan': '#3b82f6',
  'nmap': '#6366f1',
  'ipsweep': '#8b5cf6',
  'warezclient': '#a855f7',
  'guess_passwd': '#d946ef',
  'ftp_write': '#ec4899',
  'imap': '#f43f5e',
  'buffer_overflow': '#dc2626',
  'rootkit': '#991b1b',
  'loadmodule': '#7c2d12',
  'perl': '#78350f',
  'normal': '#22c55e'
};

const AttackDistributionChart = ({ data }) => {
  const chartData = Object.entries(data || {}).map(([name, value]) => ({
    name,
    value,
    percentage: 0
  }));

  const total = chartData.reduce((sum, item) => sum + item.value, 0);
  chartData.forEach(item => {
    item.percentage = total > 0 ? ((item.value / total) * 100).toFixed(1) : 0;
  });

  const sortedData = chartData.sort((a, b) => b.value - a.value).slice(0, 10);

  const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-white p-3 border border-gray-300 rounded shadow-lg">
          <p className="font-semibold text-gray-900">{payload[0].name}</p>
          <p className="text-sm text-gray-600">Count: {payload[0].value}</p>
          <p className="text-sm text-gray-600">Percentage: {payload[0].payload.percentage}%</p>
        </div>
      );
    }
    return null;
  };

  const renderCustomLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, percent }) => {
    if (percent < 0.05) return null;
    const radius = innerRadius + (outerRadius - innerRadius) * 0.5;
    const x = cx + radius * Math.cos(-midAngle * Math.PI / 180);
    const y = cy + radius * Math.sin(-midAngle * Math.PI / 180);

    return (
      <text 
        x={x} 
        y={y} 
        fill="white" 
        textAnchor={x > cx ? 'start' : 'end'} 
        dominantBaseline="central"
        className="font-bold text-xs"
      >
        {`${(percent * 100).toFixed(0)}%`}
      </text>
    );
  };

  if (!sortedData || sortedData.length === 0) {
    return (
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Attack Distribution</h3>
        <div className="flex items-center justify-center h-64 text-gray-500">
          No attack data available
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <h3 className="text-lg font-semibold text-gray-900 mb-4">Attack Distribution</h3>
      <ResponsiveContainer width="100%" height={350}>
        <PieChart>
          <Pie
            data={sortedData}
            cx="50%"
            cy="50%"
            labelLine={false}
            label={renderCustomLabel}
            outerRadius={120}
            fill="#8884d8"
            dataKey="value"
          >
            {sortedData.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={COLORS[entry.name] || COLORS['normal']} />
            ))}
          </Pie>
          <Tooltip content={<CustomTooltip />} />
          <Legend 
            verticalAlign="bottom" 
            height={36}
            formatter={(value, entry) => `${value} (${entry.payload.value})`}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
};

export default AttackDistributionChart;
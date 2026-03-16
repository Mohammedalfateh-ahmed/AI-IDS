import React, { useState, useEffect } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { format, subHours, subMinutes } from 'date-fns';

const AttacksOverTimeChart = ({ alerts }) => {
  const [timeData, setTimeData] = useState([]);

  useEffect(() => {
    if (!alerts || alerts.length === 0) {
      setTimeData([]);
      return;
    }

    const now = new Date();
    const intervals = [];
    
    for (let i = 11; i >= 0; i--) {
      intervals.push({
        time: subMinutes(now, i * 5),
        attacks: 0,
        dos: 0,
        probe: 0,
        r2l: 0,
        u2r: 0
      });
    }

    alerts.forEach(alert => {
      const alertTime = new Date(alert.timestamp);
      const intervalIndex = intervals.findIndex(interval => {
        const nextInterval = intervals[intervals.indexOf(interval) + 1];
        if (!nextInterval) return alertTime >= interval.time;
        return alertTime >= interval.time && alertTime < nextInterval.time;
      });

      if (intervalIndex !== -1) {
        intervals[intervalIndex].attacks++;
        
        const attackType = alert.attack_type?.toLowerCase() || '';
        if (['neptune', 'smurf', 'pod', 'teardrop', 'back', 'land'].includes(attackType)) {
          intervals[intervalIndex].dos++;
        } else if (['portsweep', 'satan', 'nmap', 'ipsweep'].includes(attackType)) {
          intervals[intervalIndex].probe++;
        } else if (['warezclient', 'guess_passwd', 'ftp_write', 'imap', 'phf'].includes(attackType)) {
          intervals[intervalIndex].r2l++;
        } else if (['buffer_overflow', 'rootkit', 'loadmodule', 'perl'].includes(attackType)) {
          intervals[intervalIndex].u2r++;
        }
      }
    });

    const formattedData = intervals.map(interval => ({
      time: format(interval.time, 'HH:mm'),
      'Total Attacks': interval.attacks,
      'DoS': interval.dos,
      'Probe': interval.probe,
      'R2L': interval.r2l,
      'U2R': interval.u2r
    }));

    setTimeData(formattedData);
  }, [alerts]);

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-white p-3 border border-gray-300 rounded shadow-lg">
          <p className="font-semibold text-gray-900 mb-2">{label}</p>
          {payload.map((entry, index) => (
            <p key={index} className="text-sm" style={{ color: entry.color }}>
              {entry.name}: {entry.value}
            </p>
          ))}
        </div>
      );
    }
    return null;
  };

  if (!timeData || timeData.length === 0) {
    return (
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Attacks Over Time (Last Hour)</h3>
        <div className="flex items-center justify-center h-64 text-gray-500">
          No attack data available
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <h3 className="text-lg font-semibold text-gray-900 mb-4">Attacks Over Time (Last Hour)</h3>
      <ResponsiveContainer width="100%" height={350}>
        <LineChart data={timeData}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis 
            dataKey="time" 
            tick={{ fontSize: 12 }}
            angle={-45}
            textAnchor="end"
            height={60}
          />
          <YAxis tick={{ fontSize: 12 }} />
          <Tooltip content={<CustomTooltip />} />
          <Legend />
          <Line 
            type="monotone" 
            dataKey="Total Attacks" 
            stroke="#1f2937" 
            strokeWidth={2}
            dot={{ r: 4 }}
            activeDot={{ r: 6 }}
          />
          <Line 
            type="monotone" 
            dataKey="DoS" 
            stroke="#ef4444" 
            strokeWidth={2}
            dot={{ r: 3 }}
          />
          <Line 
            type="monotone" 
            dataKey="Probe" 
            stroke="#3b82f6" 
            strokeWidth={2}
            dot={{ r: 3 }}
          />
          <Line 
            type="monotone" 
            dataKey="R2L" 
            stroke="#f59e0b" 
            strokeWidth={2}
            dot={{ r: 3 }}
          />
          <Line 
            type="monotone" 
            dataKey="U2R" 
            stroke="#8b5cf6" 
            strokeWidth={2}
            dot={{ r: 3 }}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
};

export default AttacksOverTimeChart;
import React from 'react';

const RealTimeStatsCards = ({ stats }) => {
  const cards = [
    {
      title: 'Total Packets',
      value: stats?.total_packets || 0,
      icon: '📦',
      color: 'bg-blue-500',
      textColor: 'text-blue-600',
      bgColor: 'bg-blue-50'
    },
    {
      title: 'Attacks Detected',
      value: stats?.attacks_detected || 0,
      icon: '🚨',
      color: 'bg-red-500',
      textColor: 'text-red-600',
      bgColor: 'bg-red-50'
    },
    {
      title: 'Normal Traffic',
      value: stats?.benign_traffic || 0,
      icon: '✅',
      color: 'bg-green-500',
      textColor: 'text-green-600',
      bgColor: 'bg-green-50'
    },
    {
      title: 'Total Alerts',
      value: stats?.total_alerts || 0,
      icon: '⚠️',
      color: 'bg-yellow-500',
      textColor: 'text-yellow-600',
      bgColor: 'bg-yellow-50'
    },
    {
      title: 'Detection Rate',
      value: stats?.total_packets > 0 
        ? `${((stats.attacks_detected / stats.total_packets) * 100).toFixed(1)}%`
        : '0%',
      icon: '📊',
      color: 'bg-purple-500',
      textColor: 'text-purple-600',
      bgColor: 'bg-purple-50'
    },
    {
      title: 'Avg Confidence',
      value: stats?.average_confidence 
        ? `${(stats.average_confidence * 100).toFixed(1)}%`
        : '0%',
      icon: '🎯',
      color: 'bg-indigo-500',
      textColor: 'text-indigo-600',
      bgColor: 'bg-indigo-50'
    }
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4 mb-6">
      {cards.map((card, index) => (
        <div key={index} className={`${card.bgColor} rounded-lg shadow p-4 border-l-4 ${card.color}`}>
          <div className="flex items-center justify-between mb-2">
            <span className="text-2xl">{card.icon}</span>
            <div className={`text-xs font-semibold ${card.textColor} bg-white px-2 py-1 rounded`}>
              LIVE
            </div>
          </div>
          <div className={`text-3xl font-bold ${card.textColor} mb-1`}>
            {card.value}
          </div>
          <div className="text-sm text-gray-600 font-medium">
            {card.title}
          </div>
        </div>
      ))}
    </div>
  );
};

export default RealTimeStatsCards;
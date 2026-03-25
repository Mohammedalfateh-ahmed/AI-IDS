import React, { useState, useEffect } from 'react';
import { Activity, TrendingUp, AlertTriangle, Eye, CheckCircle, XCircle } from 'lucide-react';

const BehavioralAnomalyWidget = () => {
  const [statistics, setStatistics] = useState(null);
  const [topAnomalousIPs, setTopAnomalousIPs] = useState([]);
  const [recentAnomalies, setRecentAnomalies] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchData = async () => {
    try {
      const token = localStorage.getItem('token');
      const headers = { 'Authorization': `Bearer ${token}` };

      const [statsRes, topIPsRes, anomaliesRes] = await Promise.all([
        fetch('http://localhost:8000/behavior/statistics', { headers }),
        fetch('http://localhost:8000/behavior/top-anomalous-ips?limit=5', { headers }),
        fetch('http://localhost:8000/behavior/anomalies?limit=10', { headers })
      ]);

      if (statsRes.ok) {
        const data = await statsRes.json();
        setStatistics(data.statistics);
      }

      if (topIPsRes.ok) {
        const data = await topIPsRes.json();
        setTopAnomalousIPs(data.top_anomalous_ips || []);
      }

      if (anomaliesRes.ok) {
        const data = await anomaliesRes.json();
        setRecentAnomalies(data.anomalies || []);
      }

    } catch (error) {
      console.error('Failed to fetch behavioral data:', error);
    }
  };

  useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      await fetchData();
      setLoading(false);
    };

    loadData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  const getRiskColor = (riskLevel) => {
    switch (riskLevel) {
      case 'CRITICAL': return 'text-red-400 bg-red-900 bg-opacity-30 border-red-500';
      case 'HIGH': return 'text-orange-400 bg-orange-900 bg-opacity-30 border-orange-500';
      case 'MEDIUM': return 'text-yellow-400 bg-yellow-900 bg-opacity-30 border-yellow-500';
      case 'LOW': return 'text-blue-400 bg-blue-900 bg-opacity-30 border-blue-500';
      default: return 'text-gray-400 bg-gray-900 bg-opacity-30 border-gray-500';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64" style={{ background: '#0f1729' }}>
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-4 border-cyan-500 mx-auto mb-4"></div>
          <p className="text-gray-400">Loading Behavioral Analysis...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Statistics Cards */}
      <div className="grid grid-cols-4 gap-4">
        <div className="rounded-lg border p-4" style={{ background: '#0f1729', borderColor: '#1a2332' }}>
          <div className="flex items-center justify-between mb-2">
            <Eye className="w-5 h-5 text-cyan-400" />
            <span className="text-xs text-gray-400">Tracked</span>
          </div>
          <div className="text-3xl font-bold text-white">{statistics?.total_ips_tracked || 0}</div>
          <div className="text-xs text-gray-500 mt-1">IPs Monitored</div>
        </div>

        <div className="rounded-lg border p-4" style={{ background: '#0f1729', borderColor: '#1a2332' }}>
          <div className="flex items-center justify-between mb-2">
            <CheckCircle className="w-5 h-5 text-green-400" />
            <span className="text-xs text-gray-400">Learned</span>
          </div>
          <div className="text-3xl font-bold text-white">{statistics?.baselines_learned || 0}</div>
          <div className="text-xs text-gray-500 mt-1">Baselines Ready</div>
        </div>

        <div className="rounded-lg border p-4" style={{ background: '#0f1729', borderColor: '#1a2332' }}>
          <div className="flex items-center justify-between mb-2">
            <AlertTriangle className="w-5 h-5 text-orange-400" />
            <span className="text-xs text-gray-400">Anomalies</span>
          </div>
          <div className="text-3xl font-bold text-white">{statistics?.total_anomalies_detected || 0}</div>
          <div className="text-xs text-gray-500 mt-1">Total Detected</div>
        </div>

        <div className="rounded-lg border p-4" style={{ background: '#0f1729', borderColor: '#1a2332' }}>
          <div className="flex items-center justify-between mb-2">
            <Activity className="w-5 h-5 text-red-400" />
            <span className="text-xs text-gray-400">Last Hour</span>
          </div>
          <div className="text-3xl font-bold text-white">{statistics?.anomalies_last_hour || 0}</div>
          <div className="text-xs text-gray-500 mt-1">Recent Activity</div>
        </div>
      </div>

      {/* Top Anomalous IPs */}
      <div className="rounded-lg border" style={{ background: '#0f1729', borderColor: '#1a2332' }}>
        <div className="p-4 border-b" style={{ borderColor: '#1a2332' }}>
          <h3 className="text-lg font-bold text-white flex items-center">
            <TrendingUp className="w-5 h-5 mr-2 text-cyan-400" />
            Top Anomalous IPs
          </h3>
          <p className="text-xs text-gray-400 mt-1">IPs with most unusual behavior patterns</p>
        </div>
        <div className="p-4">
          {topAnomalousIPs.length === 0 ? (
            <div className="text-center py-8">
              <p className="text-gray-500">No anomalous behavior detected</p>
            </div>
          ) : (
            <div className="space-y-3">
              {topAnomalousIPs.map((ip, index) => (
                <div key={index} className="flex items-center justify-between p-3 rounded-lg" style={{ background: '#0a0e1a' }}>
                  <div className="flex items-center space-x-3">
                    <div className="w-10 h-10 bg-gradient-to-br from-red-900 to-orange-800 rounded-full flex items-center justify-center text-white font-bold">
                      #{index + 1}
                    </div>
                    <div>
                      <div className="font-mono font-bold text-cyan-400">{ip.ip_address}</div>
                      <div className="text-xs text-gray-400">
                        {ip.anomaly_count} anomalies • {ip.packets_observed} packets
                        {ip.baseline_learned ? 
                          <CheckCircle className="w-3 h-3 inline ml-2 text-green-400" /> : 
                          <XCircle className="w-3 h-3 inline ml-2 text-gray-500" />
                        }
                      </div>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-2xl font-bold text-orange-400">{ip.max_anomaly_score}</div>
                    <div className="text-xs text-gray-500">Max Score</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Recent Anomalies */}
      <div className="rounded-lg border" style={{ background: '#0f1729', borderColor: '#1a2332' }}>
        <div className="p-4 border-b" style={{ borderColor: '#1a2332' }}>
          <h3 className="text-lg font-bold text-white flex items-center">
            <Activity className="w-5 h-5 mr-2 text-cyan-400" />
            Recent Behavioral Anomalies
          </h3>
          <p className="text-xs text-gray-400 mt-1">Latest unusual patterns detected</p>
        </div>
        <div className="p-4">
          {recentAnomalies.length === 0 ? (
            <div className="text-center py-8">
              <p className="text-gray-500">No recent anomalies</p>
            </div>
          ) : (
            <div className="space-y-2">
              {recentAnomalies.map((anomaly, index) => (
                <div key={index} className="p-3 rounded-lg border" style={{ background: '#0a0e1a', borderColor: '#1a2332' }}>
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center space-x-2">
                      <span className="font-mono text-sm text-cyan-400">{anomaly.ip}</span>
                      <span className={`px-2 py-0.5 text-xs font-semibold rounded border ${getRiskColor(anomaly.risk_level)}`}>
                        {anomaly.risk_level}
                      </span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className="text-lg font-bold text-orange-400">{anomaly.anomaly_score}</span>
                      <span className="text-xs text-gray-500">score</span>
                    </div>
                  </div>
                  <div className="text-xs text-gray-400">
                    {new Date(anomaly.timestamp).toLocaleString()}
                  </div>
                  {Object.keys(anomaly.anomalies).length > 0 && (
                    <div className="mt-2 text-xs text-gray-500">
                      Anomalies: {Object.keys(anomaly.anomalies).map(k => k.replace('_', ' ')).join(', ')}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Risk Distribution */}
      {statistics?.risk_distribution && (
        <div className="rounded-lg border p-4" style={{ background: '#0f1729', borderColor: '#1a2332' }}>
          <h3 className="text-sm font-bold text-white mb-4">Risk Level Distribution</h3>
          <div className="grid grid-cols-4 gap-3">
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((level) => {
              const count = statistics.risk_distribution[level] || 0;
              return (
                <div key={level} className="text-center p-3 rounded-lg" style={{ background: '#0a0e1a' }}>
                  <div className={`text-2xl font-bold ${getRiskColor(level).split(' ')[0]}`}>
                    {count}
                  </div>
                  <div className="text-xs text-gray-400 mt-1">{level}</div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};

export default BehavioralAnomalyWidget;
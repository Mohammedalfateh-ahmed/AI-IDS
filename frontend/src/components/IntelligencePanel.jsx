import { useState, useEffect } from 'react';
import axios from 'axios';

export default function IntelligencePanel() {
  const [health, setHealth] = useState(null);
  const [topThreats, setTopThreats] = useState([]);
  const [forecast, setForecast] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchIntelligence();
    const interval = setInterval(fetchIntelligence, 10000);
    return () => clearInterval(interval);
  }, []);

  const fetchIntelligence = async () => {
    try {
      const token = localStorage.getItem('token');
      const headers = { Authorization: `Bearer ${token}` };

      const [healthRes, threatsRes, forecastRes] = await Promise.all([
        axios.get('http://localhost:8000/intelligence/network-health', { headers }),
        axios.get('http://localhost:8000/intelligence/top-threats?limit=5', { headers }),
        axios.get('http://localhost:8000/intelligence/attack-forecast', { headers })
      ]);

      setHealth(healthRes.data);
      setTopThreats(threatsRes.data.top_threats);
      setForecast(forecastRes.data);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching intelligence:', error);
      setLoading(false);
    }
  };

  const getHealthColor = (status) => {
    switch (status) {
      case 'HEALTHY': return 'text-green-600 bg-green-50 border-green-200';
      case 'FAIR': return 'text-blue-600 bg-blue-50 border-blue-200';
      case 'DEGRADED': return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      case 'CRITICAL': return 'text-red-600 bg-red-50 border-red-200';
      default: return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  const getThreatColor = (level) => {
    switch (level) {
      case 'CRITICAL': return 'bg-red-100 text-red-700 border-red-300';
      case 'HIGH': return 'bg-orange-100 text-orange-700 border-orange-300';
      case 'MEDIUM': return 'bg-yellow-100 text-yellow-700 border-yellow-300';
      case 'LOW': return 'bg-blue-100 text-blue-700 border-blue-300';
      default: return 'bg-gray-100 text-gray-700 border-gray-300';
    }
  };

  if (loading) {
    return (
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="animate-pulse space-y-4">
          <div className="h-4 bg-gray-200 rounded w-1/2"></div>
          <div className="h-32 bg-gray-200 rounded"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200">
      <div className="p-6 border-b border-gray-200">
        <h2 className="text-lg font-bold text-gray-800 flex items-center space-x-2">
          <svg className="w-5 h-5 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
          </svg>
          <span>AI Intelligence Engine</span>
        </h2>
      </div>

      <div className="p-6 space-y-6">
        {health && (
          <div>
            <h3 className="text-sm font-semibold text-gray-700 mb-3">Network Health</h3>
            <div className={`p-4 rounded-lg border-2 ${getHealthColor(health.status)}`}>
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-medium uppercase">Status</span>
                <span className="text-lg font-bold">{health.status}</span>
              </div>
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div>
                  <span className="text-gray-600">Health Score</span>
                  <div className="font-bold text-lg">{health.health_score}%</div>
                </div>
                <div>
                  <span className="text-gray-600">Total IPs</span>
                  <div className="font-bold text-lg">{health.total_ips}</div>
                </div>
                <div>
                  <span className="text-gray-600">Malicious</span>
                  <div className="font-bold text-lg text-red-600">{health.malicious_ips}</div>
                </div>
                <div>
                  <span className="text-gray-600">At Risk</span>
                  <div className="font-bold text-lg text-yellow-600">{health.at_risk_ips}</div>
                </div>
              </div>
            </div>
          </div>
        )}

        {forecast && forecast.forecast_available && (
          <div>
            <h3 className="text-sm font-semibold text-gray-700 mb-3">Attack Forecast</h3>
            <div className="p-4 bg-purple-50 border-2 border-purple-200 rounded-lg">
              <div className="mb-2">
                <span className="text-xs text-purple-600 font-medium">Next Likely Attack</span>
                <div className="text-lg font-bold text-purple-900">{forecast.predicted_attack}</div>
              </div>
              <div className="text-sm text-purple-700 mb-2">
                Confidence: <span className="font-bold">{(forecast.confidence * 100).toFixed(1)}%</span>
              </div>
              <div className="text-xs text-purple-600 mt-2 pt-2 border-t border-purple-200">
                {forecast.reason}
              </div>
            </div>
          </div>
        )}

        <div>
          <h3 className="text-sm font-semibold text-gray-700 mb-3">Top Threats</h3>
          <div className="space-y-2">
            {topThreats.length > 0 ? (
              topThreats.map((threat, index) => (
                <div key={index} className="p-3 bg-gray-50 border border-gray-200 rounded-lg hover:bg-gray-100 transition-colors">
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-mono text-sm font-bold text-blue-600">{threat.ip_address}</span>
                    <span className={`text-xs px-2 py-1 rounded-full border ${getThreatColor(threat.threat_level)}`}>
                      {threat.threat_level}
                    </span>
                  </div>
                  <div className="grid grid-cols-3 gap-2 text-xs">
                    <div>
                      <span className="text-gray-600">Risk</span>
                      <div className="font-bold text-red-600">{threat.risk_score.toFixed(1)}</div>
                    </div>
                    <div>
                      <span className="text-gray-600">Attacks</span>
                      <div className="font-bold text-orange-600">{threat.attack_count}</div>
                    </div>
                    <div>
                      <span className="text-gray-600">Types</span>
                      <div className="font-bold text-purple-600">{threat.attack_types.length}</div>
                    </div>
                  </div>
                </div>
              ))
            ) : (
              <div className="text-center py-8 text-gray-500">
                <svg className="w-12 h-12 text-gray-300 mx-auto mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <p className="text-sm">No threats detected</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
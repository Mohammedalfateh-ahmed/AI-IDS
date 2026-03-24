import React, { useState, useEffect } from 'react';
import { 
  Shield, AlertTriangle, CheckCircle, Settings, Activity, Ban, 
  TrendingUp, Brain, Target, Eye, Globe, Zap, Server, Lock,
  AlertCircle, ChevronRight, Clock, Award, Database, GitBranch
} from 'lucide-react';

const IPSControlPanel = () => {
  const [ipsStatus, setIpsStatus] = useState(null);
  const [blockedIps, setBlockedIps] = useState([]);
  const [topThreats, setTopThreats] = useState([]);
  const [statistics, setStatistics] = useState(null);
  const [settings, setSettings] = useState(null);
  const [modelInfo, setModelInfo] = useState(null);
  const [realtimeAlerts, setRealtimeAlerts] = useState([]);
  const [stats, setStats] = useState({ total_packets: 0, attacks_detected: 0, benign_traffic: 0 });
  const [alertsData, setAlertsData] = useState([]);
  const [activeView, setActiveView] = useState('blocked');
  const [loading, setLoading] = useState(true);

  const fetchAllData = async () => {
    try {
      const token = localStorage.getItem('token');
      const headers = { 'Authorization': `Bearer ${token}` };

      const [statusRes, modelRes, blockedRes, threatsRes, statsRes, settingsRes, alertsRes, dashStatsRes] = await Promise.all([
        fetch('http://localhost:8000/ips/status', { headers }).catch(() => null),
        fetch('http://localhost:8000/model/info', { headers }).catch(() => null),
        fetch('http://localhost:8000/blocked-ips', { headers }).catch(() => null),
        fetch('http://localhost:8000/ips/top-threats?limit=10', { headers }).catch(() => null),
        fetch('http://localhost:8000/ips/statistics', { headers }).catch(() => null),
        fetch('http://localhost:8000/ips/settings', { headers }).catch(() => null),
        fetch('http://localhost:8000/alerts', { headers }).catch(() => null),
        fetch('http://localhost:8000/stats', { headers }).catch(() => null)
      ]);

      if (statusRes) setIpsStatus(await statusRes.json());
      if (modelRes) setModelInfo(await modelRes.json());
      if (blockedRes) setBlockedIps(await blockedRes.json());
      if (threatsRes) {
        const data = await threatsRes.json();
        setTopThreats(data.top_threats || []);
      }
      if (statsRes) {
        const data = await statsRes.json();
        setStatistics(data);
      }
      if (settingsRes) setSettings(await settingsRes.json());
      if (alertsRes) {
        const data = await alertsRes.json();
        setRealtimeAlerts(data.alerts?.slice(-5) || []);
        setAlertsData(data.alerts || []);
      }
      if (dashStatsRes) setStats(await dashStatsRes.json());

    } catch (error) {
      console.error('Failed to fetch data:', error);
    }
  };

  useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      await fetchAllData();
      setLoading(false);
    };

    loadData();
    const interval = setInterval(fetchAllData, 3000);
    return () => clearInterval(interval);
  }, []);

  const unblockIP = async (ip) => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`http://localhost:8000/unblock-ip/${ip}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (response.ok) {
        fetchAllData();
      }
    } catch (error) {
      console.error('Failed to unblock IP:', error);
    }
  };

  const updateSettings = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch('http://localhost:8000/ips/settings', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(settings)
      });

      if (response.ok) {
        alert('✅ Configuration updated successfully!');
      }
    } catch (error) {
      console.error('Failed to update settings:', error);
    }
  };

  const getThreatColor = (score) => {
    if (score >= 85) return 'text-red-400 bg-red-900 bg-opacity-20 border-red-500';
    if (score >= 60) return 'text-orange-400 bg-orange-900 bg-opacity-20 border-orange-500';
    if (score >= 30) return 'text-yellow-400 bg-yellow-900 bg-opacity-20 border-yellow-500';
    return 'text-blue-400 bg-blue-900 bg-opacity-20 border-blue-500';
  };

  const getThreatLabel = (score) => {
    if (score >= 85) return 'CRITICAL';
    if (score >= 60) return 'HIGH';
    if (score >= 30) return 'MEDIUM';
    return 'LOW';
  };

  const getSeverityCounts = () => {
    const counts = { high: 0, medium: 0, low: 0 };
    alertsData.forEach(alert => {
      const sev = alert.severity?.toLowerCase();
      if (sev === 'critical' || sev === 'high') counts.high++;
      else if (sev === 'medium') counts.medium++;
      else counts.low++;
    });
    return counts;
  };

  const getAttackTypeCounts = () => {
    const types = {};
    alertsData.forEach(alert => {
      const type = alert.attack_type || 'Unknown';
      types[type] = (types[type] || 0) + 1;
    });
    return Object.entries(types).sort((a, b) => b[1] - a[1]).slice(0, 6);
  };

  const getProtocolCounts = () => {
    return [
      { name: 'TCP', count: stats.total_packets * 0.65, color: 'bg-blue-500' },
      { name: 'UDP', count: stats.total_packets * 0.25, color: 'bg-orange-500' },
      { name: 'PROTO:255', count: stats.total_packets * 0.10, color: 'bg-yellow-500' }
    ];
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen bg-gray-900">
        <div className="text-center">
          <div className="animate-spin rounded-full h-16 w-16 border-b-4 border-blue-500 mx-auto mb-4"></div>
          <p className="text-gray-400 font-medium">Initializing Security Operations Center...</p>
        </div>
      </div>
    );
  }

  const severityCounts = getSeverityCounts();
  const attackTypes = getAttackTypeCounts();
  const protocols = getProtocolCounts();

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100">
      {/* Wazuh-style Header */}
      <div className="bg-gray-800 border-b border-gray-700 px-6 py-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <Shield className="w-8 h-8 text-blue-500" />
            <div>
              <h1 className="text-xl font-bold text-white">AI-IDS Security Operations</h1>
              <p className="text-xs text-gray-400">Network &gt; Snort &gt; Real-Time Monitoring</p>
            </div>
          </div>
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2 bg-green-900 bg-opacity-30 px-3 py-1 rounded border border-green-700">
              <CheckCircle className="w-4 h-4 text-green-400" />
              <span className="text-xs font-medium text-green-300">ALWAYS ACTIVE</span>
            </div>
            <div className="text-right">
              <div className="text-xs text-gray-400">Last 24 hours</div>
              <div className="text-sm font-semibold text-white">{new Date().toLocaleString()}</div>
            </div>
          </div>
        </div>
      </div>

      <div className="p-6 space-y-6">
        {/* Event Severity Cards - Wazuh Style */}
        <div>
          <h2 className="text-sm font-semibold text-gray-400 mb-3 flex items-center">
            <ChevronRight className="w-4 h-4 mr-1" />
            Event Severity
          </h2>
          <div className="grid grid-cols-5 gap-4">
            {/* High Severity */}
            <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
              <div className="text-xs text-gray-400 mb-2">High Severity</div>
              <div className="text-4xl font-bold text-red-400 mb-2">{severityCounts.high}</div>
              <div className="h-12">
                <svg className="w-full h-full" viewBox="0 0 100 40">
                  <polyline
                    points="0,30 10,25 20,35 30,20 40,28 50,15 60,25 70,18 80,30 90,22 100,25"
                    fill="none"
                    stroke="#f87171"
                    strokeWidth="2"
                  />
                </svg>
              </div>
            </div>

            {/* Medium Severity */}
            <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
              <div className="text-xs text-gray-400 mb-2">Medium Severity</div>
              <div className="text-4xl font-bold text-yellow-400 mb-2">{severityCounts.medium}</div>
              <div className="h-12">
                <svg className="w-full h-full" viewBox="0 0 100 40">
                  <polyline
                    points="0,28 10,30 20,25 30,32 40,27 50,29 60,26 70,31 80,28 90,30 100,27"
                    fill="none"
                    stroke="#facc15"
                    strokeWidth="2"
                  />
                </svg>
              </div>
            </div>

            {/* Low Severity */}
            <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
              <div className="text-xs text-gray-400 mb-2">Low Severity</div>
              <div className="text-4xl font-bold text-green-400 mb-2">{severityCounts.low}</div>
              <div className="h-12">
                <svg className="w-full h-full" viewBox="0 0 100 40">
                  <polyline
                    points="0,32 10,30 20,33 30,31 40,34 50,30 60,33 70,31 80,34 90,32 100,33"
                    fill="none"
                    stroke="#4ade80"
                    strokeWidth="2"
                  />
                </svg>
              </div>
            </div>

            {/* Outbound to Known Threat */}
            <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
              <div className="text-xs text-gray-400 mb-2">Outbound to Known Threat</div>
              <div className="text-4xl font-bold text-gray-500 mb-2">0</div>
              <div className="h-12 flex items-center justify-center">
                <div className="text-xs text-gray-600">No data</div>
              </div>
            </div>

            {/* Inbound from Known Threat */}
            <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
              <div className="text-xs text-gray-400 mb-2">Inbound from Known Threat</div>
              <div className="text-4xl font-bold text-gray-500 mb-2">0</div>
              <div className="h-12 flex items-center justify-center">
                <div className="text-xs text-gray-600">No data</div>
              </div>
            </div>
          </div>
        </div>

        {/* Alert Metrics Row */}
        <div>
          <h2 className="text-sm font-semibold text-gray-400 mb-3 flex items-center">
            <ChevronRight className="w-4 h-4 mr-1" />
            Alert Metrics
          </h2>
          <div className="grid grid-cols-3 gap-4">
            {/* Alert by Severity Chart */}
            <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-sm font-semibold text-gray-300">Alert by Severity</h3>
                <div className="text-right">
                  <div className="text-xs text-gray-400">total</div>
                  <div className="text-lg font-bold text-white">{alertsData.length}</div>
                </div>
              </div>
              <div className="h-48 flex items-end justify-between space-x-2">
                {Array.from({ length: 24 }, (_, i) => {
                  const lowHeight = Math.random() * 80 + 20;
                  const medHeight = Math.random() * 60;
                  return (
                    <div key={i} className="flex-1 flex flex-col justify-end space-y-1">
                      <div className="bg-green-500 rounded-t" style={{ height: `${lowHeight}%` }}></div>
                      <div className="bg-yellow-500" style={{ height: `${medHeight}%` }}></div>
                    </div>
                  );
                })}
              </div>
              <div className="mt-4 flex items-center justify-between text-xs">
                <div className="flex items-center space-x-4">
                  <div className="flex items-center space-x-1">
                    <div className="w-3 h-3 bg-green-500 rounded"></div>
                    <span className="text-gray-400">Low</span>
                    <span className="text-white font-semibold">{severityCounts.low}</span>
                  </div>
                  <div className="flex items-center space-x-1">
                    <div className="w-3 h-3 bg-yellow-500 rounded"></div>
                    <span className="text-gray-400">Medium</span>
                    <span className="text-white font-semibold">{severityCounts.medium}</span>
                  </div>
                </div>
                <div className="text-gray-500">Last 24h</div>
              </div>
            </div>

            {/* Top Alert Type - Donut Chart */}
            <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
              <h3 className="text-sm font-semibold text-gray-300 mb-4">Top Alert Type</h3>
              <div className="flex items-center justify-center h-48">
                <div className="relative w-40 h-40">
                  <svg className="w-full h-full transform -rotate-90">
                    <circle
                      cx="80"
                      cy="80"
                      r="70"
                      fill="none"
                      stroke="#1f2937"
                      strokeWidth="20"
                    />
                    <circle
                      cx="80"
                      cy="80"
                      r="70"
                      fill="none"
                      stroke="#4ade80"
                      strokeWidth="20"
                      strokeDasharray={`${2 * Math.PI * 70 * 0.75} ${2 * Math.PI * 70}`}
                    />
                    <circle
                      cx="80"
                      cy="80"
                      r="70"
                      fill="none"
                      stroke="#facc15"
                      strokeWidth="20"
                      strokeDasharray={`${2 * Math.PI * 70 * 0.15} ${2 * Math.PI * 70}`}
                      strokeDashoffset={`${-2 * Math.PI * 70 * 0.75}`}
                    />
                  </svg>
                  <div className="absolute inset-0 flex items-center justify-center">
                    <div className="text-center">
                      <div className="text-2xl font-bold text-white">{alertsData.length}</div>
                      <div className="text-xs text-gray-400">Total</div>
                    </div>
                  </div>
                </div>
              </div>
              <div className="space-y-1 text-xs mt-4">
                {attackTypes.slice(0, 6).map(([type, count], idx) => (
                  <div key={idx} className="flex items-center justify-between py-1 border-b border-gray-700">
                    <div className="flex items-center space-x-2">
                      <div className={`w-2 h-2 rounded-full ${idx === 0 ? 'bg-green-500' : 'bg-yellow-500'}`}></div>
                      <span className="text-gray-300">{type}</span>
                    </div>
                    <span className="text-white font-semibold">{count}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Top Protocols - Donut Chart */}
            <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
              <h3 className="text-sm font-semibold text-gray-300 mb-4">Top Protocols</h3>
              <div className="flex items-center justify-center h-48">
                <div className="relative w-40 h-40">
                  <svg className="w-full h-full transform -rotate-90">
                    <circle
                      cx="80"
                      cy="80"
                      r="70"
                      fill="none"
                      stroke="#1f2937"
                      strokeWidth="20"
                    />
                    <circle
                      cx="80"
                      cy="80"
                      r="70"
                      fill="none"
                      stroke="#3b82f6"
                      strokeWidth="20"
                      strokeDasharray={`${2 * Math.PI * 70 * 0.65} ${2 * Math.PI * 70}`}
                    />
                    <circle
                      cx="80"
                      cy="80"
                      r="70"
                      fill="none"
                      stroke="#f97316"
                      strokeWidth="20"
                      strokeDasharray={`${2 * Math.PI * 70 * 0.25} ${2 * Math.PI * 70}`}
                      strokeDashoffset={`${-2 * Math.PI * 70 * 0.65}`}
                    />
                    <circle
                      cx="80"
                      cy="80"
                      r="70"
                      fill="none"
                      stroke="#facc15"
                      strokeWidth="20"
                      strokeDasharray={`${2 * Math.PI * 70 * 0.10} ${2 * Math.PI * 70}`}
                      strokeDashoffset={`${-2 * Math.PI * 70 * 0.90}`}
                    />
                  </svg>
                  <div className="absolute inset-0 flex items-center justify-center">
                    <div className="text-center">
                      <div className="text-2xl font-bold text-white">{stats.total_packets}</div>
                      <div className="text-xs text-gray-400">Packets</div>
                    </div>
                  </div>
                </div>
              </div>
              <div className="space-y-1 text-xs mt-4">
                {protocols.map((proto, idx) => (
                  <div key={idx} className="flex items-center justify-between py-1 border-b border-gray-700">
                    <div className="flex items-center space-x-2">
                      <div className={`w-2 h-2 rounded-full ${proto.color}`}></div>
                      <span className="text-gray-300">{proto.name}</span>
                    </div>
                    <span className="text-white font-semibold">{Math.round(proto.count)}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Geographic Maps and Country Tables */}
        <div className="grid grid-cols-2 gap-4">
          {/* Outbound Map */}
          <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
            <h3 className="text-sm font-semibold text-gray-300 mb-4">Outbound</h3>
            <div className="bg-gray-900 rounded h-64 flex items-center justify-center mb-4">
              <div className="text-center">
                <Globe className="w-16 h-16 mx-auto mb-2 text-gray-600" />
                <p className="text-xs text-gray-500">Geographic visualization</p>
              </div>
            </div>
            <div>
              <div className="text-xs font-semibold text-gray-400 mb-2">Destination by Country</div>
              <div className="space-y-1">
                {[
                  { country: 'US', count: Math.round(stats.attacks_detected * 0.6) },
                  { country: 'NL', count: Math.round(stats.attacks_detected * 0.2) },
                  { country: 'TW', count: Math.round(stats.attacks_detected * 0.2) }
                ].map((item, idx) => (
                  <div key={idx} className="flex items-center justify-between py-1 border-b border-gray-700 text-xs">
                    <span className="text-blue-400">{item.country}</span>
                    <span className="text-white font-semibold">{item.count}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Inbound Map */}
          <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
            <h3 className="text-sm font-semibold text-gray-300 mb-4">Inbound</h3>
            <div className="bg-gray-900 rounded h-64 flex items-center justify-center mb-4">
              <div className="text-center">
                <Globe className="w-16 h-16 mx-auto mb-2 text-gray-600" />
                <p className="text-xs text-gray-500">Geographic visualization</p>
              </div>
            </div>
            <div>
              <div className="text-xs font-semibold text-gray-400 mb-2">Source by Country</div>
              <div className="space-y-1">
                {blockedIps.slice(0, 6).map((ip, idx) => (
                  <div key={idx} className="flex items-center justify-between py-1 border-b border-gray-700 text-xs">
                    <span className="text-blue-400">Unknown</span>
                    <span className="text-white font-semibold">{ip.attack_count || 1}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Tabs Section */}
        <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
          <div className="border-b border-gray-700 bg-gray-750">
            <nav className="flex space-x-8 px-6" aria-label="Tabs">
              {[
                { id: 'blocked', name: 'Blocked IPs', icon: Ban },
                { id: 'threats', name: 'Top Threats', icon: Target },
                { id: 'intelligence', name: 'ML Intelligence', icon: Brain },
                { id: 'settings', name: 'Configuration', icon: Settings }
              ].map((tab) => {
                const Icon = tab.icon;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveView(tab.id)}
                    className={`py-3 px-1 border-b-2 font-medium text-sm flex items-center space-x-2 transition-colors ${
                      activeView === tab.id
                        ? 'border-blue-500 text-blue-400'
                        : 'border-transparent text-gray-400 hover:text-gray-300 hover:border-gray-600'
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                    <span>{tab.name}</span>
                  </button>
                );
              })}
            </nav>
          </div>

          <div className="p-6">
            {activeView === 'blocked' && (
              <div className="space-y-4">
                <h3 className="text-lg font-bold text-white">Blocked IP Addresses</h3>
                {blockedIps.length === 0 ? (
                  <div className="text-center py-16 bg-gray-900 rounded-lg">
                    <Ban className="w-16 h-16 mx-auto mb-4 text-gray-600" />
                    <p className="text-gray-500">No blocked IPs</p>
                  </div>
                ) : (
                  <div className="overflow-hidden rounded-lg border border-gray-700">
                    <table className="min-w-full divide-y divide-gray-700">
                      <thead className="bg-gray-900">
                        <tr>
                          <th className="px-6 py-3 text-left text-xs font-semibold text-gray-400 uppercase">IP Address</th>
                          <th className="px-6 py-3 text-left text-xs font-semibold text-gray-400 uppercase">Reason</th>
                          <th className="px-6 py-3 text-left text-xs font-semibold text-gray-400 uppercase">Threat</th>
                          <th className="px-6 py-3 text-left text-xs font-semibold text-gray-400 uppercase">Blocked At</th>
                          <th className="px-6 py-3 text-left text-xs font-semibold text-gray-400 uppercase">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-700">
                        {blockedIps.map((ip, index) => (
                          <tr key={index} className="hover:bg-gray-750 transition-colors">
                            <td className="px-6 py-4 font-mono text-sm text-blue-400">{ip.ip_address}</td>
                            <td className="px-6 py-4 text-sm text-gray-300">{ip.reason}</td>
                            <td className="px-6 py-4">
                              <span className={`px-3 py-1 text-xs font-semibold rounded border ${getThreatColor(ip.threat_score || 0)}`}>
                                {getThreatLabel(ip.threat_score || 0)}
                              </span>
                            </td>
                            <td className="px-6 py-4 text-sm text-gray-400">{new Date(ip.blocked_at).toLocaleString()}</td>
                            <td className="px-6 py-4">
                              <button onClick={() => unblockIP(ip.ip_address)} className="text-blue-400 hover:text-blue-300 text-sm font-medium">
                                Unblock
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            {activeView === 'threats' && (
              <div className="space-y-4">
                <h3 className="text-lg font-bold text-white">Top Threat Sources</h3>
                {topThreats.length === 0 ? (
                  <div className="text-center py-16 bg-gray-900 rounded-lg">
                    <Target className="w-16 h-16 mx-auto mb-4 text-gray-600" />
                    <p className="text-gray-500">No threats detected</p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {topThreats.map((threat, index) => (
                      <div key={index} className="bg-gray-900 border border-gray-700 rounded-lg p-4 hover:border-gray-600 transition-colors">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-4">
                            <div className="w-12 h-12 bg-gradient-to-br from-red-900 to-red-700 rounded-full flex items-center justify-center text-white font-bold text-lg">
                              #{index + 1}
                            </div>
                            <div>
                              <div className="font-mono font-bold text-lg text-blue-400">{threat.ip_address}</div>
                              <div className="text-sm text-gray-400">{threat.attack_count} attacks detected</div>
                            </div>
                          </div>
                          <div className="text-right">
                            <div className="text-3xl font-bold text-red-400">{threat.threat_score}</div>
                            <div className="text-xs text-gray-500">Threat Score</div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {activeView === 'intelligence' && modelInfo && (
              <div className="space-y-6">
                <h3 className="text-lg font-bold text-white">ML Detection Intelligence</h3>
                <div className="bg-gradient-to-br from-purple-900 to-indigo-900 rounded-lg p-6 border border-purple-700">
                  <div className="flex items-center space-x-3 mb-4">
                    <Brain className="w-6 h-6 text-purple-400" />
                    <h4 className="font-bold text-white">XGBoost Model Performance</h4>
                  </div>
                  <div className="grid grid-cols-3 gap-6">
                    <div className="text-center">
                      <div className="text-4xl font-bold text-purple-300">{(modelInfo.accuracy * 100).toFixed(1)}%</div>
                      <div className="text-xs text-purple-400 mt-1">Accuracy</div>
                    </div>
                    <div className="text-center">
                      <div className="text-4xl font-bold text-indigo-300">{(modelInfo.precision * 100).toFixed(1)}%</div>
                      <div className="text-xs text-indigo-400 mt-1">Precision</div>
                    </div>
                    <div className="text-center">
                      <div className="text-4xl font-bold text-blue-300">{(modelInfo.recall * 100).toFixed(1)}%</div>
                      <div className="text-xs text-blue-400 mt-1">Recall</div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {activeView === 'settings' && settings && (
              <div className="space-y-6">
                <h3 className="text-lg font-bold text-white">IPS Configuration</h3>
                <div className="space-y-6 bg-gray-900 rounded-lg p-6 border border-gray-700">
                  <div>
                    <div className="flex justify-between mb-3">
                      <label className="text-sm font-semibold text-gray-300">ML Confidence Threshold</label>
                      <span className="text-2xl font-bold text-blue-400">{(settings.confidence_threshold * 100).toFixed(0)}%</span>
                    </div>
                    <input
                      type="range"
                      min="50"
                      max="100"
                      value={settings.confidence_threshold * 100}
                      onChange={(e) => setSettings({ ...settings, confidence_threshold: e.target.value / 100 })}
                      className="w-full h-2 bg-gray-700 rounded-lg appearance-none cursor-pointer accent-blue-500"
                    />
                  </div>

                  <div>
                    <div className="flex justify-between mb-3">
                      <label className="text-sm font-semibold text-gray-300">Threat Score Threshold</label>
                      <span className="text-2xl font-bold text-purple-400">{settings.threat_score_threshold}/100</span>
                    </div>
                    <input
                      type="range"
                      min="30"
                      max="100"
                      value={settings.threat_score_threshold}
                      onChange={(e) => setSettings({ ...settings, threat_score_threshold: parseInt(e.target.value) })}
                      className="w-full h-2 bg-gray-700 rounded-lg appearance-none cursor-pointer accent-purple-500"
                    />
                  </div>

                  <div className="space-y-3 pt-4 border-t border-gray-700">
                    <label className="flex items-center justify-between p-4 bg-gray-800 rounded-lg border border-gray-700 hover:border-gray-600 cursor-pointer">
                      <div className="flex items-center space-x-3">
                        <input
                          type="checkbox"
                          checked={settings.auto_block_enabled}
                          onChange={(e) => setSettings({ ...settings, auto_block_enabled: e.target.checked })}
                          className="w-5 h-5 accent-blue-500"
                        />
                        <span className="text-sm font-semibold text-gray-300">Automatic IP Blocking</span>
                      </div>
                      <span className={`px-3 py-1 rounded-full text-xs font-medium ${settings.auto_block_enabled ? 'bg-green-900 text-green-300 border border-green-700' : 'bg-gray-700 text-gray-400'}`}>
                        {settings.auto_block_enabled ? 'Enabled' : 'Disabled'}
                      </span>
                    </label>

                    <label className="flex items-center justify-between p-4 bg-gray-800 rounded-lg border border-gray-700 hover:border-gray-600 cursor-pointer">
                      <div className="flex items-center space-x-3">
                        <input
                          type="checkbox"
                          checked={settings.rate_limit_enabled}
                          onChange={(e) => setSettings({ ...settings, rate_limit_enabled: e.target.checked })}
                          className="w-5 h-5 accent-blue-500"
                        />
                        <span className="text-sm font-semibold text-gray-300">Rate Limiting</span>
                      </div>
                      <span className={`px-3 py-1 rounded-full text-xs font-medium ${settings.rate_limit_enabled ? 'bg-green-900 text-green-300 border border-green-700' : 'bg-gray-700 text-gray-400'}`}>
                        {settings.rate_limit_enabled ? 'Enabled' : 'Disabled'}
                      </span>
                    </label>
                  </div>

                  <button
                    onClick={updateSettings}
                    className="w-full bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 text-white py-4 rounded-lg font-bold text-lg transition-all"
                  >
                    Save Configuration
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default IPSControlPanel;
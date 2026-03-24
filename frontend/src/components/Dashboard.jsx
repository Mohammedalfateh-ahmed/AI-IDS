import { useState, useEffect } from 'react';
import PacketCaptureControl from './PacketCaptureControl';
import { getStats, getAlerts, getModelInfo, simulateAttack, clearAlerts } from '../services/api';
import AdminPanel from './AdminPanel';
import toast, { Toaster } from 'react-hot-toast';
import SystemLogs from './SystemLogs';
import ThreatIntelligence from './ThreatIntelligence';
import BlockedIPsPanel from './BlockedIPsPanel';
import AttackPrediction from './AttackPrediction';
import IntelligencePanel from './IntelligencePanel';
import AttackDistributionChart from './AttackDistributionChart';
import AttacksOverTimeChart from './AttacksOverTimeChart';
import TopIPsChart from './TopIPsChart';
import SeverityDistributionChart from './SeverityDistributionChart';
import IPSControlPanel from './IPSControlPanel';

export default function Dashboard({ user, onLogout }) {
  const [stats, setStats] = useState({ 
    total_alerts: 0, 
    attack_types: {}, 
    average_confidence: 0, 
    total_packets: 0,
    attacks_detected: 0,
    benign_traffic: 0
  });
  const [alerts, setAlerts] = useState([]);
  const [modelInfo, setModelInfo] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [simulatingAttack, setSimulatingAttack] = useState(null);
  const [showAdminPanel, setShowAdminPanel] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [showThreatIntel, setShowThreatIntel] = useState(false);
  const [selectedAttackType, setSelectedAttackType] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (showUserMenu && !event.target.closest('.user-menu-container')) {
        setShowUserMenu(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [showUserMenu]);

  const fetchData = async () => {
    try {
      const [statsData, alertsData, modelData] = await Promise.all([
        getStats(), getAlerts(100), getModelInfo()
      ]);
      setStats({
        total_packets: statsData?.total_packets ?? 0,
        attacks_detected: statsData?.attacks_detected ?? 0,
        benign_traffic: statsData?.benign_traffic ?? 0,
        total_alerts: statsData?.total_alerts ?? 0,
        attack_types: statsData?.attack_types ?? {},
        average_confidence: statsData?.average_confidence ?? 0
      });
      setAlerts(alertsData?.alerts ?? []);
      setModelInfo(modelData);
      setLoading(false);
      setError(null);
    } catch (err) {
      setError('Cannot connect to API');
      setLoading(false);
    }
  };

  const handleSimulateAttack = async (type) => {
    setSimulatingAttack(type);
    try {
      const result = await simulateAttack(type);
      await fetchData();
      if (result.prediction === 'normal') {
        toast.success('Normal traffic detected', { duration: 3000 });
      } else {
        toast.error(`Alert: ${result.prediction} (${(result.confidence * 100).toFixed(0)}%)`, { duration: 4000 });
      }
    } catch (err) {
      toast.error('Simulation failed');
    }
    setSimulatingAttack(null);
  };

  const handleClearAlerts = async () => {
    if (window.confirm('Clear all alerts?')) {
      await clearAlerts();
      await fetchData();
      toast.success('Alerts cleared');
    }
  };

  const exportAlerts = (format) => {
    if (alerts.length === 0) return toast.error('No alerts');
    const data = format === 'json' ? JSON.stringify(alerts, null, 2) :
      ['Timestamp,Attack,Confidence,Source,Destination,Severity', ...alerts.map(a =>
        `${a.timestamp},${a.attack_type},${(a.confidence*100).toFixed(1)}%,${a.source_ip},${a.destination_ip},${a.severity||'N/A'}`
      )].join('\n');
    const link = document.createElement('a');
    link.href = `data:${format === 'json' ? 'application/json' : 'text/csv'};charset=utf-8,${encodeURIComponent(data)}`;
    link.download = `alerts_${new Date().toISOString().split('T')[0]}.${format}`;
    link.click();
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-100 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-4 border-blue-600 border-t-transparent mx-auto mb-4"></div>
          <div className="text-gray-600">Loading...</div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gray-100 flex items-center justify-center">
        <div className="bg-white p-8 rounded-lg shadow text-center">
          <div className="text-red-600 text-xl mb-4">Connection Error</div>
          <button onClick={() => window.location.reload()} className="px-6 py-2 bg-blue-600 text-white rounded">Retry</button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-100">
      <Toaster position="top-right" />
      {showAdminPanel && <AdminPanel onClose={() => setShowAdminPanel(false)} />}

      <header className="bg-gradient-to-r from-blue-600 to-blue-700 text-white shadow-lg">
        <div className="px-6 py-3 flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-3">
              <div className="w-10 h-10 bg-white/20 rounded-lg flex items-center justify-center">
                <span className="text-2xl font-bold">A</span>
              </div>
              <div>
                <h1 className="text-xl font-bold">AI-IDS Platform</h1>
                <p className="text-blue-200 text-xs">Security Monitoring Dashboard</p>
              </div>
            </div>
          </div>
          
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2 bg-white/10 px-3 py-1.5 rounded-full">
              <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
              <span className="text-sm">Online</span>
            </div>
            
            <button onClick={() => { setIsRefreshing(true); fetchData().then(() => setIsRefreshing(false)); }}
              className="p-2 hover:bg-white/10 rounded-lg">
              <svg className={`w-5 h-5 ${isRefreshing ? 'animate-spin' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
            </button>

            <div className="relative user-menu-container">
              <button onClick={() => setShowUserMenu(!showUserMenu)} className="flex items-center space-x-2 px-3 py-2 hover:bg-white/10 rounded-lg">
                <div className="w-8 h-8 bg-white/20 rounded-full flex items-center justify-center font-semibold">
                  {user?.username?.charAt(0).toUpperCase()}
                </div>
                <span className="text-sm">{user?.username}</span>
              </button>
              {showUserMenu && (
                <div className="absolute right-0 mt-2 w-48 bg-white rounded-lg shadow-lg border z-50">
                  {user?.role === 'admin' && (
                    <button onClick={() => { setShowAdminPanel(true); setShowUserMenu(false); }}
                      className="w-full px-4 py-2 text-left text-gray-700 hover:bg-gray-100 border-b">
                      Manage Users
                    </button>
                  )}
                  <button onClick={onLogout} className="w-full px-4 py-2 text-left text-red-600 hover:bg-gray-100">
                    Logout
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="px-6 pb-0">
          <div className="flex space-x-1">
            {[
              { id: 'overview', name: 'Dashboard' },
              { id: 'analytics', name: 'Analytics' },
              { id: 'threats', name: 'Events' },
              { id: 'intelligence', name: 'Intelligence' },
              { id: 'ips', name: 'IPS System' },
              { id: 'logs', name: 'Logs' }
            ].map(tab => (
              <button key={tab.id} onClick={() => { setActiveTab(tab.id); setShowUserMenu(false); }}
                className={`px-6 py-3 font-medium rounded-t-lg transition-colors ${
                  activeTab === tab.id ? 'bg-gray-100 text-blue-600' : 'text-white/80 hover:text-white hover:bg-white/10'
                }`}>
                {tab.name}
              </button>
            ))}
          </div>
        </div>
      </header>

      <main className="p-6">
        {activeTab === 'overview' && (
          <div className="space-y-6">
            <div className="grid grid-cols-5 gap-4">
              {[
                { label: 'Total Alerts', value: stats.total_alerts, color: 'red', icon: '🚨' },
                { label: 'Attacks Detected', value: stats.attacks_detected, color: 'orange', icon: '⚠️' },
                { label: 'Normal Traffic', value: stats.benign_traffic, color: 'green', icon: '✓' },
                { label: 'Total Packets', value: stats.total_packets, color: 'blue', icon: '📊' },
                { label: 'Model Accuracy', value: `${((modelInfo?.accuracy || 0) * 100).toFixed(1)}%`, color: 'purple', icon: '🎯' }
              ].map((stat, i) => (
                <div key={i} className="bg-white rounded-xl shadow-sm border border-gray-200 p-5">
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-gray-500 text-sm">{stat.label}</span>
                    <span className="text-xl">{stat.icon}</span>
                  </div>
                  <div className={`text-3xl font-bold text-${stat.color}-600`}>{stat.value}</div>
                </div>
              ))}
            </div>

            <div className="grid grid-cols-3 gap-6">
              <div className="col-span-2 bg-white rounded-xl shadow-sm border border-gray-200 p-6">
                <div className="flex items-center justify-between mb-6">
                  <h2 className="text-lg font-semibold text-gray-800">Attack Type Distribution</h2>
                  <span className="text-sm text-gray-500">{stats.total_alerts} total events</span>
                </div>
                {Object.keys(stats.attack_types).length > 0 ? (
                  <div className="space-y-4">
                    {Object.entries(stats.attack_types).map(([type, count]) => {
                      const pct = (count / Math.max(stats.total_alerts, 1)) * 100;
                      return (
                        <div key={type}>
                          <div className="flex justify-between mb-1">
                            <span className="text-sm font-medium text-gray-700">{type}</span>
                            <span className="text-sm text-gray-500">{count} ({pct.toFixed(0)}%)</span>
                          </div>
                          <div className="h-3 bg-gray-100 rounded-full overflow-hidden">
                            <div className="h-full bg-blue-500 rounded-full" style={{ width: `${pct}%` }}></div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <div className="text-center py-12 text-gray-400">
                    <div className="text-4xl mb-2">📊</div>
                    <p>No attack data yet</p>
                  </div>
                )}
              </div>

              <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
                <h2 className="text-lg font-semibold text-gray-800 mb-6">Model Performance</h2>
                <div className="space-y-4">
                  <div className="p-4 bg-gray-50 rounded-lg text-center">
                    <div className="text-sm text-gray-500 mb-1">XGBoost NSL-KDD</div>
                    <div className="text-xs text-gray-400">122 Features • 5 Classes</div>
                  </div>
                  {[
                    { label: 'Accuracy', value: modelInfo?.accuracy, color: 'green' },
                    { label: 'Precision', value: modelInfo?.precision, color: 'blue' },
                    { label: 'Recall', value: modelInfo?.recall, color: 'purple' },
                    { label: 'F1 Score', value: modelInfo?.f1_score, color: 'orange' }
                  ].map((m, i) => (
                    <div key={i} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                      <span className="text-gray-600">{m.label}</span>
                      <span className={`font-bold text-${m.color}-600`}>{((m.value || 0) * 100).toFixed(1)}%</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
              <h2 className="text-lg font-semibold text-gray-800 mb-4">Attack Simulation</h2>
              <div className="flex flex-wrap gap-3">
                {['DoS', 'Probe', 'R2L', 'U2R'].map(type => (
                  <button key={type} onClick={() => handleSimulateAttack(type)} disabled={simulatingAttack === type}
                    className="px-6 py-3 bg-red-500 hover:bg-red-600 disabled:bg-gray-300 text-white font-medium rounded-lg transition-colors">
                    {simulatingAttack === type ? 'Running...' : `Simulate ${type}`}
                  </button>
                ))}
                <button onClick={() => handleSimulateAttack('Normal')} disabled={simulatingAttack === 'Normal'}
                  className="px-6 py-3 bg-green-500 hover:bg-green-600 disabled:bg-gray-300 text-white font-medium rounded-lg transition-colors">
                  {simulatingAttack === 'Normal' ? 'Running...' : 'Simulate Normal'}
                </button>
                <button onClick={handleClearAlerts}
                  className="px-6 py-3 bg-gray-500 hover:bg-gray-600 text-white font-medium rounded-lg transition-colors">
                  Clear All
                </button>
              </div>
            </div>

            <PacketCaptureControl user={user} />
          </div>
        )}

        {activeTab === 'analytics' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <AttackDistributionChart data={stats?.attack_types} />
              <SeverityDistributionChart alerts={alerts} />
            </div>

            <div>
              <AttacksOverTimeChart alerts={alerts} />
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <TopIPsChart alerts={alerts} />
              
              <div className="bg-white rounded-lg shadow p-6">
                <h3 className="text-lg font-semibold text-gray-900 mb-4">Detection Statistics</h3>
                <div className="space-y-3">
                  <div className="flex justify-between py-3 border-b">
                    <span className="text-gray-600">Total Events Analyzed</span>
                    <span className="font-bold text-gray-900">{stats.total_packets}</span>
                  </div>
                  <div className="flex justify-between py-3 border-b">
                    <span className="text-gray-600">Attacks Detected</span>
                    <span className="font-bold text-red-600">{stats.attacks_detected}</span>
                  </div>
                  <div className="flex justify-between py-3 border-b">
                    <span className="text-gray-600">Normal Traffic</span>
                    <span className="font-bold text-green-600">{stats.benign_traffic}</span>
                  </div>
                  <div className="flex justify-between py-3 border-b">
                    <span className="text-gray-600">Detection Rate</span>
                    <span className="font-bold text-blue-600">
                      {stats.total_packets > 0 ? ((stats.attacks_detected / stats.total_packets) * 100).toFixed(1) : 0}%
                    </span>
                  </div>
                  <div className="flex justify-between py-3">
                    <span className="text-gray-600">Avg Confidence</span>
                    <span className="font-bold text-purple-600">{(stats.average_confidence * 100).toFixed(1)}%</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'threats' && (
          <div className="space-y-6">
            <div className="bg-white rounded-xl shadow-sm border border-gray-200">
              <div className="p-6 border-b border-gray-200 flex justify-between items-center">
                <h2 className="text-lg font-semibold text-gray-800">Security Events ({alerts.length})</h2>
                {alerts.length > 0 && (
                  <div className="flex gap-2">
                    <button onClick={() => exportAlerts('csv')} className="px-4 py-2 bg-green-500 hover:bg-green-600 text-white text-sm rounded-lg">CSV</button>
                    <button onClick={() => exportAlerts('json')} className="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white text-sm rounded-lg">JSON</button>
                  </div>
                )}
              </div>
              
              {alerts.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead className="bg-gray-50 border-b border-gray-200">
                      <tr>
                        <th className="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase">Time</th>
                        <th className="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase">Attack</th>
                        <th className="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase">Confidence</th>
                        <th className="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase">Source</th>
                        <th className="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase">Destination</th>
                        <th className="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase">Severity</th>
                        <th className="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-100">
                      {alerts.slice().reverse().map((alert, i) => (
                        <tr key={i} className="hover:bg-gray-50">
                          <td className="px-6 py-4 text-sm text-gray-600">{alert.timestamp}</td>
                          <td className="px-6 py-4">
                            <button onClick={() => { setSelectedAttackType(alert.attack_type); setShowThreatIntel(true); }}
                              className="text-blue-600 hover:underline font-medium">
                              {alert.attack_type}
                            </button>
                          </td>
                          <td className="px-6 py-4">
                            <div className="flex items-center space-x-2">
                              <div className="w-20 h-2 bg-gray-200 rounded-full overflow-hidden">
                                <div className={`h-full rounded-full ${alert.confidence > 0.8 ? 'bg-red-500' : alert.confidence > 0.6 ? 'bg-yellow-500' : 'bg-green-500'}`}
                                  style={{ width: `${alert.confidence * 100}%` }}></div>
                              </div>
                              <span className="text-sm font-medium">{(alert.confidence * 100).toFixed(0)}%</span>
                            </div>
                          </td>
                          <td className="px-6 py-4 text-sm font-mono text-gray-700">{alert.source_ip}</td>
                          <td className="px-6 py-4 text-sm font-mono text-gray-700">{alert.destination_ip}</td>
                          <td className="px-6 py-4">
                            <span className={`px-2 py-1 text-xs font-medium rounded ${
                              alert.severity === 'Critical' ? 'bg-red-100 text-red-700' :
                              alert.severity === 'High' ? 'bg-orange-100 text-orange-700' :
                              alert.severity === 'Medium' ? 'bg-yellow-100 text-yellow-700' :
                              'bg-blue-100 text-blue-700'
                            }`}>
                              {alert.severity}
                            </span>
                          </td>
                          <td className="px-6 py-4">
                            {alert.blocked ? (
                              <span className="px-2 py-1 text-xs font-medium rounded bg-red-100 text-red-700">Blocked</span>
                            ) : (
                              <span className="px-2 py-1 text-xs font-medium rounded bg-green-100 text-green-700">Active</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="p-16 text-center">
                  <div className="text-5xl mb-4">🛡️</div>
                  <p className="text-gray-500 text-lg">No security events detected</p>
                  <p className="text-gray-400 text-sm mt-1">Run attack simulations to test the system</p>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'intelligence' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <IntelligencePanel />
            <AttackPrediction />
            <BlockedIPsPanel userRole={user?.role} />
          </div>
        )}

        {activeTab === 'ips' && (
          <IPSControlPanel />
        )}

        {activeTab === 'logs' && <SystemLogs user={user} />}
      </main>

      {showThreatIntel && selectedAttackType && (
        <ThreatIntelligence attackType={selectedAttackType} onClose={() => setShowThreatIntel(false)} />
      )}
    </div>
  );
}
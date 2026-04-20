import { useState, useEffect } from 'react';
import {
  Activity, TrendingUp, FileText, Shield, AlertTriangle,
  CheckCircle, Info, Download, Clock, Calendar, RefreshCw,
  WifiOff, ChevronDown, ChevronUp
} from 'lucide-react';

export default function IntelligencePage() {
  const [activeTab, setActiveTab] = useState('health');

  const tabs = [
    { id: 'health',     label: 'Network Health',      icon: Activity   },
    { id: 'intel',      label: 'Threat Intelligence', icon: Shield     },
    { id: 'reports',    label: 'Security Report',     icon: FileText   },
  ];

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="bg-white border-b border-gray-200 px-8 pt-6 shadow-sm">
        <div className="mb-5">
          <h1 className="text-2xl font-extrabold text-gray-900 tracking-tight">Intelligence Center</h1>
          <p className="text-sm text-gray-400 mt-1">Real-time threat analysis, predictions, and security reporting</p>
        </div>
        <div className="flex">
          {tabs.map(tab => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-6 py-3 text-sm font-semibold border-b-2 transition-all duration-150 ${
                  isActive
                    ? 'border-blue-600 text-blue-600 bg-blue-50/60'
                    : 'border-transparent text-gray-500 hover:text-gray-800 hover:bg-gray-50'
                }`}
              >
                <Icon className="w-4 h-4" />
                {tab.label}
              </button>
            );
          })}
        </div>
      </div>

      <div className="p-8">
        {activeTab === 'health'  && <NetworkHealthTab />}
        {activeTab === 'intel'   && <ThreatIntelligenceTab />}
        {activeTab === 'reports' && <SecurityReportTab />}
      </div>
    </div>
  );
}

function NetworkHealthTab() {
  const [networkHealth, setNetworkHealth] = useState(null);
  const [topThreats, setTopThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expandedThreat, setExpandedThreat] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, []);

  const fetchData = async () => {
    try {
      const token = localStorage.getItem('token');
      const [healthRes, threatsRes] = await Promise.all([
        fetch('http://localhost:8000/intelligence/network-health', {
          headers: { Authorization: `Bearer ${token}` }
        }),
        fetch('http://localhost:8000/intelligence/top-threats?limit=5', {
          headers: { Authorization: `Bearer ${token}` }
        }),
      ]);
      if (healthRes.ok)  setNetworkHealth(await healthRes.json());
      if (threatsRes.ok) {
        const d = await threatsRes.json();
        setTopThreats(d.top_threats || []);
      }
      setLastUpdated(new Date());
      setLoading(false);
    } catch {
      setLoading(false);
    }
  };

  const getHealthStyle = (score) => {
    if (score >= 80) return { ring: 'border-green-400', bg: 'bg-green-50', text: 'text-green-700', bar: 'bg-green-500', label: 'HEALTHY',  dot: 'bg-green-500'  };
    if (score >= 60) return { ring: 'border-yellow-400', bg: 'bg-yellow-50', text: 'text-yellow-700', bar: 'bg-yellow-400', label: 'DEGRADED', dot: 'bg-yellow-400' };
    return            { ring: 'border-red-400',    bg: 'bg-red-50',    text: 'text-red-700',    bar: 'bg-red-500',    label: 'CRITICAL', dot: 'bg-red-500'    };
  };

  const getThreatBadge = (level) => {
    const m = {
      CRITICAL: 'bg-red-100 text-red-800 border border-red-300',
      HIGH:     'bg-orange-100 text-orange-800 border border-orange-300',
      MEDIUM:   'bg-yellow-100 text-yellow-800 border border-yellow-300',
    };
    return m[level] || 'bg-gray-100 text-gray-800 border border-gray-300';
  };

  if (loading) return <Spinner />;

  const hs = networkHealth ? getHealthStyle(networkHealth.health_score) : null;

  return (
    <div className="grid grid-cols-2 gap-6">
      <Card>
        <CardHeader icon={<Activity className="w-4 h-4 text-blue-600" />} iconBg="bg-blue-100" title="Network Health" subtitle="Real-time status" />

        {networkHealth ? (
          <div className="mt-5 space-y-5">
            <div className={`border-2 ${hs.ring} ${hs.bg} rounded-2xl p-6 text-center`}>
              <div className={`text-6xl font-black ${hs.text} leading-none mb-1`}>{networkHealth.health_score}%</div>
              <div className="flex items-center justify-center gap-2 mt-2">
                <span className={`w-2 h-2 rounded-full ${hs.dot} animate-pulse`} />
                <span className={`text-xs font-bold tracking-widest ${hs.text}`}>{hs.label}</span>
              </div>
              <div className="mt-4 h-2 bg-white/70 rounded-full overflow-hidden mx-4">
                <div
                  className={`h-full rounded-full ${hs.bar} transition-all duration-1000`}
                  style={{ width: `${networkHealth.health_score}%` }}
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              {[
                { label: 'Total IPs',  value: networkHealth.total_ips,     color: 'text-gray-900',   bg: 'bg-gray-50 border-gray-200'   },
                { label: 'At Risk',    value: networkHealth.at_risk_ips,   color: 'text-red-600',    bg: 'bg-red-50 border-red-200'     },
                { label: 'Malicious',  value: networkHealth.malicious_ips, color: 'text-orange-600', bg: 'bg-orange-50 border-orange-200' },
                { label: 'Unknown',    value: networkHealth.unknown_ips,   color: 'text-gray-500',   bg: 'bg-gray-50 border-gray-200'   },
              ].map(item => (
                <div key={item.label} className={`p-4 rounded-xl border ${item.bg}`}>
                  <div className="text-xs text-gray-400 mb-1 font-medium">{item.label}</div>
                  <div className={`text-3xl font-black ${item.color}`}>{item.value}</div>
                </div>
              ))}
            </div>

            {lastUpdated && (
              <div className="flex items-center gap-1.5 text-xs text-gray-400">
                <RefreshCw className="w-3 h-3" />
                Last updated {lastUpdated.toLocaleTimeString()}
              </div>
            )}
          </div>
        ) : (
          <EmptyState icon={<WifiOff className="w-10 h-10 text-gray-300" />} text="No health data available" />
        )}
      </Card>

      <Card>
        <CardHeader icon={<Shield className="w-4 h-4 text-purple-600" />} iconBg="bg-purple-100" title="Top Threats" subtitle="Highest risk IPs" />

        {topThreats.length > 0 ? (
          <div className="mt-5 space-y-2">
            {topThreats.map((threat, index) => {
              const isExpanded = expandedThreat === index;
              return (
                <div key={index} className="rounded-xl border border-gray-200 overflow-hidden hover:border-red-300 transition-colors">
                  <button
                    onClick={() => setExpandedThreat(isExpanded ? null : index)}
                    className="w-full p-4 bg-white hover:bg-gray-50 transition-colors text-left"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <span className="w-6 h-6 rounded-full bg-gray-100 text-gray-500 text-xs font-bold flex items-center justify-center">
                          {index + 1}
                        </span>
                        <span className="font-mono text-sm font-bold text-gray-900">{threat.ip_address}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 text-xs font-bold rounded-full ${getThreatBadge(threat.threat_level)}`}>
                          {threat.threat_level}
                        </span>
                        {isExpanded
                          ? <ChevronUp className="w-4 h-4 text-gray-400" />
                          : <ChevronDown className="w-4 h-4 text-gray-400" />
                        }
                      </div>
                    </div>
                    <div className="grid grid-cols-3 gap-2 mt-3 text-xs">
                      <div>
                        <span className="text-gray-400">Risk</span>
                        <div className="font-bold text-red-600 mt-0.5">{threat.risk_score?.toFixed(1)}</div>
                      </div>
                      <div>
                        <span className="text-gray-400">Attacks</span>
                        <div className="font-bold text-gray-900 mt-0.5">{threat.attack_count}</div>
                      </div>
                      <div>
                        <span className="text-gray-400">Types</span>
                        <div className="font-bold text-gray-900 mt-0.5">{threat.attack_types?.length}</div>
                      </div>
                    </div>
                  </button>

                  {isExpanded && (
                    <div className="px-4 pb-4 bg-red-50 border-t border-red-100">
                      <div className="text-xs font-semibold text-gray-500 mt-3 mb-2">DETECTED ATTACK TYPES</div>
                      <div className="flex flex-wrap gap-1">
                        {threat.attack_types?.map((type, i) => (
                          <span key={i} className="px-2 py-0.5 bg-red-100 text-red-800 text-xs font-semibold rounded-full border border-red-200">
                            {type}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        ) : (
          <EmptyState icon={<Shield className="w-10 h-10 text-gray-300" />} text="No threats detected" sub="System is clean" />
        )}
      </Card>
    </div>
  );
}

function ThreatIntelligenceTab() {
  const [prediction, setPrediction] = useState(null);
  const [intel, setIntel] = useState(null);
  const [loading, setLoading] = useState(true);
  const [intelLoading, setIntelLoading] = useState(false);

  useEffect(() => {
    fetchPrediction();
    const interval = setInterval(fetchPrediction, 10000);
    return () => clearInterval(interval);
  }, []);

  const fetchPrediction = async () => {
    try {
      const token = localStorage.getItem('token');
      const res = await fetch('http://localhost:8000/intelligence/attack-forecast', {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) setPrediction(await res.json());
      setLoading(false);
    } catch {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (prediction?.forecast_available && prediction?.predicted_attack) {
      fetchIntel(prediction.predicted_attack);
    }
  }, [prediction]);

  const fetchIntel = async (attackType) => {
    setIntelLoading(true);
    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`http://localhost:8000/threat-intelligence/${attackType}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) setIntel(await res.json());
    } catch {}
    setIntelLoading(false);
  };

  const getSeverityStyle = (s) => {
    const m = {
      CRITICAL: 'bg-red-100 text-red-800 border-red-300',
      HIGH:     'bg-orange-100 text-orange-800 border-orange-300',
      MEDIUM:   'bg-yellow-100 text-yellow-800 border-yellow-300',
    };
    return m[s] || 'bg-gray-100 text-gray-800 border-gray-300';
  };

  if (loading) return <Spinner />;

  if (!prediction?.forecast_available) {
    return (
      <Card className="py-16 text-center">
        <TrendingUp className="w-16 h-16 text-gray-200 mx-auto mb-4" />
        <h3 className="text-lg font-bold text-gray-500 mb-2">Not enough data for prediction</h3>
        <p className="text-sm text-gray-400">Collect more attack samples to enable AI-powered forecasting</p>
      </Card>
    );
  }

  return (
    <div className="grid grid-cols-2 gap-6">
      <Card>
        <CardHeader icon={<TrendingUp className="w-4 h-4 text-red-600" />} iconBg="bg-red-100" title="Attack Forecast" subtitle="AI-powered prediction" />

        <div className="mt-5 space-y-4">
          <div className="rounded-2xl border-2 border-red-200 bg-red-50 p-6">
            <div className="flex items-center gap-2 mb-4">
              <span className="w-2 h-2 bg-red-500 rounded-full animate-pulse" />
              <span className="text-xs font-bold text-red-500 tracking-widest">PREDICTION ACTIVE</span>
            </div>

            <div className="mb-5">
              <div className="text-xs text-gray-400 mb-1 font-medium">NEXT LIKELY ATTACK</div>
              <div className="text-4xl font-black text-gray-900 uppercase tracking-tight">
                {prediction.predicted_attack}
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <div className="text-xs text-gray-400 mb-1 font-medium">Confidence</div>
                <div className="text-3xl font-black text-gray-900">{prediction.confidence}%</div>
                <div className="mt-2 h-1.5 bg-red-200 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-red-500 rounded-full transition-all duration-700"
                    style={{ width: `${prediction.confidence}%` }}
                  />
                </div>
              </div>
              <div>
                <div className="text-xs text-gray-400 mb-1 font-medium">Time Window</div>
                <div className="text-sm font-bold text-gray-900 mt-1">Next 5–10 minutes</div>
                <div className="text-xs text-gray-400 mt-1">Based on traffic patterns</div>
              </div>
            </div>
          </div>

          <div className="rounded-xl border border-yellow-200 bg-yellow-50 p-4">
            <div className="flex items-center gap-2 text-yellow-700 font-semibold text-sm mb-1">
              <AlertTriangle className="w-4 h-4" />
              Recommendation
            </div>
            <p className="text-xs text-gray-600 leading-relaxed">
              High probability of continued <strong>{prediction.predicted_attack}</strong> attacks.
              Review firewall rules and consider enabling auto-blocking for this category.
            </p>
          </div>
        </div>
      </Card>

      <Card>
        <CardHeader
          icon={<Info className="w-4 h-4 text-blue-600" />}
          iconBg="bg-blue-100"
          title="Threat Intelligence"
          subtitle={intel ? `Details for ${prediction.predicted_attack}` : 'Loading details...'}
        />

        {intelLoading ? (
          <div className="mt-5 flex items-center justify-center h-48"><Spinner /></div>
        ) : intel ? (
          <div className="mt-5 space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <InfoBox label="Category" value={intel.category} />
              <div className={`p-3 rounded-xl border ${getSeverityStyle(intel.severity)}`}>
                <div className="text-xs mb-1 opacity-60 font-medium">Severity</div>
                <div className="text-sm font-black">{intel.severity}</div>
              </div>
              <InfoBox label="CVSS Score" value={`${intel.cvss_score}/10`} valueClass="text-orange-600" />
              <InfoBox label="MITRE ATT&CK" value={intel.mitre_attack_id} valueClass="text-purple-700" />
            </div>

            <div className="p-4 bg-gray-50 rounded-xl border border-gray-200">
              <div className="text-xs font-semibold text-gray-400 mb-2 tracking-wider">DESCRIPTION</div>
              <p className="text-sm text-gray-700 leading-relaxed">{intel.description}</p>
            </div>

            {intel.statistics && (
              <div className="grid grid-cols-3 gap-3">
                <div className="p-3 bg-blue-50 border border-blue-200 rounded-xl text-center">
                  <div className="text-xs text-blue-500 mb-1 font-medium">Total Detections</div>
                  <div className="text-2xl font-black text-blue-900">{intel.statistics.total_detections}</div>
                </div>
                <div className="p-3 bg-red-50 border border-red-200 rounded-xl text-center">
                  <div className="text-xs text-red-500 mb-1 font-medium">IPs Blocked</div>
                  <div className="text-2xl font-black text-red-900">{intel.statistics.ips_blocked}</div>
                </div>
                <div className="p-3 bg-yellow-50 border border-yellow-200 rounded-xl text-center">
                  <div className="text-xs text-yellow-600 mb-1 font-medium">Last Seen</div>
                  <div className="text-sm font-black text-yellow-900">{intel.statistics.last_seen}</div>
                </div>
              </div>
            )}

            {intel.recommendations?.length > 0 && (
              <div className="p-4 bg-green-50 rounded-xl border border-green-200">
                <div className="flex items-center gap-2 text-green-700 text-xs font-bold mb-3 tracking-wider">
                  <CheckCircle className="w-4 h-4" />
                  RECOMMENDATIONS
                </div>
                <ul className="space-y-2">
                  {intel.recommendations.slice(0, 3).map((rec, i) => (
                    <li key={i} className="text-xs text-gray-700 flex gap-2 leading-relaxed">
                      <span className="text-green-600 font-bold shrink-0">{i + 1}.</span>
                      <span>{rec}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        ) : (
          <EmptyState icon={<Info className="w-10 h-10 text-gray-300" />} text="No threat intelligence available" sub="for this attack type" />
        )}
      </Card>
    </div>
  );
}

function SecurityReportTab() {
  const [reportPeriod, setReportPeriod] = useState('month');
  const [reportData, setReportData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => { generateReport(reportPeriod); }, [reportPeriod]);

  const generateReport = async (period) => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const res = await fetch('http://localhost:8000/database/alerts?limit=1000', {
        headers: { Authorization: `Bearer ${token}` }
      });

      let alerts = [];
      if (res.ok) {
        const data = await res.json();
        alerts = data.alerts || [];
      }

      const cutoff = new Date();
      if      (period === 'month') cutoff.setMonth(cutoff.getMonth() - 1);
      else if (period === 'year')  cutoff.setFullYear(cutoff.getFullYear() - 1);
      else                         cutoff.setDate(cutoff.getDate() - 7);

      const filtered = alerts.filter(a => new Date(a.timestamp) >= cutoff);

      const attackTypes    = {};
      const severityCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
      const hourlyDist     = Array(24).fill(0);
      const dailyDist      = Array(7).fill(0);

      filtered.forEach(alert => {
        attackTypes[alert.attack_type] = (attackTypes[alert.attack_type] || 0) + 1;
        severityCounts[alert.severity] = (severityCounts[alert.severity] || 0) + 1;
        const d = new Date(alert.timestamp);
        hourlyDist[d.getHours()]++;
        dailyDist[d.getDay()]++;
      });

      const sortedAttacks = Object.entries(attackTypes).sort((a, b) => b[1] - a[1]).slice(0, 5);
      const peakHour = hourlyDist.indexOf(Math.max(...hourlyDist));
      const peakDay  = ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'][
        dailyDist.indexOf(Math.max(...dailyDist))
      ];

      setReportData({
        totalAlerts: filtered.length,
        attackTypes: sortedAttacks,
        severityCounts,
        peakHour,
        peakDay,
        blockedCount: filtered.filter(a => a.blocked).length,
        averageConfidence: filtered.length > 0
          ? (filtered.reduce((s, a) => s + a.confidence, 0) / filtered.length * 100).toFixed(1)
          : 0,
      });
    } catch {}
    setLoading(false);
  };

  const downloadReport = () => {
    if (!reportData) return;
    const periodName = reportPeriod === 'month' ? 'Monthly' : reportPeriod === 'year' ? 'Yearly' : 'Weekly';
    const content = `
AI-IDS SECURITY REPORT
${periodName} Report — Generated: ${new Date().toLocaleString()}

===========================================
SUMMARY
===========================================
Total Alerts:        ${reportData.totalAlerts}
Blocked Attacks:     ${reportData.blockedCount}
Average Confidence:  ${reportData.averageConfidence}%

===========================================
TOP 5 ATTACK TYPES
===========================================
${reportData.attackTypes.map(([type, count], i) => `${i + 1}. ${type}: ${count} attacks`).join('\n')}

===========================================
SEVERITY BREAKDOWN
===========================================
Critical: ${reportData.severityCounts.Critical}
High:     ${reportData.severityCounts.High}
Medium:   ${reportData.severityCounts.Medium}
Low:      ${reportData.severityCounts.Low}

===========================================
ATTACK PATTERNS
===========================================
Peak Activity Hour: ${reportData.peakHour}:00
Peak Activity Day:  ${reportData.peakDay}

===========================================
RECOMMENDATIONS
===========================================
${reportData.totalAlerts > 100 ? '⚠ High attack volume. Consider enabling Smart IPS.' : ''}
${reportData.severityCounts.Critical > 10 ? '⚠ Multiple critical threats. Review security policies.' : ''}
${reportData.blockedCount < reportData.totalAlerts / 2 ? '⚠ Less than 50% blocked. Enable auto-blocking.' : ''}
${reportData.attackTypes[0]?.[1] > 20 ? `⚠ High frequency of ${reportData.attackTypes[0][0]} attacks. Update detection rules.` : ''}

===========================================
Generated by AI-IDS Platform
===========================================
`.trim();

    const blob = new Blob([content], { type: 'text/plain' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `AI-IDS_${periodName}_Report_${new Date().toISOString().split('T')[0]}.txt`;
    a.click();
  };

  return (
    <div className="bg-white rounded-2xl border border-gray-200 shadow-sm p-6">
      <div className="flex items-center justify-between mb-6">
        <CardHeader icon={<FileText className="w-4 h-4 text-green-600" />} iconBg="bg-green-100" title="Security Report" subtitle="Attack analysis and trends" />
        <div className="flex items-center gap-3">
          <select
            value={reportPeriod}
            onChange={(e) => setReportPeriod(e.target.value)}
            className="px-4 py-2 border border-gray-200 rounded-xl text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none bg-gray-50"
          >
            <option value="week">Last 7 Days</option>
            <option value="month">Last Month</option>
            <option value="year">Last Year</option>
          </select>
          <button
            onClick={downloadReport}
            disabled={!reportData || loading}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-40 text-white text-sm font-bold rounded-xl transition shadow-sm"
          >
            <Download className="w-4 h-4" />
            Download
          </button>
        </div>
      </div>

      {loading ? <Spinner /> : reportData ? (
        <div className="space-y-6">
          <div className="grid grid-cols-3 gap-4">
            {[
              { label: 'TOTAL ALERTS',    value: reportData.totalAlerts,          bg: 'bg-blue-50 border-blue-200',     text: 'text-blue-900',   lbl: 'text-blue-500'   },
              { label: 'BLOCKED',         value: reportData.blockedCount,         bg: 'bg-red-50 border-red-200',       text: 'text-red-900',    lbl: 'text-red-500'    },
              { label: 'AVG CONFIDENCE',  value: `${reportData.averageConfidence}%`, bg: 'bg-purple-50 border-purple-200', text: 'text-purple-900', lbl: 'text-purple-500' },
            ].map(item => (
              <div key={item.label} className={`p-5 rounded-2xl border ${item.bg} text-center`}>
                <div className={`text-xs font-bold mb-1 tracking-widest ${item.lbl}`}>{item.label}</div>
                <div className={`text-5xl font-black ${item.text}`}>{item.value}</div>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-3 gap-6">
            <div className="col-span-2 space-y-4">
              <h4 className="font-bold text-gray-900">Top Attack Types</h4>
              {reportData.attackTypes.length === 0 ? (
                <p className="text-sm text-gray-400">No attack data for this period</p>
              ) : (
                reportData.attackTypes.map(([type, count], index) => {
                  const pct = reportData.totalAlerts > 0
                    ? (count / reportData.totalAlerts * 100).toFixed(1)
                    : 0;
                  return (
                    <div key={index}>
                      <div className="flex justify-between mb-1.5">
                        <span className="text-sm font-semibold text-gray-800">{type}</span>
                        <span className="text-sm text-gray-400">
                          {count} <span className="text-gray-300">({pct}%)</span>
                        </span>
                      </div>
                      <div className="h-2.5 bg-gray-100 rounded-full overflow-hidden">
                        <div
                          className="h-full rounded-full bg-gradient-to-r from-blue-500 to-blue-700 transition-all duration-700"
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                    </div>
                  );
                })
              )}

              <div className="grid grid-cols-2 gap-4 pt-2">
                <div className="p-4 bg-gray-50 rounded-2xl border border-gray-200">
                  <div className="flex items-center gap-2 text-gray-400 mb-2">
                    <Clock className="w-4 h-4" />
                    <span className="text-xs font-semibold">Peak Hour</span>
                  </div>
                  <div className="text-3xl font-black text-gray-900">{reportData.peakHour}:00</div>
                </div>
                <div className="p-4 bg-gray-50 rounded-2xl border border-gray-200">
                  <div className="flex items-center gap-2 text-gray-400 mb-2">
                    <Calendar className="w-4 h-4" />
                    <span className="text-xs font-semibold">Peak Day</span>
                  </div>
                  <div className="text-3xl font-black text-gray-900">{reportData.peakDay}</div>
                </div>
              </div>
            </div>

            <div>
              <h4 className="font-bold text-gray-900 mb-4">Severity Breakdown</h4>
              <div className="space-y-2">
                {[
                  { label: 'Critical', key: 'Critical', cls: 'bg-red-50 border-red-200 text-red-700',       val: 'text-red-900'    },
                  { label: 'High',     key: 'High',     cls: 'bg-orange-50 border-orange-200 text-orange-700', val: 'text-orange-900' },
                  { label: 'Medium',   key: 'Medium',   cls: 'bg-yellow-50 border-yellow-200 text-yellow-700', val: 'text-yellow-900' },
                  { label: 'Low',      key: 'Low',      cls: 'bg-blue-50 border-blue-200 text-blue-700',     val: 'text-blue-900'   },
                ].map(item => (
                  <div key={item.key} className={`flex justify-between items-center p-3 rounded-xl border ${item.cls}`}>
                    <span className="text-sm font-semibold">{item.label}</span>
                    <span className={`text-2xl font-black ${item.val}`}>{reportData.severityCounts[item.key]}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      ) : (
        <EmptyState icon={<FileText className="w-10 h-10 text-gray-300" />} text="No report data available" />
      )}
    </div>
  );
}

function Card({ children, className = '' }) {
  return (
    <div className={`bg-white rounded-2xl border border-gray-200 shadow-sm p-6 ${className}`}>
      {children}
    </div>
  );
}

function CardHeader({ icon, iconBg, title, subtitle }) {
  return (
    <div className="flex items-center gap-3">
      <div className={`w-9 h-9 ${iconBg} rounded-xl flex items-center justify-center`}>{icon}</div>
      <div>
        <div className="font-bold text-gray-900 text-sm">{title}</div>
        <div className="text-xs text-gray-400">{subtitle}</div>
      </div>
    </div>
  );
}

function InfoBox({ label, value, valueClass = 'text-gray-900' }) {
  return (
    <div className="p-3 bg-gray-50 rounded-xl border border-gray-200">
      <div className="text-xs text-gray-400 mb-1 font-medium">{label}</div>
      <div className={`text-sm font-black ${valueClass}`}>{value}</div>
    </div>
  );
}

function EmptyState({ icon, text, sub }) {
  return (
    <div className="text-center py-12">
      <div className="flex justify-center mb-3">{icon}</div>
      <p className="text-sm text-gray-500 font-medium">{text}</p>
      {sub && <p className="text-xs text-gray-400 mt-1">{sub}</p>}
    </div>
  );
}

function Spinner() {
  return (
    <div className="flex items-center justify-center h-48">
      <div className="animate-spin rounded-full h-10 w-10 border-4 border-blue-600 border-t-transparent" />
    </div>
  );
}
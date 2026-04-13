import { useState, useEffect } from 'react';
import { Shield, TrendingUp, AlertTriangle, Activity, Clock, FileText, Download, Calendar } from 'lucide-react';

export default function EnhancedIntelligencePanel() {
  const [networkHealth, setNetworkHealth] = useState(null);
  const [topThreats, setTopThreats] = useState([]);
  const [prediction, setPrediction] = useState(null);
  const [loading, setLoading] = useState(true);
  const [reportPeriod, setReportPeriod] = useState('month');
  const [reportData, setReportData] = useState(null);

  useEffect(() => {
    fetchIntelligenceData();
    const interval = setInterval(fetchIntelligenceData, 10000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (reportPeriod) {
      generateReport(reportPeriod);
    }
  }, [reportPeriod]);

  const fetchIntelligenceData = async () => {
    try {
      const token = localStorage.getItem('token');
      
      const [healthRes, threatsRes, predRes] = await Promise.all([
        fetch('http://localhost:8000/intelligence/network-health', {
          headers: { 'Authorization': `Bearer ${token}` }
        }),
        fetch('http://localhost:8000/intelligence/top-threats?limit=5', {
          headers: { 'Authorization': `Bearer ${token}` }
        }),
        fetch('http://localhost:8000/intelligence/attack-forecast', {
          headers: { 'Authorization': `Bearer ${token}` }
        })
      ]);

      if (healthRes.ok) {
        const health = await healthRes.json();
        setNetworkHealth(health);
      }

      if (threatsRes.ok) {
        const threats = await threatsRes.json();
        setTopThreats(threats.top_threats || []);
      }

      if (predRes.ok) {
        const pred = await predRes.json();
        setPrediction(pred);
      }

      setLoading(false);
    } catch (error) {
      console.error('Error fetching intelligence:', error);
      setLoading(false);
    }
  };

  const generateReport = async (period) => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`http://localhost:8000/stats`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (response.ok) {
        const stats = await response.json();
        
        const alertsRes = await fetch('http://localhost:8000/database/alerts?limit=1000', {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        
        let alerts = [];
        if (alertsRes.ok) {
          const data = await alertsRes.json();
          alerts = data.alerts || [];
        }

        const now = new Date();
        const cutoffDate = new Date();
        
        if (period === 'month') {
          cutoffDate.setMonth(cutoffDate.getMonth() - 1);
        } else if (period === 'year') {
          cutoffDate.setFullYear(cutoffDate.getFullYear() - 1);
        } else {
          cutoffDate.setDate(cutoffDate.getDate() - 7);
        }

        const periodAlerts = alerts.filter(alert => {
          const alertDate = new Date(alert.timestamp);
          return alertDate >= cutoffDate;
        });

        const attackTypes = {};
        const severityCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
        const hourlyDistribution = Array(24).fill(0);
        const dailyDistribution = Array(7).fill(0);

        periodAlerts.forEach(alert => {
          attackTypes[alert.attack_type] = (attackTypes[alert.attack_type] || 0) + 1;
          severityCounts[alert.severity] = (severityCounts[alert.severity] || 0) + 1;
          
          const date = new Date(alert.timestamp);
          const hour = date.getHours();
          const day = date.getDay();
          hourlyDistribution[hour]++;
          dailyDistribution[day]++;
        });

        const sortedAttacks = Object.entries(attackTypes)
          .sort((a, b) => b[1] - a[1])
          .slice(0, 5);

        const peakHour = hourlyDistribution.indexOf(Math.max(...hourlyDistribution));
        const peakDay = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'][
          dailyDistribution.indexOf(Math.max(...dailyDistribution))
        ];

        setReportData({
          period,
          totalAlerts: periodAlerts.length,
          attackTypes: sortedAttacks,
          severityCounts,
          peakHour,
          peakDay,
          blockedCount: periodAlerts.filter(a => a.blocked).length,
          averageConfidence: periodAlerts.length > 0 
            ? (periodAlerts.reduce((sum, a) => sum + a.confidence, 0) / periodAlerts.length * 100).toFixed(1)
            : 0
        });
      }
    } catch (error) {
      console.error('Error generating report:', error);
    }
  };

  const downloadReport = () => {
    if (!reportData) return;

    const periodName = reportPeriod === 'month' ? 'Monthly' : reportPeriod === 'year' ? 'Yearly' : 'Weekly';
    
    const report = `
AI-IDS SECURITY REPORT
${periodName} Report - Generated: ${new Date().toLocaleString()}

===========================================
SUMMARY
===========================================
Total Alerts: ${reportData.totalAlerts}
Blocked Attacks: ${reportData.blockedCount}
Average Confidence: ${reportData.averageConfidence}%

===========================================
TOP 5 ATTACK TYPES
===========================================
${reportData.attackTypes.map(([type, count], i) => `${i + 1}. ${type}: ${count} attacks`).join('\n')}

===========================================
SEVERITY BREAKDOWN
===========================================
Critical: ${reportData.severityCounts.Critical}
High: ${reportData.severityCounts.High}
Medium: ${reportData.severityCounts.Medium}
Low: ${reportData.severityCounts.Low}

===========================================
ATTACK PATTERNS
===========================================
Peak Activity Hour: ${reportData.peakHour}:00
Peak Activity Day: ${reportData.peakDay}

===========================================
RECOMMENDATIONS
===========================================
${reportData.totalAlerts > 100 ? '⚠️ High attack volume detected. Consider enabling Smart IPS.' : ''}
${reportData.severityCounts.Critical > 10 ? '⚠️ Multiple critical threats. Review security policies.' : ''}
${reportData.blockedCount < reportData.totalAlerts / 2 ? '⚠️ Less than 50% attacks blocked. Enable auto-blocking.' : ''}
${reportData.attackTypes[0] && reportData.attackTypes[0][1] > 20 ? `⚠️ High frequency of ${reportData.attackTypes[0][0]} attacks. Update detection rules.` : ''}

===========================================
Generated by AI-IDS Platform
===========================================
    `.trim();

    const blob = new Blob([report], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `AI-IDS_${periodName}_Report_${new Date().toISOString().split('T')[0]}.txt`;
    a.click();
  };

  const getHealthColor = (score) => {
    if (score >= 80) return 'text-green-600 bg-green-100';
    if (score >= 60) return 'text-yellow-600 bg-yellow-100';
    return 'text-red-600 bg-red-100';
  };

  const getHealthStatus = (score) => {
    if (score >= 80) return 'HEALTHY';
    if (score >= 60) return 'DEGRADED';
    return 'CRITICAL';
  };

  const getSeverityColor = (severity) => {
    const colors = {
      CRITICAL: 'bg-red-100 text-red-800 border-red-300',
      HIGH: 'bg-orange-100 text-orange-800 border-orange-300',
      MEDIUM: 'bg-yellow-100 text-yellow-800 border-yellow-300'
    };
    return colors[severity] || 'bg-gray-100 text-gray-800 border-gray-300';
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-4 border-blue-600 border-t-transparent"></div>
      </div>
    );
  }

  return (
    <div className="grid grid-cols-3 gap-6">
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center">
            <Activity className="w-6 h-6 text-blue-600" />
          </div>
          <div>
            <h3 className="font-bold text-gray-900">Network Health</h3>
            <p className="text-xs text-gray-500">Real-time status</p>
          </div>
        </div>

        {networkHealth && (
          <div className="space-y-4">
            <div className={`p-4 rounded-lg border-2 ${getHealthColor(networkHealth.health_score)}`}>
              <div className="text-center">
                <div className="text-3xl font-bold mb-1">{networkHealth.health_score}%</div>
                <div className="text-sm font-semibold">{getHealthStatus(networkHealth.health_score)}</div>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="p-3 bg-gray-50 rounded-lg">
                <div className="text-xs text-gray-500 mb-1">Total IPs</div>
                <div className="text-xl font-bold text-gray-900">{networkHealth.total_ips}</div>
              </div>
              <div className="p-3 bg-gray-50 rounded-lg">
                <div className="text-xs text-gray-500 mb-1">At Risk</div>
                <div className="text-xl font-bold text-red-600">{networkHealth.at_risk_ips}</div>
              </div>
              <div className="p-3 bg-gray-50 rounded-lg">
                <div className="text-xs text-gray-500 mb-1">Malicious</div>
                <div className="text-xl font-bold text-orange-600">{networkHealth.malicious_ips}</div>
              </div>
              <div className="p-3 bg-gray-50 rounded-lg">
                <div className="text-xs text-gray-500 mb-1">Unknown</div>
                <div className="text-xl font-bold text-gray-600">{networkHealth.unknown_ips}</div>
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 bg-red-100 rounded-lg flex items-center justify-center">
            <AlertTriangle className="w-6 h-6 text-red-600" />
          </div>
          <div>
            <h3 className="font-bold text-gray-900">Threat Prediction</h3>
            <p className="text-xs text-gray-500">AI-powered forecast</p>
          </div>
        </div>

        {prediction && prediction.forecast_available ? (
          <div className="space-y-4">
            <div className="p-4 bg-red-50 border-2 border-red-200 rounded-lg">
              <div className="mb-3">
                <div className="text-xs text-red-600 font-semibold mb-1">PREDICTION</div>
                <div className="text-sm text-gray-700">High probability of continued <b>{prediction.predicted_attack}</b> attacks</div>
              </div>

              <div className="mb-3">
                <div className="text-xs text-gray-500 mb-1">NEXT LIKELY ATTACK</div>
                <div className="text-lg font-bold text-gray-900">{prediction.predicted_attack}</div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <div className="text-xs text-gray-500 mb-1">Confidence</div>
                  <div className="text-lg font-bold text-gray-900">{prediction.confidence}%</div>
                </div>
                <div>
                  <div className="text-xs text-gray-500 mb-1">Time Window</div>
                  <div className="text-sm font-semibold text-gray-700">Next 5-10 minutes</div>
                </div>
              </div>
            </div>

            <div className="p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
              <div className="text-xs font-semibold text-yellow-800 mb-1">Threat Information</div>
              <div className="text-xs text-gray-700">
                <div>Name: Unknown Attack: {prediction.predicted_attack}</div>
                <div className="mt-1">Category: Unknown</div>
                <div className="mt-2 px-2 py-1 bg-yellow-200 text-yellow-900 rounded inline-block">MEDIUM</div>
              </div>
            </div>
          </div>
        ) : (
          <div className="text-center py-12">
            <TrendingUp className="w-12 h-12 text-gray-300 mx-auto mb-3" />
            <p className="text-gray-500">Not enough data for prediction</p>
            <p className="text-xs text-gray-400 mt-1">Collect more attack samples</p>
          </div>
        )}
      </div>

      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-purple-100 rounded-lg flex items-center justify-center">
              <Shield className="w-6 h-6 text-purple-600" />
            </div>
            <div>
              <h3 className="font-bold text-gray-900">Top Threats</h3>
              <p className="text-xs text-gray-500">Highest risk IPs</p>
            </div>
          </div>
        </div>

        {topThreats.length > 0 ? (
          <div className="space-y-3">
            {topThreats.map((threat, index) => (
              <div key={index} className="p-3 bg-gray-50 rounded-lg border border-gray-200 hover:border-red-300 transition">
                <div className="flex items-center justify-between mb-2">
                  <span className="font-mono text-sm font-semibold text-gray-900">{threat.ip_address}</span>
                  <span className={`px-2 py-1 text-xs font-bold rounded border ${getSeverityColor(threat.threat_level)}`}>
                    {threat.threat_level}
                  </span>
                </div>
                <div className="grid grid-cols-3 gap-2 text-xs">
                  <div>
                    <div className="text-gray-500">Risk</div>
                    <div className="font-bold text-red-600">{threat.risk_score.toFixed(1)}</div>
                  </div>
                  <div>
                    <div className="text-gray-500">Attacks</div>
                    <div className="font-bold text-gray-900">{threat.attack_count}</div>
                  </div>
                  <div>
                    <div className="text-gray-500">Types</div>
                    <div className="font-bold text-gray-900">{threat.attack_types.length}</div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-12">
            <Shield className="w-12 h-12 text-gray-300 mx-auto mb-3" />
            <p className="text-gray-500">No threats detected</p>
            <p className="text-xs text-gray-400 mt-1">System is clean</p>
          </div>
        )}
      </div>

      <div className="col-span-3 bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-green-100 rounded-lg flex items-center justify-center">
              <FileText className="w-6 h-6 text-green-600" />
            </div>
            <div>
              <h3 className="font-bold text-gray-900">Security Report</h3>
              <p className="text-xs text-gray-500">Attack analysis and trends</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <select
              value={reportPeriod}
              onChange={(e) => setReportPeriod(e.target.value)}
              className="px-4 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500"
            >
              <option value="week">Last 7 Days</option>
              <option value="month">Last Month</option>
              <option value="year">Last Year</option>
            </select>
            <button
              onClick={downloadReport}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition"
            >
              <Download className="w-4 h-4" />
              Download Report
            </button>
          </div>
        </div>

        {reportData && (
          <div className="grid grid-cols-4 gap-6">
            <div className="col-span-1 space-y-4">
              <div className="p-4 bg-blue-50 rounded-lg border border-blue-200">
                <div className="text-sm text-blue-600 font-semibold mb-1">Total Alerts</div>
                <div className="text-3xl font-bold text-blue-900">{reportData.totalAlerts}</div>
              </div>

              <div className="p-4 bg-red-50 rounded-lg border border-red-200">
                <div className="text-sm text-red-600 font-semibold mb-1">Blocked</div>
                <div className="text-3xl font-bold text-red-900">{reportData.blockedCount}</div>
              </div>

              <div className="p-4 bg-purple-50 rounded-lg border border-purple-200">
                <div className="text-sm text-purple-600 font-semibold mb-1">Avg Confidence</div>
                <div className="text-3xl font-bold text-purple-900">{reportData.averageConfidence}%</div>
              </div>
            </div>

            <div className="col-span-2">
              <h4 className="font-semibold text-gray-900 mb-3">Top Attack Types</h4>
              <div className="space-y-3">
                {reportData.attackTypes.map(([type, count], index) => {
                  const percentage = (count / reportData.totalAlerts * 100).toFixed(1);
                  return (
                    <div key={index}>
                      <div className="flex justify-between mb-1">
                        <span className="text-sm font-medium text-gray-700">{type}</span>
                        <span className="text-sm text-gray-500">{count} ({percentage}%)</span>
                      </div>
                      <div className="h-3 bg-gray-200 rounded-full overflow-hidden">
                        <div 
                          className="h-full bg-gradient-to-r from-blue-500 to-blue-600 rounded-full"
                          style={{ width: `${percentage}%` }}
                        ></div>
                      </div>
                    </div>
                  );
                })}
              </div>

              <div className="mt-6 grid grid-cols-2 gap-4">
                <div className="p-3 bg-gray-50 rounded-lg">
                  <div className="flex items-center gap-2 text-gray-600 mb-1">
                    <Clock className="w-4 h-4" />
                    <span className="text-xs font-semibold">Peak Hour</span>
                  </div>
                  <div className="text-lg font-bold text-gray-900">{reportData.peakHour}:00</div>
                </div>
                <div className="p-3 bg-gray-50 rounded-lg">
                  <div className="flex items-center gap-2 text-gray-600 mb-1">
                    <Calendar className="w-4 h-4" />
                    <span className="text-xs font-semibold">Peak Day</span>
                  </div>
                  <div className="text-lg font-bold text-gray-900">{reportData.peakDay}</div>
                </div>
              </div>
            </div>

            <div className="col-span-1">
              <h4 className="font-semibold text-gray-900 mb-3">Severity Distribution</h4>
              <div className="space-y-2">
                <div className="flex justify-between items-center p-2 bg-red-50 rounded border border-red-200">
                  <span className="text-sm font-medium text-red-700">Critical</span>
                  <span className="text-lg font-bold text-red-900">{reportData.severityCounts.Critical}</span>
                </div>
                <div className="flex justify-between items-center p-2 bg-orange-50 rounded border border-orange-200">
                  <span className="text-sm font-medium text-orange-700">High</span>
                  <span className="text-lg font-bold text-orange-900">{reportData.severityCounts.High}</span>
                </div>
                <div className="flex justify-between items-center p-2 bg-yellow-50 rounded border border-yellow-200">
                  <span className="text-sm font-medium text-yellow-700">Medium</span>
                  <span className="text-lg font-bold text-yellow-900">{reportData.severityCounts.Medium}</span>
                </div>
                <div className="flex justify-between items-center p-2 bg-blue-50 rounded border border-blue-200">
                  <span className="text-sm font-medium text-blue-700">Low</span>
                  <span className="text-lg font-bold text-blue-900">{reportData.severityCounts.Low}</span>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
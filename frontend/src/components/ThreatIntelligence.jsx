import { useState, useEffect } from 'react';
import axios from 'axios';
import { X, Shield, AlertTriangle, Target, Code, CheckCircle } from 'lucide-react';

export default function ThreatIntelligence({ attackType, onClose }) {
  const [intel, setIntel] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchThreatIntel();
  }, [attackType]);

  const fetchThreatIntel = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(
        `http://localhost:8000/threat-intelligence/${attackType}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setIntel(response.data);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching threat intelligence:', error);
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="fixed inset-0 bg-black/90 flex items-center justify-center z-50">
        <div className="bg-black border-2 border-green-600 p-8">
          <div className="text-green-500 font-mono">[●] LOADING THREAT DATABASE...</div>
        </div>
      </div>
    );
  }

  if (!intel) return null;

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'CRITICAL': return 'text-red-500 border-red-600';
      case 'HIGH': return 'text-orange-500 border-orange-600';
      case 'MEDIUM': return 'text-yellow-500 border-yellow-600';
      default: return 'text-blue-500 border-blue-600';
    }
  };

  return (
    <div className="fixed inset-0 bg-black/90 flex items-center justify-center z-50 p-4 overflow-y-auto">
      <div className="bg-black border-2 border-green-600 max-w-4xl w-full max-h-[90vh] overflow-y-auto">
        <div className="border-b-2 border-green-600 p-4 flex justify-between items-center bg-gray-900">
          <h2 className="text-green-500 font-mono text-lg">
            [THREAT_INTELLIGENCE]$ {intel.name}
          </h2>
          <button
            onClick={onClose}
            className="text-red-500 hover:text-red-400 font-mono"
          >
            [X] CLOSE
          </button>
        </div>

        <div className="p-6 space-y-6">
          <div className="grid grid-cols-2 gap-4">
            <div className="border-2 border-gray-700 p-4">
              <div className="text-gray-500 font-mono text-xs mb-2">[CATEGORY]</div>
              <div className="text-cyan-400 font-mono">{intel.category}</div>
            </div>
            <div className={`border-2 p-4 ${getSeverityColor(intel.severity)}`}>
              <div className="text-gray-500 font-mono text-xs mb-2">[SEVERITY]</div>
              <div className="font-mono font-bold">{intel.severity}</div>
            </div>
            <div className="border-2 border-gray-700 p-4">
              <div className="text-gray-500 font-mono text-xs mb-2">[CVSS_SCORE]</div>
              <div className="text-orange-400 font-mono">{intel.cvss_score}/10</div>
            </div>
            <div className="border-2 border-gray-700 p-4">
              <div className="text-gray-500 font-mono text-xs mb-2">[MITRE_ATT&CK]</div>
              <div className="text-purple-400 font-mono">{intel.mitre_attack_id}</div>
            </div>
          </div>

          {intel.statistics && (
            <div className="border-2 border-blue-600 p-4 bg-gray-900">
              <div className="text-blue-400 font-mono text-sm mb-3">[DETECTION_STATISTICS]</div>
              <div className="grid grid-cols-3 gap-4 text-sm">
                <div>
                  <div className="text-gray-500 font-mono text-xs">Total Detections</div>
                  <div className="text-green-400 font-mono">{intel.statistics.total_detections}</div>
                </div>
                <div>
                  <div className="text-gray-500 font-mono text-xs">IPs Blocked</div>
                  <div className="text-red-400 font-mono">{intel.statistics.ips_blocked}</div>
                </div>
                <div>
                  <div className="text-gray-500 font-mono text-xs">Last Seen</div>
                  <div className="text-yellow-400 font-mono">{intel.statistics.last_seen}</div>
                </div>
              </div>
            </div>
          )}

          <div className="border-2 border-gray-700 p-4">
            <div className="text-green-500 font-mono text-sm mb-3">[DESCRIPTION]</div>
            <p className="text-gray-400 font-mono text-sm leading-relaxed">{intel.description}</p>
          </div>

          <div className="border-2 border-red-600 p-4 bg-gray-900">
            <div className="text-red-400 font-mono text-sm mb-3 flex items-center gap-2">
              <Target size={16} />
              [ATTACKER_METHOD]
            </div>
            <ul className="space-y-2">
              {intel.attacker_method.map((method, index) => (
                <li key={index} className="text-gray-400 font-mono text-sm flex items-start gap-2">
                  <span className="text-red-500">[{index + 1}]</span>
                  <span>{method}</span>
                </li>
              ))}
            </ul>
          </div>

          <div className="border-2 border-yellow-600 p-4 bg-gray-900">
            <div className="text-yellow-400 font-mono text-sm mb-3 flex items-center gap-2">
              <AlertTriangle size={16} />
              [INDICATORS_OF_COMPROMISE]
            </div>
            <ul className="space-y-2">
              {intel.indicators.map((indicator, index) => (
                <li key={index} className="text-gray-400 font-mono text-sm flex items-start gap-2">
                  <span className="text-yellow-500">[!]</span>
                  <span>{indicator}</span>
                </li>
              ))}
            </ul>
          </div>

          <div className="border-2 border-green-600 p-4 bg-gray-900">
            <div className="text-green-400 font-mono text-sm mb-3 flex items-center gap-2">
              <Shield size={16} />
              [SECURITY_RECOMMENDATIONS]
            </div>
            <ul className="space-y-3">
              {intel.recommendations.map((rec, index) => (
                <li key={index} className="border-l-2 border-green-600 pl-4 py-2">
                  <div className="text-green-400 font-mono text-sm flex items-start gap-2">
                    <span className="text-green-500 font-bold">[{index + 1}]</span>
                    <span>{rec}</span>
                  </div>
                </li>
              ))}
            </ul>
          </div>

          <div className={`border-2 p-4 ${intel.blocking_action === 'IMMEDIATE' ? 'border-red-600 bg-red-950/20' : 'border-yellow-600 bg-yellow-950/20'}`}>
            <div className="font-mono text-sm flex items-center gap-2">
              <Code size={16} />
              <span className={intel.blocking_action === 'IMMEDIATE' ? 'text-red-400' : 'text-yellow-400'}>
                [RECOMMENDED_ACTION] {intel.blocking_action}
              </span>
            </div>
          </div>
        </div>

        <div className="border-t-2 border-green-600 p-4 bg-gray-900">
          <button
            onClick={onClose}
            className="w-full px-4 py-3 bg-gray-800 hover:bg-gray-700 text-green-500 border-2 border-green-600 font-mono transition-all"
          >
            [ESC] CLOSE THREAT INTELLIGENCE
          </button>
        </div>
      </div>
    </div>
  );
}
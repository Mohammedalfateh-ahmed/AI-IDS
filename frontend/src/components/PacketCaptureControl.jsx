import React, { useState, useEffect } from 'react';
import axios from 'axios';

const PacketCaptureControl = ({ user }) => {
  const [isCapturing, setIsCapturing] = useState(false);
  const [stats, setStats] = useState({
    packets_captured: 0,
    attacks_detected: 0,
    recent_alerts: []
  });
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    loadStats();
    const interval = setInterval(() => {
      loadStats();
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  const loadStats = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('http://localhost:8000/capture/stats', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setStats(response.data);
      setIsCapturing(response.data.active);
    } catch (error) {
      console.error('Failed to load capture stats:', error);
    }
  };

  const startCapture = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('token');
      await axios.post('http://localhost:8000/capture/start', {}, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setIsCapturing(true);
      loadStats();
    } catch (error) {
      alert('Failed to start capture. Admin privileges required! Error: ' + (error.response?.data?.detail || error.message));
    } finally {
      setLoading(false);
    }
  };

  const stopCapture = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('token');
      await axios.post('http://localhost:8000/capture/stop', {}, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setIsCapturing(false);
      loadStats();
    } catch (error) {
      alert('Failed to stop capture: ' + (error.response?.data?.detail || error.message));
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity) => {
    switch(severity?.toLowerCase()) {
      case 'high': return 'bg-red-500';
      case 'medium': return 'bg-yellow-500';
      case 'low': return 'bg-blue-500';
      default: return 'bg-gray-500';
    }
  };

  return (
    <div className="bg-gradient-to-br from-slate-800/50 via-slate-800/30 to-transparent backdrop-blur-md rounded-2xl p-8 border border-slate-600/50 shadow-2xl">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-bold text-white flex items-center">
          <div className="w-10 h-10 bg-gradient-to-br from-green-500 to-emerald-600 rounded-lg flex items-center justify-center mr-3 shadow-lg">
            <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
          </div>
          Live Packet Capture
          {isCapturing && (
            <span className="ml-4 flex items-center">
              <span className="w-3 h-3 bg-green-400 rounded-full animate-pulse mr-2"></span>
              <span className="text-green-400 text-sm font-medium">CAPTURING</span>
            </span>
          )}
        </h2>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
        <div className="bg-gradient-to-br from-blue-600/20 to-blue-700/10 rounded-xl p-6 border border-blue-500/30">
          <div className="text-blue-300 text-sm font-semibold uppercase tracking-wider mb-2">Packets Captured</div>
          <div className="text-4xl font-extrabold text-white">{stats.packets_captured}</div>
        </div>

        <div className="bg-gradient-to-br from-red-600/20 to-red-700/10 rounded-xl p-6 border border-red-500/30">
          <div className="text-red-300 text-sm font-semibold uppercase tracking-wider mb-2">Threats Detected</div>
          <div className="text-4xl font-extrabold text-white">{stats.attacks_detected}</div>
        </div>

        <div className="bg-gradient-to-br from-green-600/20 to-green-700/10 rounded-xl p-6 border border-green-500/30">
          <div className="text-green-300 text-sm font-semibold uppercase tracking-wider mb-2">Status</div>
          <div className="text-2xl font-bold text-white">
            {isCapturing ? '🟢 ACTIVE' : '🔴 STOPPED'}
          </div>
        </div>
      </div>

      <div className="flex gap-4 mb-6">
        {user?.role === 'admin' ? (
          <button
            onClick={isCapturing ? stopCapture : startCapture}
            disabled={loading}
            className={`flex-1 px-8 py-4 rounded-xl font-bold text-lg text-white transition-all transform hover:scale-105 active:scale-95 shadow-xl ${
              isCapturing 
                ? 'bg-gradient-to-r from-red-600 to-red-700 hover:from-red-500 hover:to-red-600' 
                : 'bg-gradient-to-r from-green-600 to-emerald-700 hover:from-green-500 hover:to-emerald-600'
            } disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none`}
          >
            {loading ? (
              <span className="flex items-center justify-center">
                <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Processing...
              </span>
            ) : isCapturing ? (
              '⏹️ Stop Capture'
            ) : (
              '▶️ Start Capture'
            )}
          </button>
        ) : (
          <div className="flex-1 bg-gray-700/50 rounded-xl p-4 text-center">
            <p className="text-gray-400 text-sm">Admin privileges required to control packet capture</p>
          </div>
        )}
      </div>

      {!isCapturing && user?.role === 'admin' && (
        <div className="bg-yellow-900/30 border border-yellow-500/50 rounded-xl p-4 mb-6">
          <div className="flex items-start">
            <svg className="w-6 h-6 text-yellow-400 mr-3 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <div>
              <h3 className="text-yellow-400 font-bold mb-1">Administrator Privileges Required</h3>
              <p className="text-yellow-200 text-sm">
                To capture live network traffic, run the backend server with administrator privileges.
                <br />
                <strong>Windows:</strong> Run Command Prompt as Administrator
                <br />
                <strong>Linux:</strong> Use sudo python -m app.main
              </p>
            </div>
          </div>
        </div>
      )}

      {stats.recent_alerts && stats.recent_alerts.length > 0 && (
        <div className="bg-red-900/20 border border-red-500/30 rounded-xl p-6">
          <h3 className="text-xl font-bold text-red-300 mb-4 flex items-center">
            <svg className="w-6 h-6 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            Live Threats from Packet Capture
          </h3>
          <div className="space-y-3">
            {stats.recent_alerts.map((alert, index) => (
              <div key={index} className="bg-slate-800/50 rounded-lg p-4 border border-slate-600/50">
                <div className="flex items-center justify-between mb-2">
                  <span className={`px-3 py-1 rounded-full text-xs font-bold ${getSeverityColor(alert.severity)} text-white`}>
                    {alert.severity?.toUpperCase()}
                  </span>
                  <span className="text-sm text-gray-400">{alert.timestamp}</span>
                </div>
                <div className="text-white font-bold text-lg mb-2">{alert.attack_type}</div>
                <div className="grid grid-cols-2 gap-2 text-sm">
                  <div className="text-gray-400">Source: <span className="text-cyan-400 font-mono">{alert.source_ip}</span></div>
                  <div className="text-gray-400">Destination: <span className="text-purple-400 font-mono">{alert.destination_ip}</span></div>
                  <div className="text-gray-400">Confidence: <span className="text-green-400 font-bold">{(alert.confidence * 100).toFixed(1)}%</span></div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default PacketCaptureControl;
import { useState, useEffect } from 'react';
import { Shield, Unlock, Plus, Trash2, AlertTriangle, Clock, XCircle, ArrowLeft } from 'lucide-react';

export default function BlockedIPs() {
  const [blockedIPs, setBlockedIPs] = useState({});
  const [whitelist, setWhitelist] = useState([]);
  const [autoResponseConfig, setAutoResponseConfig] = useState({});
  const [newIP, setNewIP] = useState('');
  const [newReason, setNewReason] = useState('');
  const [newDuration, setNewDuration] = useState(60);
  const [newWhitelistIP, setNewWhitelistIP] = useState('');
  const [showAddModal, setShowAddModal] = useState(false);
  const [showWhitelistModal, setShowWhitelistModal] = useState(false);
  const [showConfigModal, setShowConfigModal] = useState(false);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  const fetchData = async () => {
    try {
      const token = localStorage.getItem('token');
      
      const [blockedRes, whitelistRes, configRes] = await Promise.all([
        fetch('http://localhost:8000/firewall/blocked-ips', {
          headers: { 'Authorization': `Bearer ${token}` }
        }),
        fetch('http://localhost:8000/firewall/whitelist', {
          headers: { 'Authorization': `Bearer ${token}` }
        }),
        fetch('http://localhost:8000/auto-response/config', {
          headers: { 'Authorization': `Bearer ${token}` }
        })
      ]);

      const blocked = await blockedRes.json();
      const whitelistData = await whitelistRes.json();
      const config = await configRes.json();

      setBlockedIPs(blocked);
      setWhitelist(whitelistData.whitelist);
      setAutoResponseConfig(config);
    } catch (error) {
      console.error('Error fetching firewall data:', error);
    }
  };

  const handleBlockIP = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`http://localhost:8000/firewall/block?ip=${newIP}&reason=${newReason}&duration=${newDuration}`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });

      const result = await response.json();
      alert(result.message || result.reason);
      setShowAddModal(false);
      setNewIP('');
      setNewReason('');
      setNewDuration(60);
      fetchData();
    } catch (error) {
      alert('Error blocking IP: ' + error.message);
    }
  };

  const handleUnblockIP = async (ip) => {
    if (!confirm(`Unblock IP ${ip}?`)) return;
    
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`http://localhost:8000/firewall/unblock?ip=${ip}`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });

      const result = await response.json();
      alert(result.message);
      fetchData();
    } catch (error) {
      alert('Error unblocking IP: ' + error.message);
    }
  };

  const handleUnblockAll = async () => {
    if (!confirm('Unblock ALL IPs? This cannot be undone.')) return;
    
    try {
      const token = localStorage.getItem('token');
      const response = await fetch('http://localhost:8000/firewall/unblock-all', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });

      const result = await response.json();
      alert(`Unblocked ${result.results.length} IPs`);
      fetchData();
    } catch (error) {
      alert('Error unblocking all IPs: ' + error.message);
    }
  };

  const handleAddWhitelist = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`http://localhost:8000/firewall/whitelist/add?ip=${newWhitelistIP}`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });

      const result = await response.json();
      alert(result.message);
      setShowWhitelistModal(false);
      setNewWhitelistIP('');
      fetchData();
    } catch (error) {
      alert('Error adding to whitelist: ' + error.message);
    }
  };

  const handleRemoveWhitelist = async (ip) => {
    if (!confirm(`Remove ${ip} from whitelist?`)) return;
    
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`http://localhost:8000/firewall/whitelist/remove?ip=${ip}`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });

      const result = await response.json();
      alert(result.message);
      fetchData();
    } catch (error) {
      alert('Error removing from whitelist: ' + error.message);
    }
  };

  const handleUpdateConfig = async () => {
    try {
      const token = localStorage.getItem('token');
      const params = new URLSearchParams({
        confidence_threshold: autoResponseConfig.confidence_threshold,
        block_duration: autoResponseConfig.block_duration,
        attack_threshold: autoResponseConfig.attack_threshold
      });

      const response = await fetch(`http://localhost:8000/auto-response/config?${params}`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });

      await response.json();
      alert('Configuration updated successfully');
      setShowConfigModal(false);
      fetchData();
    } catch (error) {
      alert('Error updating configuration: ' + error.message);
    }
  };

  const toggleAutoResponse = async () => {
    try {
      const token = localStorage.getItem('token');
      const endpoint = autoResponseConfig.enabled ? 'disable' : 'enable';
      
      const response = await fetch(`http://localhost:8000/auto-response/${endpoint}`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });

      const result = await response.json();
      alert(result.message);
      fetchData();
    } catch (error) {
      alert('Error toggling auto-response: ' + error.message);
    }
  };

  const getRemainingTime = (unblockAt) => {
    const now = new Date();
    const unblock = new Date(unblockAt);
    const diff = unblock - now;
    
    if (diff <= 0) return 'Expired';
    
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(minutes / 60);
    
    if (hours > 0) return `${hours}h ${minutes % 60}m`;
    return `${minutes}m`;
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-purple-900 to-gray-900 p-8">
      <div className="max-w-7xl mx-auto">
        <div className="mb-8 flex items-center justify-between">
          <div>
            <button
              onClick={() => window.location.href = '/dashboard'}
              className="mb-4 flex items-center gap-2 text-purple-300 hover:text-white transition-colors"
            >
              <ArrowLeft className="w-5 h-5" />
              Back to Dashboard
            </button>
            <h1 className="text-4xl font-bold text-white mb-2">Firewall Management</h1>
            <p className="text-purple-200">Automated Response & IP Blocking</p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20">
            <div className="flex items-center justify-between mb-4">
              <Shield className="w-10 h-10 text-red-400" />
              <span className="text-3xl font-bold text-white">{Object.keys(blockedIPs).length}</span>
            </div>
            <p className="text-purple-200">Blocked IPs</p>
          </div>

          <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20">
            <div className="flex items-center justify-between mb-4">
              <Shield className="w-10 h-10 text-green-400" />
              <span className="text-3xl font-bold text-white">{whitelist.length}</span>
            </div>
            <p className="text-purple-200">Whitelisted IPs</p>
          </div>

          <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20">
            <div className="flex items-center justify-between mb-4">
              <AlertTriangle className={`w-10 h-10 ${autoResponseConfig.enabled ? 'text-green-400' : 'text-gray-400'}`} />
              <button
                onClick={toggleAutoResponse}
                className={`px-4 py-2 rounded-lg font-semibold ${
                  autoResponseConfig.enabled
                    ? 'bg-red-500 hover:bg-red-600'
                    : 'bg-green-500 hover:bg-green-600'
                } text-white`}
              >
                {autoResponseConfig.enabled ? 'Disable' : 'Enable'}
              </button>
            </div>
            <p className="text-purple-200">Auto-Response</p>
          </div>
        </div>

        <div className="flex gap-4 mb-6 flex-wrap">
          <button
            onClick={() => setShowAddModal(true)}
            className="bg-red-600 hover:bg-red-700 text-white px-6 py-3 rounded-lg flex items-center gap-2 font-semibold"
          >
            <Plus className="w-5 h-5" />
            Block IP
          </button>
          <button
            onClick={() => setShowWhitelistModal(true)}
            className="bg-green-600 hover:bg-green-700 text-white px-6 py-3 rounded-lg flex items-center gap-2 font-semibold"
          >
            <Plus className="w-5 h-5" />
            Add Whitelist
          </button>
          <button
            onClick={() => setShowConfigModal(true)}
            className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 rounded-lg font-semibold"
          >
            Configure Auto-Response
          </button>
          <button
            onClick={handleUnblockAll}
            className="bg-orange-600 hover:bg-orange-700 text-white px-6 py-3 rounded-lg flex items-center gap-2 font-semibold"
          >
            <Unlock className="w-5 h-5" />
            Unblock All
          </button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20">
            <h2 className="text-2xl font-bold text-white mb-4">Blocked IPs</h2>
            <div className="space-y-3 max-h-96 overflow-y-auto">
              {Object.entries(blockedIPs).length === 0 ? (
                <p className="text-purple-200 text-center py-8">No blocked IPs</p>
              ) : (
                Object.entries(blockedIPs).map(([ip, data]) => (
                  <div key={ip} className="bg-white/5 rounded-lg p-4 border border-red-500/30">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-white font-semibold text-lg">{ip}</span>
                      <button
                        onClick={() => handleUnblockIP(ip)}
                        className="bg-green-600 hover:bg-green-700 text-white px-3 py-1 rounded flex items-center gap-1 text-sm"
                      >
                        <Unlock className="w-4 h-4" />
                        Unblock
                      </button>
                    </div>
                    <p className="text-purple-200 text-sm mb-2">{data.reason}</p>
                    <div className="flex items-center gap-4 text-xs text-purple-300">
                      <span className="flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        Remaining: {getRemainingTime(data.unblock_at)}
                      </span>
                      <span>Duration: {data.duration_minutes}m</span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20">
            <h2 className="text-2xl font-bold text-white mb-4">Whitelist</h2>
            <div className="space-y-3 max-h-96 overflow-y-auto">
              {whitelist.length === 0 ? (
                <p className="text-purple-200 text-center py-8">No whitelisted IPs</p>
              ) : (
                whitelist.map(ip => (
                  <div key={ip} className="bg-white/5 rounded-lg p-4 border border-green-500/30 flex items-center justify-between">
                    <span className="text-white font-semibold">{ip}</span>
                    <button
                      onClick={() => handleRemoveWhitelist(ip)}
                      className="bg-red-600 hover:bg-red-700 text-white px-3 py-1 rounded flex items-center gap-1 text-sm"
                    >
                      <Trash2 className="w-4 h-4" />
                      Remove
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {showAddModal && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
            <div className="bg-gray-800 rounded-xl p-6 max-w-md w-full">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-xl font-bold text-white">Block IP Address</h3>
                <button onClick={() => setShowAddModal(false)} className="text-gray-400 hover:text-white">
                  <XCircle className="w-6 h-6" />
                </button>
              </div>
              <div className="space-y-4">
                <div>
                  <label className="block text-purple-200 mb-2">IP Address</label>
                  <input
                    type="text"
                    value={newIP}
                    onChange={(e) => setNewIP(e.target.value)}
                    className="w-full px-4 py-2 rounded-lg bg-white/10 border border-white/20 text-white"
                    placeholder="192.168.1.100"
                  />
                </div>
                <div>
                  <label className="block text-purple-200 mb-2">Reason</label>
                  <input
                    type="text"
                    value={newReason}
                    onChange={(e) => setNewReason(e.target.value)}
                    className="w-full px-4 py-2 rounded-lg bg-white/10 border border-white/20 text-white"
                    placeholder="Manual block - suspicious activity"
                  />
                </div>
                <div>
                  <label className="block text-purple-200 mb-2">Duration (minutes)</label>
                  <input
                    type="number"
                    value={newDuration}
                    onChange={(e) => setNewDuration(parseInt(e.target.value))}
                    className="w-full px-4 py-2 rounded-lg bg-white/10 border border-white/20 text-white"
                  />
                </div>
                <button
                  onClick={handleBlockIP}
                  className="w-full bg-red-600 hover:bg-red-700 text-white py-3 rounded-lg font-semibold"
                >
                  Block IP
                </button>
              </div>
            </div>
          </div>
        )}

        {showWhitelistModal && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
            <div className="bg-gray-800 rounded-xl p-6 max-w-md w-full">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-xl font-bold text-white">Add to Whitelist</h3>
                <button onClick={() => setShowWhitelistModal(false)} className="text-gray-400 hover:text-white">
                  <XCircle className="w-6 h-6" />
                </button>
              </div>
              <div className="space-y-4">
                <div>
                  <label className="block text-purple-200 mb-2">IP Address</label>
                  <input
                    type="text"
                    value={newWhitelistIP}
                    onChange={(e) => setNewWhitelistIP(e.target.value)}
                    className="w-full px-4 py-2 rounded-lg bg-white/10 border border-white/20 text-white"
                    placeholder="192.168.1.1"
                  />
                </div>
                <button
                  onClick={handleAddWhitelist}
                  className="w-full bg-green-600 hover:bg-green-700 text-white py-3 rounded-lg font-semibold"
                >
                  Add to Whitelist
                </button>
              </div>
            </div>
          </div>
        )}

        {showConfigModal && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
            <div className="bg-gray-800 rounded-xl p-6 max-w-md w-full">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-xl font-bold text-white">Auto-Response Configuration</h3>
                <button onClick={() => setShowConfigModal(false)} className="text-gray-400 hover:text-white">
                  <XCircle className="w-6 h-6" />
                </button>
              </div>
              <div className="space-y-4">
                <div>
                  <label className="block text-purple-200 mb-2">Confidence Threshold (0.0 - 1.0)</label>
                  <input
                    type="number"
                    step="0.1"
                    min="0"
                    max="1"
                    value={autoResponseConfig.confidence_threshold || 0.7}
                    onChange={(e) => setAutoResponseConfig({...autoResponseConfig, confidence_threshold: parseFloat(e.target.value)})}
                    className="w-full px-4 py-2 rounded-lg bg-white/10 border border-white/20 text-white"
                  />
                  <p className="text-xs text-purple-300 mt-1">Only block attacks with confidence above this value</p>
                </div>
                <div>
                  <label className="block text-purple-200 mb-2">Block Duration (minutes)</label>
                  <input
                    type="number"
                    value={autoResponseConfig.block_duration || 60}
                    onChange={(e) => setAutoResponseConfig({...autoResponseConfig, block_duration: parseInt(e.target.value)})}
                    className="w-full px-4 py-2 rounded-lg bg-white/10 border border-white/20 text-white"
                  />
                </div>
                <div>
                  <label className="block text-purple-200 mb-2">Attack Threshold</label>
                  <input
                    type="number"
                    value={autoResponseConfig.attack_threshold || 3}
                    onChange={(e) => setAutoResponseConfig({...autoResponseConfig, attack_threshold: parseInt(e.target.value)})}
                    className="w-full px-4 py-2 rounded-lg bg-white/10 border border-white/20 text-white"
                  />
                  <p className="text-xs text-purple-300 mt-1">Block IP after this many attacks from same source</p>
                </div>
                <button
                  onClick={handleUpdateConfig}
                  className="w-full bg-blue-600 hover:bg-blue-700 text-white py-3 rounded-lg font-semibold"
                >
                  Update Configuration
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
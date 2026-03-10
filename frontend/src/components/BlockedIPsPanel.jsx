import { useState, useEffect } from 'react';
import axios from 'axios';
import toast from 'react-hot-toast';

export default function BlockedIPsPanel({ userRole }) {
  const [blockedIPs, setBlockedIPs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showAddForm, setShowAddForm] = useState(false);
  const [newIP, setNewIP] = useState('');
  const [blockReason, setBlockReason] = useState('');

  useEffect(() => {
    fetchBlockedIPs();
    const interval = setInterval(fetchBlockedIPs, 10000);
    return () => clearInterval(interval);
  }, []);

  const fetchBlockedIPs = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('http://localhost:8000/blocked-ips', {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      console.log('Blocked IPs received:', response.data);
      setBlockedIPs(response.data || []);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching blocked IPs:', error);
      setLoading(false);
    }
  };

  const handleBlockIP = async (e) => {
    e.preventDefault();
    try {
      const token = localStorage.getItem('token');
      await axios.post(
        `http://localhost:8000/block-ip/${newIP}`,
        { reason: blockReason },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      toast.success('IP blocked successfully');
      setNewIP('');
      setBlockReason('');
      setShowAddForm(false);
      fetchBlockedIPs();
    } catch (error) {
      console.error('Block IP error:', error);
      toast.error(error.response?.data?.detail || 'Failed to block IP');
    }
  };

  const handleUnblockIP = async (ip) => {
    if (window.confirm(`Unblock ${ip}?`)) {
      try {
        const token = localStorage.getItem('token');
        await axios.delete(`http://localhost:8000/unblock-ip/${ip}`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        toast.success('IP unblocked successfully');
        fetchBlockedIPs();
      } catch (error) {
        console.error('Unblock IP error:', error);
        toast.error(error.response?.data?.detail || 'Failed to unblock IP');
      }
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
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-bold text-gray-800 flex items-center space-x-2">
            <svg className="w-5 h-5 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
            </svg>
            <span>Blocked IPs ({blockedIPs.length})</span>
          </h2>
          
          {userRole === 'admin' && (
            <button
              onClick={() => setShowAddForm(!showAddForm)}
              className="px-3 py-1 bg-red-600 hover:bg-red-700 text-white text-sm rounded-lg transition-colors"
            >
              {showAddForm ? 'Cancel' : '+ Block IP'}
            </button>
          )}
        </div>
      </div>

      <div className="p-6">
        {showAddForm && userRole === 'admin' && (
          <form onSubmit={handleBlockIP} className="mb-4 p-4 bg-gray-50 border border-gray-200 rounded-lg">
            <div className="space-y-3">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">IP Address</label>
                <input
                  type="text"
                  value={newIP}
                  onChange={(e) => setNewIP(e.target.value)}
                  placeholder="192.168.1.100"
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-red-500"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Reason</label>
                <input
                  type="text"
                  value={blockReason}
                  onChange={(e) => setBlockReason(e.target.value)}
                  placeholder="Manual block - suspicious activity"
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-red-500"
                  required
                />
              </div>
              <button
                type="submit"
                className="w-full px-4 py-2 bg-red-600 hover:bg-red-700 text-white font-medium rounded-lg transition-colors"
              >
                Block IP
              </button>
            </div>
          </form>
        )}

        <div className="space-y-2 max-h-96 overflow-y-auto">
          {blockedIPs.length > 0 ? (
            blockedIPs.map((item, index) => (
              <div key={index} className="p-3 bg-red-50 border border-red-200 rounded-lg">
                <div className="flex items-start justify-between mb-2">
                  <div className="flex-1">
                    <div className="font-mono font-bold text-red-900">{item.ip_address}</div>
                    <div className="text-xs text-red-600 mt-1">{item.reason}</div>
                  </div>
                  {userRole === 'admin' && (
                    <button
                      onClick={() => handleUnblockIP(item.ip_address)}
                      className="ml-2 px-2 py-1 bg-red-600 hover:bg-red-700 text-white text-xs rounded transition-colors"
                    >
                      Unblock
                    </button>
                  )}
                </div>
                
                <div className="grid grid-cols-3 gap-2 text-xs mt-2 pt-2 border-t border-red-200">
                  <div>
                    <span className="text-red-600">Threat Level</span>
                    <div className="font-bold text-red-900">{item.threat_level || 'HIGH'}</div>
                  </div>
                  <div>
                    <span className="text-red-600">Attacks</span>
                    <div className="font-bold text-red-900">{item.attack_count || 1}</div>
                  </div>
                  <div>
                    <span className="text-red-600">Blocked At</span>
                    <div className="font-bold text-red-900">
                      {new Date(item.blocked_at).toLocaleDateString()}
                    </div>
                  </div>
                </div>
              </div>
            ))
          ) : (
            <div className="text-center py-8 text-gray-500">
              <svg className="w-12 h-12 text-gray-300 mx-auto mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <p className="text-sm">No blocked IPs</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
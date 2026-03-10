import { useState, useEffect } from 'react';
import axios from 'axios';

export default function SystemLogs({ user }) {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('ALL');
  const [filteredLogs, setFilteredLogs] = useState([]);

  useEffect(() => {
    fetchLogs();
    const interval = setInterval(fetchLogs, 5000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (filter === 'ALL') {
      setFilteredLogs(logs);
    } else {
      setFilteredLogs(logs.filter(log => log.level === filter));
    }
  }, [filter, logs]);

  const fetchLogs = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('http://localhost:8000/system-logs', {
        headers: { Authorization: `Bearer ${token}` },
        params: { limit: 50 }
      });
      
      console.log('Logs received:', response.data);
      setLogs(response.data || []);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching logs:', error);
      setLoading(false);
    }
  };

  const getLevelBadge = (level) => {
    const badges = {
      'ALERT': 'bg-red-100 text-red-700 border-red-300',
      'ERROR': 'bg-red-100 text-red-700 border-red-300',
      'WARNING': 'bg-yellow-100 text-yellow-700 border-yellow-300',
      'INFO': 'bg-blue-100 text-blue-700 border-blue-300',
      'LOGIN_SUCCESS': 'bg-green-100 text-green-700 border-green-300',
      'CAPTURE': 'bg-purple-100 text-purple-700 border-purple-300',
      'NORMAL': 'bg-gray-100 text-gray-700 border-gray-300'
    };
    return badges[level] || 'bg-gray-100 text-gray-700 border-gray-300';
  };

  const getLevelIcon = (level) => {
    switch(level) {
      case 'ALERT':
      case 'ERROR':
        return (
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        );
      case 'WARNING':
        return (
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
        );
      case 'LOGIN_SUCCESS':
        return (
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        );
      case 'CAPTURE':
        return (
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 15l-2 5L9 9l11 4-5 2zm0 0l5 5M7.188 2.239l.777 2.897M5.136 7.965l-2.898-.777M13.95 4.05l-2.122 2.122m-5.657 5.656l-2.12 2.122" />
          </svg>
        );
      default:
        return (
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        );
    }
  };

  const logCounts = {
    ALL: logs.length,
    ALERT: logs.filter(log => log.level === 'ALERT').length,
    LOGIN_SUCCESS: logs.filter(log => log.level === 'LOGIN_SUCCESS').length,
    NORMAL: logs.filter(log => log.level === 'NORMAL').length,
    CAPTURE: logs.filter(log => log.level === 'CAPTURE').length,
    ERROR: logs.filter(log => log.level === 'ERROR').length
  };

  if (loading) {
    return (
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="animate-pulse space-y-4">
          <div className="h-4 bg-gray-200 rounded w-1/4"></div>
          <div className="space-y-2">
            <div className="h-16 bg-gray-200 rounded"></div>
            <div className="h-16 bg-gray-200 rounded"></div>
            <div className="h-16 bg-gray-200 rounded"></div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200">
      <div className="p-6 border-b border-gray-200">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-bold text-gray-800 flex items-center space-x-2">
            <svg className="w-5 h-5 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            <span>System Logs</span>
            <span className="text-sm text-gray-500">({filteredLogs.length} entries)</span>
          </h2>
        </div>

        <div className="flex flex-wrap gap-2">
          {[
            { key: 'ALL', label: 'All Logs', color: 'bg-gray-100 hover:bg-gray-200 text-gray-700 border-gray-300' },
            { key: 'ALERT', label: 'Attacks', color: 'bg-red-50 hover:bg-red-100 text-red-700 border-red-200' },
            { key: 'LOGIN_SUCCESS', label: 'Login', color: 'bg-green-50 hover:bg-green-100 text-green-700 border-green-200' },
            { key: 'NORMAL', label: 'Normal', color: 'bg-blue-50 hover:bg-blue-100 text-blue-700 border-blue-200' },
            { key: 'CAPTURE', label: 'Capture', color: 'bg-purple-50 hover:bg-purple-100 text-purple-700 border-purple-200' },
            { key: 'ERROR', label: 'Errors', color: 'bg-red-50 hover:bg-red-100 text-red-700 border-red-200' }
          ].map(({ key, label, color }) => (
            <button
              key={key}
              onClick={() => setFilter(key)}
              className={`px-4 py-2 rounded-lg border-2 font-medium text-sm transition-all ${
                filter === key
                  ? 'ring-2 ring-blue-500 ' + color
                  : color
              }`}
            >
              {label} ({logCounts[key] || 0})
            </button>
          ))}
        </div>
      </div>

      <div className="divide-y divide-gray-200 max-h-[600px] overflow-y-auto">
        {filteredLogs.length > 0 ? (
          filteredLogs.slice().reverse().map((log, index) => (
            <div
              key={index}
              className="p-4 hover:bg-gray-50 transition-colors"
            >
              <div className="flex items-start space-x-4">
                <div className={`p-2 rounded-lg border ${getLevelBadge(log.level)}`}>
                  {getLevelIcon(log.level)}
                </div>

                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between mb-2">
                    <span className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-semibold border ${getLevelBadge(log.level)}`}>
                      {log.level}
                    </span>
                    <span className="text-xs text-gray-500">
                      {new Date(log.timestamp).toLocaleString()}
                    </span>
                  </div>

                  <p className="text-sm text-gray-800 font-medium mb-1">
                    {log.message}
                  </p>

                  {log.user && (
                    <div className="text-xs text-gray-600 mb-1">
                      User: <span className="font-semibold text-blue-600">{log.user}</span>
                    </div>
                  )}

                  {log.details && typeof log.details === 'object' && (
                    <div className="mt-2 p-3 bg-gray-50 rounded-lg border border-gray-200">
                      <div className="text-xs font-semibold text-gray-700 mb-2">Details:</div>
                      <div className="space-y-1 text-xs text-gray-600">
                        {Object.entries(log.details).map(([key, value]) => (
                          <div key={key} className="flex items-start">
                            <span className="font-medium text-gray-700 min-w-[100px]">{key}:</span>
                            <span className="flex-1 break-words">
                              {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))
        ) : (
          <div className="text-center py-16">
            <svg className="w-16 h-16 text-gray-300 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            <p className="text-xl font-medium text-gray-500 mb-2">No Logs Found</p>
            <p className="text-gray-400">
              {filter === 'ALL' ? 'System has no logs yet' : `No ${filter} logs found`}
            </p>
          </div>
        )}
      </div>

      {filteredLogs.length > 0 && (
        <div className="p-4 bg-gray-50 border-t border-gray-200">
          <div className="flex items-center justify-between text-sm text-gray-600">
            <span>Showing {filteredLogs.length} of {logs.length} total logs</span>
            <span>Auto-refreshes every 5 seconds</span>
          </div>
        </div>
      )}
    </div>
  );
}
import { useState, useEffect, useMemo } from 'react';
import axios from 'axios';

const LEVEL_STYLES = {
  ALERT:         { badge: 'bg-red-100 text-red-700 border-red-300',      dot: 'bg-red-500',    label: 'Attack'  },
  ERROR:         { badge: 'bg-red-100 text-red-700 border-red-300',      dot: 'bg-red-500',    label: 'Error'   },
  WARNING:       { badge: 'bg-yellow-100 text-yellow-700 border-yellow-300', dot: 'bg-yellow-400', label: 'Warning' },
  INFO:          { badge: 'bg-blue-100 text-blue-700 border-blue-300',   dot: 'bg-blue-500',   label: 'Info'    },
  LOGIN_SUCCESS: { badge: 'bg-green-100 text-green-700 border-green-300',dot: 'bg-green-500',  label: 'Login'   },
  CAPTURE:       { badge: 'bg-purple-100 text-purple-700 border-purple-300', dot: 'bg-purple-500', label: 'Capture' },
  NORMAL:        { badge: 'bg-gray-100 text-gray-600 border-gray-300',   dot: 'bg-gray-400',   label: 'Normal'  },
};

const SEVERITY_COLORS = {
  Critical: 'bg-red-100 text-red-700 border-red-300',
  High:     'bg-orange-100 text-orange-700 border-orange-300',
  Medium:   'bg-yellow-100 text-yellow-700 border-yellow-300',
  Low:      'bg-blue-100 text-blue-700 border-blue-300',
};

const LEVEL_TABS = [
  { key: 'ALL',           label: 'All'     },
  { key: 'ALERT',         label: 'Attacks' },
  { key: 'LOGIN_SUCCESS', label: 'Login'   },
  { key: 'NORMAL',        label: 'Normal'  },
  { key: 'CAPTURE',       label: 'Capture' },
  { key: 'ERROR',         label: 'Errors'  },
];

function IconChevron({ open }) {
  return (
    <svg className={`w-4 h-4 transition-transform duration-200 ${open ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
    </svg>
  );
}

function IconSearch() {
  return (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-4.35-4.35M17 11A6 6 0 115 11a6 6 0 0112 0z" />
    </svg>
  );
}

function IconX() {
  return (
    <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
    </svg>
  );
}

function IconFilter() {
  return (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 4h18M7 8h10M11 12h2M9 16h6" />
    </svg>
  );
}

function IconRefresh({ spin }) {
  return (
    <svg className={`w-4 h-4 ${spin ? 'animate-spin' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
    </svg>
  );
}

function LogRow({ log, index }) {
  const [open, setOpen] = useState(false);
  const style = LEVEL_STYLES[log.level] || LEVEL_STYLES.NORMAL;
  const hasDetails = log.details && typeof log.details === 'object' && Object.keys(log.details).length > 0;

  const extractIP = (msg = '') => {
    const m = msg.match(/(\d{1,3}\.){3}\d{1,3}/);
    return m ? m[0] : null;
  };

  const ip = extractIP(log.message);

  return (
    <div className={`border-b border-gray-100 transition-colors ${open ? 'bg-blue-50/30' : 'hover:bg-gray-50/70'}`}>
      <div
        className="px-6 py-4 flex items-start gap-4 cursor-pointer select-none"
        onClick={() => hasDetails && setOpen(o => !o)}
      >
        <div className="flex items-center gap-3 flex-shrink-0 pt-0.5">
          <span className={`w-2 h-2 rounded-full flex-shrink-0 ${style.dot}`} />
          <span className={`px-2.5 py-0.5 text-xs font-bold rounded-full border ${style.badge} whitespace-nowrap`}>
            {style.label}
          </span>
        </div>

        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-gray-800 leading-snug truncate">{log.message}</p>
          <div className="flex flex-wrap items-center gap-3 mt-1.5">
            {log.user && (
              <span className="text-xs text-gray-400">
                User: <span className="text-blue-600 font-semibold">{log.user}</span>
              </span>
            )}
            {ip && (
              <span className="text-xs font-mono text-gray-400">{ip}</span>
            )}
            {log.details?.severity && (
              <span className={`px-2 py-0.5 text-xs font-semibold rounded border ${SEVERITY_COLORS[log.details.severity] || 'bg-gray-100 text-gray-600 border-gray-300'}`}>
                {log.details.severity}
              </span>
            )}
            {log.details?.blocked !== undefined && (
              <span className={`px-2 py-0.5 text-xs font-semibold rounded border ${
                String(log.details.blocked) === 'true'
                  ? 'bg-red-100 text-red-700 border-red-300'
                  : 'bg-green-100 text-green-700 border-green-300'
              }`}>
                {String(log.details.blocked) === 'true' ? 'Blocked' : 'Allowed'}
              </span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-3 flex-shrink-0">
          <span className="text-xs text-gray-400 whitespace-nowrap">
            {new Date(log.timestamp).toLocaleString()}
          </span>
          {hasDetails && (
            <span className="text-gray-400">
              <IconChevron open={open} />
            </span>
          )}
        </div>
      </div>

      {open && hasDetails && (
        <div className="px-6 pb-4 ml-9">
          <div className="bg-white border border-gray-200 rounded-xl p-4 shadow-sm">
            <div className="text-xs font-bold text-gray-400 tracking-widest mb-3">DETAILS</div>
            <div className="grid grid-cols-2 gap-x-8 gap-y-2">
              {Object.entries(log.details).map(([key, value]) => (
                <div key={key} className="flex items-start gap-2 text-xs">
                  <span className="text-gray-400 font-medium min-w-[110px] capitalize">{key.replace(/_/g, ' ')}:</span>
                  <span className="text-gray-800 font-semibold break-all">
                    {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function SystemLogs({ user }) {
  const [logs, setLogs]           = useState([]);
  const [loading, setLoading]     = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [levelFilter, setLevelFilter] = useState('ALL');
  const [search, setSearch]       = useState('');
  const [searchInput, setSearchInput] = useState('');
  const [severity, setSeverity]   = useState('ALL');
  const [blocked, setBlocked]     = useState('ALL');
  const [dateFrom, setDateFrom]   = useState('');
  const [dateTo, setDateTo]       = useState('');
  const [showFilters, setShowFilters] = useState(false);

  useEffect(() => {
    fetchLogs();
    const interval = setInterval(fetchLogs, 5000);
    return () => clearInterval(interval);
  }, []);

  const fetchLogs = async (manual = false) => {
    if (manual) setRefreshing(true);
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('http://localhost:8000/system-logs', {
        headers: { Authorization: `Bearer ${token}` },
        params: { limit: 200 }
      });
      setLogs(response.data || []);
      setLoading(false);
    } catch {
      setLoading(false);
    }
    if (manual) setRefreshing(false);
  };

  const counts = useMemo(() => {
    const c = { ALL: logs.length };
    LEVEL_TABS.forEach(t => {
      if (t.key !== 'ALL') c[t.key] = logs.filter(l => l.level === t.key).length;
    });
    return c;
  }, [logs]);

  const filtered = useMemo(() => {
    return logs.slice().reverse().filter(log => {
      if (levelFilter !== 'ALL' && log.level !== levelFilter) return false;

      if (search) {
        const q = search.toLowerCase();
        const msg   = (log.message || '').toLowerCase();
        const usr   = (log.user || '').toLowerCase();
        const atk   = (log.details?.attack || '').toLowerCase();
        const ip    = (log.message || '').match(/(\d{1,3}\.){3}\d{1,3}/)?.[0] || '';
        if (!msg.includes(q) && !usr.includes(q) && !atk.includes(q) && !ip.includes(q)) return false;
      }

      if (severity !== 'ALL' && log.details?.severity !== severity) return false;

      if (blocked !== 'ALL') {
        const isBlocked = String(log.details?.blocked) === 'true';
        if (blocked === 'BLOCKED' && !isBlocked) return false;
        if (blocked === 'ALLOWED' && isBlocked) return false;
      }

      if (dateFrom) {
        if (new Date(log.timestamp) < new Date(dateFrom)) return false;
      }
      if (dateTo) {
        const to = new Date(dateTo);
        to.setHours(23, 59, 59, 999);
        if (new Date(log.timestamp) > to) return false;
      }

      return true;
    });
  }, [logs, levelFilter, search, severity, blocked, dateFrom, dateTo]);

  const hasActiveFilters = severity !== 'ALL' || blocked !== 'ALL' || dateFrom || dateTo;

  const clearAllFilters = () => {
    setSeverity('ALL');
    setBlocked('ALL');
    setDateFrom('');
    setDateTo('');
    setSearch('');
    setSearchInput('');
    setLevelFilter('ALL');
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <div className="animate-spin rounded-full h-10 w-10 border-4 border-blue-600 border-t-transparent mx-auto mb-3" />
          <p className="text-gray-400 text-sm">Loading logs...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full" style={{ minHeight: 'calc(100vh - 130px)' }}>
      <div className="bg-white rounded-2xl border border-gray-200 shadow-sm flex flex-col flex-1 overflow-hidden">

        <div className="px-6 pt-5 pb-4 border-b border-gray-100 flex-shrink-0">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 bg-blue-100 rounded-xl flex items-center justify-center">
                <svg className="w-4 h-4 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
              </div>
              <div>
                <h2 className="text-base font-bold text-gray-900">System Logs</h2>
                <p className="text-xs text-gray-400">
                  Showing <span className="font-semibold text-gray-600">{filtered.length}</span> of <span className="font-semibold text-gray-600">{logs.length}</span> entries
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              {(search || hasActiveFilters) && (
                <button onClick={clearAllFilters}
                  className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-red-600 hover:bg-red-50 border border-red-200 rounded-xl transition">
                  <IconX /> Clear all
                </button>
              )}
              <button
                onClick={() => setShowFilters(f => !f)}
                className={`flex items-center gap-1.5 px-3 py-2 text-xs font-semibold rounded-xl border transition ${
                  showFilters || hasActiveFilters
                    ? 'bg-blue-600 text-white border-blue-600'
                    : 'text-gray-600 border-gray-200 hover:bg-gray-50'
                }`}
              >
                <IconFilter />
                Filters
                {hasActiveFilters && <span className="w-4 h-4 bg-white text-blue-600 rounded-full text-xs font-black flex items-center justify-center">!</span>}
              </button>
              <button onClick={() => fetchLogs(true)}
                className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-gray-600 hover:bg-gray-50 border border-gray-200 rounded-xl transition">
                <IconRefresh spin={refreshing} />
                Refresh
              </button>
            </div>
          </div>

          <div className="relative mb-4">
            <div className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400">
              <IconSearch />
            </div>
            <input
              type="text"
              value={searchInput}
              onChange={e => setSearchInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && setSearch(searchInput)}
              placeholder="Search by message, IP address, user, attack type... then press Enter"
              className="w-full pl-10 pr-24 py-2.5 border border-gray-200 rounded-xl text-sm focus:ring-2 focus:ring-blue-400 focus:outline-none bg-gray-50 focus:bg-white transition"
            />
            <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1">
              {searchInput && (
                <button onClick={() => { setSearchInput(''); setSearch(''); }} className="p-1 text-gray-400 hover:text-gray-600">
                  <IconX />
                </button>
              )}
              <button onClick={() => setSearch(searchInput)}
                className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold rounded-lg transition">
                Search
              </button>
            </div>
          </div>

          {showFilters && (
            <div className="bg-gray-50 border border-gray-200 rounded-xl p-4 mb-4 grid grid-cols-4 gap-4">
              <div>
                <label className="text-xs font-bold text-gray-500 mb-1.5 block tracking-wider">SEVERITY</label>
                <select value={severity} onChange={e => setSeverity(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-400 focus:outline-none bg-white">
                  <option value="ALL">All Severities</option>
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                </select>
              </div>
              <div>
                <label className="text-xs font-bold text-gray-500 mb-1.5 block tracking-wider">STATUS</label>
                <select value={blocked} onChange={e => setBlocked(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-400 focus:outline-none bg-white">
                  <option value="ALL">All Status</option>
                  <option value="BLOCKED">Blocked</option>
                  <option value="ALLOWED">Allowed</option>
                </select>
              </div>
              <div>
                <label className="text-xs font-bold text-gray-500 mb-1.5 block tracking-wider">FROM DATE</label>
                <input type="date" value={dateFrom} onChange={e => setDateFrom(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-400 focus:outline-none bg-white" />
              </div>
              <div>
                <label className="text-xs font-bold text-gray-500 mb-1.5 block tracking-wider">TO DATE</label>
                <input type="date" value={dateTo} onChange={e => setDateTo(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-400 focus:outline-none bg-white" />
              </div>
            </div>
          )}

          <div className="flex gap-1">
            {LEVEL_TABS.map(tab => (
              <button key={tab.key} onClick={() => setLevelFilter(tab.key)}
                className={`px-4 py-2 rounded-lg text-xs font-bold transition-all ${
                  levelFilter === tab.key
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'text-gray-500 hover:text-gray-700 hover:bg-gray-100'
                }`}>
                {tab.label}
                <span className={`ml-1.5 px-1.5 py-0.5 rounded-full text-xs ${
                  levelFilter === tab.key ? 'bg-white/20 text-white' : 'bg-gray-200 text-gray-600'
                }`}>
                  {counts[tab.key] || 0}
                </span>
              </button>
            ))}
          </div>
        </div>

        <div className="flex-1 overflow-y-auto divide-y divide-gray-100">
          {filtered.length > 0 ? (
            filtered.map((log, i) => (
              <LogRow key={i} log={log} index={i} />
            ))
          ) : (
            <div className="flex flex-col items-center justify-center h-64 text-center">
              <svg className="w-14 h-14 text-gray-200 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              <p className="text-gray-500 font-semibold">No logs found</p>
              <p className="text-gray-400 text-sm mt-1">
                {search || hasActiveFilters ? 'Try adjusting your search or filters' : 'System has no logs yet'}
              </p>
              {(search || hasActiveFilters) && (
                <button onClick={clearAllFilters} className="mt-3 px-4 py-2 bg-blue-600 text-white text-xs font-bold rounded-lg hover:bg-blue-700 transition">
                  Clear filters
                </button>
              )}
            </div>
          )}
        </div>

        <div className="px-6 py-3 bg-gray-50 border-t border-gray-100 flex items-center justify-between flex-shrink-0">
          <span className="text-xs text-gray-400">
            {filtered.length} result{filtered.length !== 1 ? 's' : ''} · Auto-refreshes every 5s
          </span>
          <div className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 bg-green-400 rounded-full animate-pulse" />
            <span className="text-xs text-gray-400">Live</span>
          </div>
        </div>
      </div>
    </div>
  );
}
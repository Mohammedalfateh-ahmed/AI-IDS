import React, { useState, useEffect, useCallback } from 'react';
import {
  Activity, AlertTriangle, Eye, CheckCircle, Shield,
  Brain, Clock, Network, TrendingUp, BarChart2,
  ChevronRight, RefreshCw, WifiOff, Layers,
  Cpu, Globe, Lock, Zap, Radio, Filter
} from 'lucide-react';

const C = {
  pageBg:     '#F1F5F9',
  surface:    '#FFFFFF',
  surfaceAlt: '#F8FAFC',
  blue:       '#1E40AF',
  blueMid:    '#2563EB',
  blueLight:  '#DBEAFE',
  blueDim:    '#EFF6FF',
  border:     '#E2E8F0',
  borderBlue: '#BFDBFE',
  critical:   '#DC2626',
  criticalBg: '#FEF2F2',
  high:       '#D97706',
  highBg:     '#FFFBEB',
  medium:     '#0369A1',
  mediumBg:   '#F0F9FF',
  low:        '#15803D',
  lowBg:      '#F0FDF4',
  text:       '#0F172A',
  textSub:    '#334155',
  textMuted:  '#64748B',
};

const scoreColor = s => s >= 80 ? C.critical : s >= 60 ? C.high : s >= 40 ? C.medium : C.low;
const RISK = {
  CRITICAL: { color: C.critical, bg: C.criticalBg },
  HIGH:     { color: C.high,     bg: C.highBg     },
  MEDIUM:   { color: C.medium,   bg: C.mediumBg   },
  LOW:      { color: C.low,      bg: C.lowBg      },
  NORMAL:   { color: C.textMuted,bg: C.surfaceAlt },
};
const rm = l => RISK[l] || RISK.NORMAL;

const pill = (color, bg) => ({
  background: bg, color,
  border: `1px solid ${color}30`,
  borderRadius: 4, padding: '2px 8px',
  fontSize: 10, fontWeight: 700,
  letterSpacing: 0.6, textTransform: 'uppercase',
  whiteSpace: 'nowrap', display: 'inline-block',
});

const Bar = ({ value, max = 100, color, h = 5 }) => (
  <div style={{ height: h, background: C.border, borderRadius: h, overflow: 'hidden', flex: 1 }}>
    <div style={{ height: '100%', width: `${Math.min(Math.max((value / max) * 100, 0), 100)}%`, background: color, borderRadius: h, transition: 'width .5s' }} />
  </div>
);

const Card = ({ children, style }) => (
  <div style={{
    background: C.surface, border: `1px solid ${C.border}`, borderRadius: 10,
    overflow: 'hidden', boxShadow: '0 1px 3px rgba(15,23,42,0.06)', ...style,
  }}>{children}</div>
);

const SHead = ({ icon: Icon, title, sub, right }) => (
  <div style={{
    display: 'flex', alignItems: 'center', gap: 8, padding: '11px 16px',
    background: C.blueDim, borderBottom: `1px solid ${C.borderBlue}`,
  }}>
    <Icon size={14} color={C.blueMid} />
    <span style={{ color: C.blue, fontSize: 13, fontWeight: 700, flex: 1 }}>{title}</span>
    {sub && <span style={{ color: C.textMuted, fontSize: 11 }}>{sub}</span>}
    {right}
  </div>
);

const StatCard = ({ label, value, icon: Icon, color, sub }) => (
  <div style={{
    background: C.surface, border: `1px solid ${C.border}`, borderRadius: 10,
    padding: '18px 20px', borderTop: `4px solid ${color}`,
    boxShadow: '0 1px 3px rgba(15,23,42,0.06)',
  }}>
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
      <span style={{ color: C.textMuted, fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.8 }}>{label}</span>
      <div style={{ background: `${color}15`, borderRadius: 7, padding: 6 }}>
        <Icon size={14} color={color} />
      </div>
    </div>
    <div style={{ color: C.text, fontSize: 34, fontWeight: 800, lineHeight: 1, marginBottom: 4 }}>{value ?? 0}</div>
    {sub && <div style={{ color: C.textMuted, fontSize: 11 }}>{sub}</div>}
  </div>
);

const Empty = ({ icon: Icon, msg, ok }) => (
  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '40px 0', gap: 12 }}>
    <div style={{ background: ok ? C.lowBg : C.surfaceAlt, borderRadius: '50%', padding: 16, border: `1px solid ${ok ? C.low + '30' : C.border}` }}>
      <Icon size={26} color={ok ? C.low : C.textMuted} strokeWidth={1.3} />
    </div>
    <p style={{ margin: 0, color: ok ? C.low : C.textMuted, fontSize: 13, fontWeight: 500 }}>{msg}</p>
  </div>
);

const BASE = 'http://localhost:8000';

export default function BehavioralAnomalyWidget() {
  const [stats,      setStats]      = useState(null);
  const [topIPs,     setTopIPs]     = useState([]);
  const [anomalies,  setAnomalies]  = useState([]);
  const [loading,    setLoading]    = useState(true);
  const [connected,  setConnected]  = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [updatedAt,  setUpdatedAt]  = useState('');
  const [activeIP,   setActiveIP]   = useState(null);
  const [ipProfile,  setIpProfile]  = useState(null);
  const [activeTab,  setActiveTab]  = useState('overview');
  const [filter,     setFilter]     = useState('ALL');
  const [history,    setHistory]    = useState([]);
  const [apiError,   setApiError]   = useState('');

  const hdrs = () => ({ 'Authorization': `Bearer ${localStorage.getItem('token')}` });

  const fetchAll = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    try {
      const [sRes, ipRes, aRes] = await Promise.all([
        fetch(`${BASE}/behavior/statistics`,                { headers: hdrs() }),
        fetch(`${BASE}/behavior/top-anomalous-ips?limit=10`,{ headers: hdrs() }),
        fetch(`${BASE}/behavior/anomalies?limit=50`,        { headers: hdrs() }),
      ]);

      if (!sRes.ok) throw new Error(`Statistics API error: ${sRes.status}`);
      if (!ipRes.ok) throw new Error(`Top IPs API error: ${ipRes.status}`);
      if (!aRes.ok)  throw new Error(`Anomalies API error: ${aRes.status}`);

      const [sd, id, ad] = await Promise.all([sRes.json(), ipRes.json(), aRes.json()]);

      const s = sd.statistics || {};
      setStats(s);
      setTopIPs(id.top_anomalous_ips || []);
      setAnomalies(ad.anomalies || []);
      setConnected(true);
      setApiError('');
      setUpdatedAt(new Date().toLocaleTimeString());
      setHistory(prev => [...prev.slice(-29), s.total_anomalies_detected || 0]);
    } catch (err) {
      setConnected(false);
      setApiError(err.message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  const fetchIP = async ip => {
    if (activeIP === ip) { setActiveIP(null); setIpProfile(null); return; }
    setActiveIP(ip); setIpProfile(null);
    try {
      const r = await fetch(`${BASE}/behavior/ip/${ip}`, { headers: hdrs() });
      if (!r.ok) throw new Error();
      const d = await r.json();
      setIpProfile(d.profile);
    } catch { setIpProfile({ error: true }); }
  };

  useEffect(() => {
    fetchAll();
    const iv = setInterval(fetchAll, 5000);
    return () => clearInterval(iv);
  }, [fetchAll]);

  const riskDist  = stats?.risk_distribution || {};
  const riskTotal = Object.values(riskDist).reduce((a, b) => a + b, 0);

  const typeCounts = {};
  anomalies.forEach(a => {
    const anom = a.anomalies || {};
    Object.keys(anom).forEach(k => { typeCounts[k] = (typeCounts[k] || 0) + 1; });
  });
  const typeEntries = Object.entries(typeCounts).sort((a, b) => b[1] - a[1]);
  const maxType = typeEntries[0]?.[1] || 1;

  const filteredAnomalies = filter === 'ALL'
    ? anomalies
    : anomalies.filter(a => a.risk_level === filter);

  const recentIPs      = [...new Set(anomalies.slice(0, 10).map(a => a.ip))];
  const avgScore       = anomalies.length ? Math.round(anomalies.reduce((s, a) => s + (a.anomaly_score || 0), 0) / anomalies.length) : 0;
  const criticalCount  = anomalies.filter(a => a.risk_level === 'CRITICAL').length;
  const learnedPct     = stats?.total_ips_tracked > 0 ? Math.round((stats.baselines_learned / stats.total_ips_tracked) * 100) : 0;

  const TABS = [
    { id: 'overview',  label: 'Overview',        icon: Layers   },
    { id: 'ips',       label: 'IP Profiles',     icon: Globe    },
    { id: 'anomalies', label: 'Anomaly Events',  icon: Activity },
    { id: 'detection', label: 'Detection Engine',icon: Cpu      },
  ];

  if (loading) return (
    <div style={{ minHeight: '100vh', background: C.pageBg, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ textAlign: 'center' }}>
        <div style={{ width: 38, height: 38, border: `3px solid ${C.border}`, borderTopColor: C.blueMid, borderRadius: '50%', animation: 'bSpin .7s linear infinite', margin: '0 auto 14px' }} />
        <p style={{ color: C.textMuted, fontSize: 13, margin: 0 }}>Loading behavioral engine…</p>
        <style>{`@keyframes bSpin{to{transform:rotate(360deg)}}`}</style>
      </div>
    </div>
  );

  return (
    <div style={{ background: C.pageBg, minHeight: '100vh', fontFamily: "'Segoe UI', system-ui, sans-serif", color: C.text }}>
      <style>{`
        @keyframes bSpin { to { transform: rotate(360deg); } }
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 5px; }
        ::-webkit-scrollbar-track { background: ${C.surfaceAlt}; }
        ::-webkit-scrollbar-thumb { background: ${C.borderBlue}; border-radius: 3px; }
        .hov-row:hover { background: ${C.blueDim} !important; cursor: pointer; }
        .tab-btn { cursor: pointer; border: none; background: transparent; font-family: inherit; }
      `}</style>

      {/* ── HEADER ── */}
      <div style={{
        background: `linear-gradient(90deg, ${C.blue} 0%, ${C.blueMid} 100%)`,
        padding: '14px 24px', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        boxShadow: '0 2px 8px rgba(30,64,175,0.2)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ background: 'rgba(255,255,255,0.15)', borderRadius: 8, padding: 8 }}>
            <Brain size={20} color="#fff" />
          </div>
          <div>
            <h1 style={{ color: '#fff', fontSize: 16, fontWeight: 700, margin: 0 }}>Behavioral Anomaly Detection</h1>
            <p style={{ color: 'rgba(255,255,255,0.65)', fontSize: 11, margin: '3px 0 0' }}>
              Statistical baseline · 3σ deviation · Dual-layer IDS · Auto-refresh 5s
            </p>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, background: 'rgba(255,255,255,0.12)', borderRadius: 20, padding: '4px 12px' }}>
            {connected
              ? <><span style={{ width: 7, height: 7, borderRadius: '50%', background: '#4ade80', display: 'inline-block', boxShadow: '0 0 6px #4ade80' }} /><span style={{ color: '#fff', fontSize: 11, fontWeight: 700 }}>LIVE</span></>
              : <><WifiOff size={11} color="#fca5a5" /><span style={{ color: '#fca5a5', fontSize: 11 }}>OFFLINE</span></>}
          </div>
          {updatedAt && <span style={{ color: 'rgba(255,255,255,0.55)', fontSize: 11 }}>Updated {updatedAt}</span>}
          <button onClick={() => fetchAll(true)} disabled={refreshing} style={{
            background: 'rgba(255,255,255,0.15)', border: '1px solid rgba(255,255,255,0.25)',
            borderRadius: 6, padding: '6px 14px', cursor: 'pointer',
            color: '#fff', display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, fontWeight: 600,
          }}>
            <RefreshCw size={12} style={{ animation: refreshing ? 'bSpin .7s linear infinite' : 'none' }} />
            Refresh
          </button>
        </div>
      </div>

      {/* ── TABS ── */}
      <div style={{ background: C.surface, borderBottom: `1px solid ${C.border}`, padding: '0 24px', display: 'flex' }}>
        {TABS.map(t => (
          <button key={t.id} className="tab-btn" onClick={() => setActiveTab(t.id)} style={{
            padding: '12px 18px', display: 'flex', alignItems: 'center', gap: 6,
            color: activeTab === t.id ? C.blueMid : C.textMuted,
            fontSize: 13, fontWeight: activeTab === t.id ? 700 : 500,
            borderBottom: activeTab === t.id ? `2px solid ${C.blueMid}` : '2px solid transparent',
            marginBottom: -1,
          }}>
            <t.icon size={13} />{t.label}
          </button>
        ))}
      </div>

      {/* ── CONTENT ── */}
      <div style={{ padding: '20px 24px', display: 'flex', flexDirection: 'column', gap: 16 }}>

        {/* Connection error banner */}
        {!connected && (
          <div style={{ background: C.criticalBg, border: `1px solid ${C.critical}25`, borderRadius: 8, padding: '10px 16px', display: 'flex', alignItems: 'center', gap: 8 }}>
            <AlertTriangle size={14} color={C.critical} />
            <div>
              <span style={{ color: C.critical, fontSize: 13, fontWeight: 600 }}>Backend connection failed</span>
              {apiError && <span style={{ color: C.critical, fontSize: 12, marginLeft: 8 }}>— {apiError}</span>}
              <p style={{ color: C.critical, fontSize: 11, margin: '2px 0 0' }}>Make sure the FastAPI server is running on port 8000 and behavioral endpoints are registered.</p>
            </div>
          </div>
        )}

        {/* ════ OVERVIEW TAB ════ */}
        {activeTab === 'overview' && (
          <>
            {/* 5 stat cards — maps to /behavior/statistics response */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 14 }}>
              <StatCard label="IPs Monitored"    value={stats?.total_ips_tracked}       icon={Eye}           color={C.blueMid}  sub={`${learnedPct}% baselines ready`} />
              <StatCard label="Baselines Learned" value={stats?.baselines_learned}        icon={CheckCircle}   color={C.low}      sub={stats?.learning_progress || '—'} />
              <StatCard label="Total Anomalies"   value={stats?.total_anomalies_detected} icon={AlertTriangle} color={C.high}     sub={`${criticalCount} critical`} />
              <StatCard label="Last Hour"         value={stats?.anomalies_last_hour}      icon={Clock}         color={C.critical} sub="Recent activity" />
              <StatCard label="Avg Score"         value={avgScore}                        icon={Zap}           color={C.medium}   sub="Across all events" />
            </div>

            {/* Trend chart + risk dist */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 300px', gap: 14 }}>
              <Card>
                <SHead icon={TrendingUp} title="Live Anomaly Trend" sub="Total anomalies over time — updates every 5s" />
                <div style={{ padding: 20 }}>
                  {history.length > 1 ? (
                    <>
                      <svg width="100%" height="100" viewBox={`0 0 ${Math.max(history.length * 28, 280)} 100`} preserveAspectRatio="none">
                        <defs>
                          <linearGradient id="aGrad" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor={C.blueMid} stopOpacity="0.2" />
                            <stop offset="100%" stopColor={C.blueMid} stopOpacity="0" />
                          </linearGradient>
                        </defs>
                        {(() => {
                          const max = Math.max(...history, 1);
                          const W = Math.max(history.length * 28, 280);
                          const pts = history.map((v, i) => `${(i / (history.length - 1)) * W},${100 - (v / max) * 85}`);
                          return (
                            <>
                              <path d={`M${pts[0]} ` + pts.slice(1).map(p => `L${p}`).join(' ') + ` L${W},100 L0,100 Z`} fill="url(#aGrad)" />
                              <polyline fill="none" stroke={C.blueMid} strokeWidth="2.5" strokeLinejoin="round" points={pts.join(' ')} />
                              {history.map((v, i) => (
                                <circle key={i} cx={(i / (history.length - 1)) * Math.max(history.length * 28, 280)} cy={100 - (v / max) * 85} r={i === history.length - 1 ? 5 : 3} fill={C.blueMid} opacity={i === history.length - 1 ? 1 : 0.35} />
                              ))}
                            </>
                          );
                        })()}
                      </svg>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 6 }}>
                        <span style={{ color: C.textMuted, fontSize: 10 }}>Oldest ({history.length} samples)</span>
                        <span style={{ color: C.blueMid, fontSize: 10, fontWeight: 600 }}>Latest: {history[history.length - 1]}</span>
                      </div>
                    </>
                  ) : (
                    <div style={{ textAlign: 'center', padding: '20px 0', color: C.textMuted, fontSize: 13 }}>
                      Sparkline appears after 2+ data points — simulate attacks on Dashboard tab
                    </div>
                  )}
                </div>
              </Card>

              <Card>
                <SHead icon={BarChart2} title="Risk Distribution" />
                <div style={{ padding: 18 }}>
                  {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(level => {
                    const r = rm(level);
                    const count = riskDist[level] || 0;
                    const pct = riskTotal > 0 ? Math.round((count / riskTotal) * 100) : 0;
                    return (
                      <div key={level} style={{ marginBottom: 14 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 5 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                            <span style={{ width: 8, height: 8, borderRadius: '50%', background: r.color, display: 'inline-block' }} />
                            <span style={{ color: C.text, fontSize: 12, fontWeight: 700 }}>{level}</span>
                          </div>
                          <div style={{ display: 'flex', gap: 8 }}>
                            <span style={{ color: r.color, fontWeight: 800, fontSize: 16 }}>{count}</span>
                            <span style={{ color: C.textMuted, fontSize: 11 }}>{pct}%</span>
                          </div>
                        </div>
                        <div style={{ height: 8, background: C.surfaceAlt, borderRadius: 4, overflow: 'hidden', border: `1px solid ${C.border}` }}>
                          <div style={{ height: '100%', width: `${pct}%`, background: r.color, borderRadius: 4, transition: 'width .5s' }} />
                        </div>
                      </div>
                    );
                  })}
                  <div style={{ paddingTop: 12, borderTop: `1px solid ${C.border}`, display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: C.textMuted, fontSize: 12 }}>Total</span>
                    <span style={{ color: C.text, fontWeight: 800 }}>{riskTotal}</span>
                  </div>
                </div>
              </Card>
            </div>

            {/* Anomaly type breakdown — derived from /behavior/anomalies → anomalies[].anomalies keys */}
            {typeEntries.length > 0 && (
              <Card>
                <SHead icon={Filter} title="Anomaly Type Breakdown" sub="Behavioral patterns flagged across all events" />
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 12, padding: 16 }}>
                  {typeEntries.map(([type, count]) => (
                    <div key={type} style={{ background: C.surfaceAlt, borderRadius: 8, padding: '13px 15px', border: `1px solid ${C.border}` }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                        <span style={{ color: C.text, fontSize: 12, fontWeight: 700, textTransform: 'capitalize' }}>{type.replace(/_/g, ' ')}</span>
                        <span style={{ color: C.blueMid, fontWeight: 800 }}>{count}</span>
                      </div>
                      <Bar value={count} max={maxType} color={C.blueMid} />
                      <div style={{ color: C.textMuted, fontSize: 10, marginTop: 5 }}>
                        {Math.round((count / (anomalies.length || 1)) * 100)}% of events
                      </div>
                    </div>
                  ))}
                </div>
              </Card>
            )}

            {/* Recent threat sources — derived from /behavior/anomalies → [].ip */}
            {recentIPs.length > 0 && (
              <Card>
                <SHead icon={Radio} title="Recent Threat Sources" sub="IPs seen in last 10 anomaly events" />
                <div style={{ padding: '12px 16px', display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                  {recentIPs.map(ip => (
                    <div key={ip} onClick={() => { setActiveTab('ips'); fetchIP(ip); }} style={{
                      background: C.criticalBg, border: `1px solid ${C.critical}30`, borderRadius: 6,
                      padding: '6px 12px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6,
                    }}>
                      <span style={{ width: 6, height: 6, borderRadius: '50%', background: C.critical, display: 'inline-block' }} />
                      <span style={{ color: C.blue, fontFamily: 'monospace', fontSize: 12, fontWeight: 700 }}>{ip}</span>
                    </div>
                  ))}
                </div>
              </Card>
            )}
          </>
        )}

        {/* ════ IP PROFILES TAB ════ */}
        {activeTab === 'ips' && (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>

            {/* Left: ranked list from /behavior/top-anomalous-ips */}
            <Card>
              <SHead icon={TrendingUp} title="Top Anomalous IPs" right={<span style={pill(C.blueMid, C.blueLight)}>{topIPs.length} IPs</span>} />
              <div>
                {topIPs.length === 0
                  ? <Empty icon={Shield} msg="No anomalous IPs detected yet — simulate attacks to generate data" ok />
                  : topIPs.map((ip, i) => (
                    <React.Fragment key={ip.ip_address}>
                      <div className="hov-row" onClick={() => fetchIP(ip.ip_address)} style={{
                        display: 'flex', alignItems: 'center', gap: 10, padding: '11px 16px',
                        borderBottom: `1px solid ${C.border}`,
                        background: activeIP === ip.ip_address ? C.blueDim : i % 2 === 0 ? C.surface : C.surfaceAlt,
                        borderLeft: `3px solid ${activeIP === ip.ip_address ? C.blueMid : 'transparent'}`,
                        transition: 'all .15s',
                      }}>
                        <div style={{
                          width: 26, height: 26, borderRadius: '50%', flexShrink: 0,
                          background: i < 3 ? C.blue : C.border,
                          color: i < 3 ? '#fff' : C.textMuted,
                          fontSize: 11, fontWeight: 800,
                          display: 'flex', alignItems: 'center', justifyContent: 'center',
                        }}>{i + 1}</div>
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                            <span style={{ color: C.blue, fontFamily: 'monospace', fontSize: 13, fontWeight: 700 }}>
                              {ip.ip_address}
                            </span>
                            {ip.baseline_learned
                              ? <span style={pill(C.low, C.lowBg)}>✓ learned</span>
                              : <span style={pill(C.textMuted, C.surfaceAlt)}>learning</span>}
                          </div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 5 }}>
                            <Bar value={ip.max_anomaly_score} max={100} color={scoreColor(ip.max_anomaly_score)} />
                            <span style={{ color: C.textMuted, fontSize: 10, whiteSpace: 'nowrap' }}>
                              {ip.anomaly_count} events · {ip.packets_observed} pkts
                            </span>
                          </div>
                        </div>
                        <div style={{ textAlign: 'right', flexShrink: 0 }}>
                          <div style={{ color: scoreColor(ip.max_anomaly_score), fontWeight: 800, fontSize: 24, lineHeight: 1 }}>
                            {ip.max_anomaly_score}
                          </div>
                          <div style={{ color: C.textMuted, fontSize: 10 }}>/ 100</div>
                        </div>
                        <ChevronRight size={13} color={C.textMuted} />
                      </div>

                      {/* Inline profile from /behavior/ip/{ip} */}
                      {activeIP === ip.ip_address && (
                        <div style={{ margin: '0 14px 10px', background: C.blueDim, border: `1px solid ${C.borderBlue}`, borderRadius: 8, padding: 16 }}>
                          {!ipProfile
                            ? <p style={{ color: C.textMuted, fontSize: 12, margin: 0 }}>Loading profile…</p>
                            : ipProfile.error
                            ? <p style={{ color: C.critical, fontSize: 12, margin: 0 }}>Failed to load profile from /behavior/ip/{ip.ip_address}</p>
                            : (
                              <>
                                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '10px 20px', marginBottom: 12 }}>
                                  {[
                                    ['Packets observed',  ipProfile.packets_observed],
                                    ['Total bytes',       ipProfile.total_bytes?.toLocaleString()],
                                    ['Avg packet size',   ipProfile.avg_packet_size ? `${ipProfile.avg_packet_size} B` : '—'],
                                    ['Typical ports',     (ipProfile.typical_ports || []).join(', ') || '—'],
                                    ['Protocols',         (ipProfile.typical_protocols || []).join(', ') || '—'],
                                    ['Active hours',      (ipProfile.most_active_hours || []).map(h => `${h}:00`).join(', ') || '—'],
                                  ].map(([k, v]) => (
                                    <div key={k}>
                                      <div style={{ color: C.textMuted, fontSize: 10, textTransform: 'uppercase', letterSpacing: 0.4, marginBottom: 2 }}>{k}</div>
                                      <div style={{ color: C.text, fontSize: 12, fontWeight: 700 }}>{v ?? '—'}</div>
                                    </div>
                                  ))}
                                </div>
                                {/* Anomaly history for this IP from /behavior/anomalies */}
                                <div style={{ paddingTop: 10, borderTop: `1px solid ${C.borderBlue}` }}>
                                  <div style={{ color: C.textMuted, fontSize: 10, textTransform: 'uppercase', letterSpacing: 0.4, marginBottom: 6 }}>
                                    Anomaly history
                                  </div>
                                  <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                                    {anomalies.filter(a => a.ip === ip.ip_address).slice(0, 8).map((a, j) => {
                                      const r = rm(a.risk_level);
                                      return (
                                        <div key={j} style={{ background: r.bg, border: `1px solid ${r.color}25`, borderRadius: 5, padding: '4px 8px', fontSize: 10 }}>
                                          <span style={{ color: r.color, fontWeight: 700 }}>{a.anomaly_score}</span>
                                          <span style={{ color: C.textMuted, marginLeft: 4 }}>{new Date(a.timestamp).toLocaleTimeString()}</span>
                                        </div>
                                      );
                                    })}
                                    {anomalies.filter(a => a.ip === ip.ip_address).length === 0 && (
                                      <span style={{ color: C.textMuted, fontSize: 11 }}>No anomaly history yet</span>
                                    )}
                                  </div>
                                </div>
                              </>
                            )}
                        </div>
                      )}
                    </React.Fragment>
                  ))}
              </div>
            </Card>

            {/* Right: table view */}
            <Card>
              <SHead icon={Network} title="IP Profiles Table" sub="Full details — click row to inspect" />
              {topIPs.length === 0
                ? <Empty icon={Shield} msg="No IP profiles yet" />
                : (
                  <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                      <thead>
                        <tr style={{ background: C.surfaceAlt }}>
                          {['IP Address', 'Packets', 'Anomalies', 'Max Score', 'Baseline', 'Risk'].map(h => (
                            <th key={h} style={{ padding: '9px 14px', textAlign: 'left', color: C.textMuted, fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.5, borderBottom: `2px solid ${C.borderBlue}` }}>{h}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {topIPs.map((ip, i) => {
                          const s = ip.max_anomaly_score;
                          const rl = s >= 80 ? 'CRITICAL' : s >= 60 ? 'HIGH' : s >= 40 ? 'MEDIUM' : 'LOW';
                          const r = rm(rl);
                          return (
                            <tr key={ip.ip_address} className="hov-row" onClick={() => fetchIP(ip.ip_address)} style={{ background: i % 2 === 0 ? C.surface : C.surfaceAlt, borderBottom: `1px solid ${C.border}` }}>
                              <td style={{ padding: '9px 14px' }}><span style={{ color: C.blue, fontFamily: 'monospace', fontWeight: 700 }}>{ip.ip_address}</span></td>
                              <td style={{ padding: '9px 14px', color: C.textSub }}>{ip.packets_observed}</td>
                              <td style={{ padding: '9px 14px', color: C.high, fontWeight: 700 }}>{ip.anomaly_count}</td>
                              <td style={{ padding: '9px 14px' }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                  <span style={{ color: scoreColor(s), fontWeight: 800, minWidth: 26 }}>{s}</span>
                                  <Bar value={s} max={100} color={scoreColor(s)} />
                                </div>
                              </td>
                              <td style={{ padding: '9px 14px' }}>
                                {ip.baseline_learned
                                  ? <span style={pill(C.low, C.lowBg)}>✓ learned</span>
                                  : <span style={pill(C.textMuted, C.surfaceAlt)}>learning…</span>}
                              </td>
                              <td style={{ padding: '9px 14px' }}><span style={pill(r.color, r.bg)}>{rl}</span></td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
            </Card>
          </div>
        )}

        {/* ════ ANOMALY EVENTS TAB ════ */}
        {activeTab === 'anomalies' && (
          <Card>
            <SHead
              icon={Activity} title="Behavioral Anomaly Events"
              sub={`${filteredAnomalies.length} of ${anomalies.length} events`}
              right={
                <div style={{ display: 'flex', gap: 4 }}>
                  {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(f => {
                    const active = filter === f;
                    const r = f === 'ALL' ? { color: C.blueMid, bg: C.blueLight } : rm(f);
                    return (
                      <button key={f} onClick={() => setFilter(f)} style={{
                        background: active ? r.bg : 'transparent',
                        color: active ? r.color : C.textMuted,
                        border: `1px solid ${active ? r.color + '40' : C.border}`,
                        borderRadius: 4, padding: '3px 8px',
                        fontSize: 10, fontWeight: 700, cursor: 'pointer', letterSpacing: 0.5,
                        fontFamily: 'inherit',
                      }}>{f}</button>
                    );
                  })}
                </div>
              }
            />
            <div style={{ maxHeight: 600, overflowY: 'auto' }}>
              {filteredAnomalies.length === 0
                ? <Empty icon={CheckCircle} msg="No anomalies match this filter" ok />
                : filteredAnomalies.map((a, i) => {
                  const r = rm(a.risk_level);
                  const anomTags = Object.entries(a.anomalies || {});
                  return (
                    <div key={i} style={{ padding: '12px 16px', borderBottom: `1px solid ${C.border}`, background: i % 2 === 0 ? C.surface : C.surfaceAlt }}>
                      <div style={{ display: 'flex', gap: 12 }}>
                        <div style={{ background: r.bg, border: `1px solid ${r.color}25`, borderRadius: 8, padding: '10px 12px', flexShrink: 0, textAlign: 'center', minWidth: 54 }}>
                          <div style={{ color: r.color, fontWeight: 800, fontSize: 22, lineHeight: 1 }}>{a.anomaly_score}</div>
                          <div style={{ color: C.textMuted, fontSize: 9, marginTop: 2 }}>score</div>
                        </div>
                        <div style={{ flex: 1 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 6 }}>
                            <span style={{ color: C.blue, fontFamily: 'monospace', fontSize: 13, fontWeight: 700 }}>{a.ip}</span>
                            <span style={pill(r.color, r.bg)}>{a.risk_level}</span>
                            <span style={{ color: C.textMuted, fontSize: 11 }}>{new Date(a.timestamp).toLocaleString()}</span>
                          </div>
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                            {anomTags.map(([t, detail]) => (
                              <div key={t} style={{ background: C.blueLight, border: `1px solid ${C.borderBlue}`, borderRadius: 4, padding: '3px 8px', display: 'flex', alignItems: 'center', gap: 5 }}>
                                <span style={{ color: C.blue, fontSize: 10, fontWeight: 700, textTransform: 'capitalize' }}>{t.replace(/_/g, ' ')}</span>
                                {detail?.deviation && <span style={{ color: C.textMuted, fontSize: 10 }}>±{detail.deviation}σ</span>}
                                {detail?.severity && (
                                  <span style={{ color: detail.severity === 'HIGH' ? C.critical : C.high, fontSize: 10, fontWeight: 700 }}>
                                    [{detail.severity}]
                                  </span>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })}
            </div>
          </Card>
        )}

        {/* ════ DETECTION ENGINE TAB ════ */}
        {activeTab === 'detection' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>

              <Card>
                <SHead icon={Cpu} title="Algorithm Specifications" />
                <div style={{ padding: 18 }}>
                  {[
                    ['Algorithm',        '3-Sigma Statistical Deviation (Z-score)'],
                    ['Detection rule',   'Z-score > 3.0 → Anomaly flagged'],
                    ['Learning window',  '5 minutes per IP (10 packet minimum)'],
                    ['Score range',      '0 – 100 (composite across all checks)'],
                    ['Update rate',      'Real-time, every packet'],
                    ['Persistence',      'Profiles saved to data/behavior_profiles.json'],
                    ['Endpoints',        '/behavior/statistics · /behavior/anomalies · /behavior/ip/{ip} · /behavior/top-anomalous-ips'],
                  ].map(([k, v]) => (
                    <div key={k} style={{ display: 'flex', gap: 12, padding: '9px 0', borderBottom: `1px solid ${C.border}` }}>
                      <span style={{ color: C.textMuted, fontSize: 12, minWidth: 130, flexShrink: 0 }}>{k}</span>
                      <span style={{ color: C.text, fontSize: 12, fontWeight: 600 }}>{v}</span>
                    </div>
                  ))}
                </div>
              </Card>

              <Card>
                <SHead icon={Lock} title="5 Monitored Behavioral Features" />
                <div style={{ padding: 18 }}>
                  {[
                    { name: 'Packet Size Anomaly',  desc: 'Detects unusually large/small packets vs per-IP mean ± σ', color: C.critical },
                    { name: 'Packet Rate Anomaly',  desc: 'Flags abnormal transmission speed (interval between packets)', color: C.high },
                    { name: 'Unusual Port Usage',   desc: 'Identifies access to ports outside normal usage pattern (>5% threshold)', color: C.medium },
                    { name: 'Protocol Deviation',   desc: 'Catches use of protocols not in baseline (>10% usage threshold)', color: C.blueMid },
                    { name: 'Temporal Anomaly',     desc: 'Flags activity outside normal active hours for that specific IP', color: C.low },
                  ].map(({ name, desc, color }) => (
                    <div key={name} style={{ display: 'flex', gap: 12, marginBottom: 14, paddingBottom: 14, borderBottom: `1px solid ${C.border}` }}>
                      <div style={{ width: 4, borderRadius: 4, background: color, flexShrink: 0 }} />
                      <div>
                        <div style={{ color: C.text, fontSize: 12, fontWeight: 700, marginBottom: 3 }}>{name}</div>
                        <div style={{ color: C.textMuted, fontSize: 11, lineHeight: 1.5 }}>{desc}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </Card>
            </div>

            {/* Flow diagram */}
            <Card>
              <SHead icon={Zap} title="Dual-Layer Detection Flow" />
              <div style={{ padding: 20, display: 'flex', alignItems: 'stretch', gap: 0 }}>
                {[
                  { label: 'Packet arrives',       icon: Radio,    color: C.textMuted, desc: 'Raw network packet captured from live traffic or simulation' },
                  { label: 'ML Model (XGBoost)',   icon: Brain,    color: C.blueMid,   desc: 'Known attack pattern matching\nNSL-KDD · 77.3% accuracy' },
                  { label: 'Behavioral engine',    icon: Activity, color: C.medium,    desc: '3σ deviation from\nper-IP learned baseline' },
                  { label: 'Combined decision',    icon: Zap,      color: C.high,      desc: 'Block if EITHER layer\ntriggers — catches zero-days' },
                  { label: 'Action taken',         icon: Lock,     color: C.low,       desc: 'Block IP · Alert admin\nLog event · Store profile' },
                ].map((step, i, arr) => (
                  <React.Fragment key={step.label}>
                    <div style={{ flex: 1, textAlign: 'center', padding: '0 6px' }}>
                      <div style={{ background: `${step.color}10`, border: `2px solid ${step.color}30`, borderRadius: 10, padding: '14px 8px' }}>
                        <div style={{ background: `${step.color}18`, borderRadius: '50%', width: 36, height: 36, display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 8px' }}>
                          <step.icon size={16} color={step.color} />
                        </div>
                        <div style={{ color: C.text, fontSize: 11, fontWeight: 700, marginBottom: 5 }}>{step.label}</div>
                        <div style={{ color: C.textMuted, fontSize: 10, lineHeight: 1.5, whiteSpace: 'pre-line' }}>{step.desc}</div>
                      </div>
                    </div>
                    {i < arr.length - 1 && (
                      <div style={{ display: 'flex', alignItems: 'center', color: C.borderBlue, fontSize: 20, fontWeight: 700, flexShrink: 0, paddingBottom: 20 }}>→</div>
                    )}
                  </React.Fragment>
                ))}
              </div>
            </Card>

            {/* Live API status check */}
            <Card>
              <SHead icon={Network} title="API Endpoint Status" sub="Verifying backend behavioral endpoints" />
              <div style={{ padding: 16, display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 10 }}>
                {[
                  { path: '/behavior/statistics',         label: 'Statistics',       data: stats ? `${stats.total_ips_tracked} IPs tracked` : null },
                  { path: '/behavior/top-anomalous-ips',  label: 'Top Anomalous IPs',data: `${topIPs.length} IPs returned` },
                  { path: '/behavior/anomalies',          label: 'Anomaly Events',   data: `${anomalies.length} events returned` },
                  { path: '/behavior/ip/{ip_address}',    label: 'IP Profile Detail',data: activeIP ? `Last: ${activeIP}` : 'Click an IP to test' },
                ].map(({ path, label, data }) => (
                  <div key={path} style={{ display: 'flex', alignItems: 'center', gap: 10, background: C.surfaceAlt, borderRadius: 8, padding: '10px 14px', border: `1px solid ${C.border}` }}>
                    <div style={{ width: 8, height: 8, borderRadius: '50%', background: connected ? C.low : C.critical, flexShrink: 0, boxShadow: connected ? `0 0 5px ${C.low}` : 'none' }} />
                    <div style={{ flex: 1 }}>
                      <div style={{ color: C.text, fontSize: 12, fontWeight: 700 }}>{label}</div>
                      <div style={{ color: C.textMuted, fontSize: 10, fontFamily: 'monospace', marginTop: 1 }}>GET {path}</div>
                    </div>
                    {data && <span style={{ color: C.low, fontSize: 10, fontWeight: 600 }}>{data}</span>}
                  </div>
                ))}
              </div>
            </Card>
          </div>
        )}

      </div>
    </div>
  );
}
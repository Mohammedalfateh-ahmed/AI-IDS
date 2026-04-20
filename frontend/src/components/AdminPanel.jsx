import { useState, useEffect } from 'react';
import { getAllUsers, registerUser, deleteUser, updateUser } from '../services/api';

export default function AdminPanel({ onClose }) {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showAddUser, setShowAddUser] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [newUser, setNewUser] = useState({ username: '', password: '', role: 'user', email: '' });
  const [editingUser, setEditingUser] = useState(null);
  const [editForm, setEditForm] = useState({ email: '', role: '' });

  useEffect(() => { fetchUsers(); }, []);

  const fetchUsers = async () => {
    try {
      const data = await getAllUsers();
      setUsers(data);
      setLoading(false);
    } catch {
      setError('Failed to load users');
      setLoading(false);
    }
  };

  const handleAddUser = async (e) => {
    e.preventDefault();
    setError(''); setSuccess('');
    try {
      await registerUser(newUser);
      setSuccess(`Agent "${newUser.username}" registered.`);
      setNewUser({ username: '', password: '', role: 'user', email: '' });
      setShowAddUser(false);
      fetchUsers();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to create user');
    }
  };

  const handleDeleteUser = async (username) => {
    if (!window.confirm(`Remove agent "${username}"?`)) return;
    try {
      await deleteUser(username);
      setSuccess(`Agent "${username}" removed.`);
      fetchUsers();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to delete user');
    }
  };

  const handleEditUser = (u) => {
    setEditingUser(u.username);
    setEditForm({ email: u.email || '', role: u.role });
  };

  const handleSaveEdit = async () => {
    setError(''); setSuccess('');
    try {
      await updateUser(editingUser, editForm);
      setSuccess(`User "${editingUser}" updated.`);
      setEditingUser(null);
      fetchUsers();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to update user');
    }
  };

  const mono = 'var(--font-mono)';

  return (
    <div style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.80)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      zIndex: 50, padding: '1rem'
    }}>
      <div style={{
        background: '#0d1117', border: '1px solid #21262d',
        borderRadius: '10px', width: '100%', maxWidth: '900px',
        maxHeight: '90vh', overflow: 'hidden', fontFamily: mono
      }}>

        {/* ── Header ── */}
        <div style={{
          background: '#161b22', borderBottom: '1px solid #21262d',
          padding: '12px 20px', display: 'flex', alignItems: 'center', justifyContent: 'space-between'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{
              width: '32px', height: '32px', background: '#1f6feb18',
              border: '1px solid #1f6feb44', borderRadius: '6px',
              display: 'flex', alignItems: 'center', justifyContent: 'center'
            }}>
              <svg width="16" height="16" fill="none" stroke="#58a6ff" strokeWidth="1.5" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"/>
              </svg>
            </div>
            <div>
              <div style={{ fontSize: '13px', fontWeight: 500, color: '#e6edf3' }}>User Management</div>
              <div style={{ fontSize: '10px', color: '#484f58' }}>wazuh &gt; administration &gt; users</div>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{
              fontSize: '10px', color: '#3fb950', background: '#3fb95011',
              border: '1px solid #3fb95033', padding: '2px 8px', borderRadius: '20px'
            }}>
              ● {users.length} agents
            </span>
            <button onClick={onClose} style={{
              width: '26px', height: '26px', background: 'transparent',
              border: '1px solid #30363d', borderRadius: '5px',
              color: '#7d8590', cursor: 'pointer', fontSize: '13px',
              display: 'flex', alignItems: 'center', justifyContent: 'center'
            }}>✕</button>
          </div>
        </div>

        {/* ── Body ── */}
        <div style={{ padding: '14px 20px', overflowY: 'auto', maxHeight: 'calc(90vh - 110px)' }}>

          {/* Alerts */}
          {error && (
            <div style={{
              marginBottom: '10px', padding: '8px 12px',
              background: '#da363310', border: '1px solid #da363340',
              borderLeft: '3px solid #da3633', borderRadius: '4px',
              fontSize: '11px', color: '#f85149', fontFamily: mono
            }}>
              ✗ {error}
            </div>
          )}
          {success && (
            <div style={{
              marginBottom: '10px', padding: '8px 12px',
              background: '#23863610', border: '1px solid #23863640',
              borderLeft: '3px solid #238636', borderRadius: '4px',
              fontSize: '11px', color: '#3fb950', fontFamily: mono
            }}>
              ✓ {success}
            </div>
          )}

          {/* Toolbar */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              {!showAddUser && (
                <button onClick={() => setShowAddUser(true)} style={{
                  background: '#238636', border: '1px solid #2ea043',
                  color: '#fff', fontSize: '11px', fontWeight: 500,
                  padding: '5px 12px', borderRadius: '5px', cursor: 'pointer',
                  display: 'flex', alignItems: 'center', gap: '5px', fontFamily: mono
                }}>
                  <span style={{ fontSize: '14px', lineHeight: 1 }}>+</span> Add agent
                </button>
              )}
            </div>
            <div style={{ fontSize: '10px', color: '#484f58' }}>
              last updated: {new Date().toLocaleTimeString()}
            </div>
          </div>

          {/* Add User Form */}
          {showAddUser && (
            <div style={{
              background: '#161b22', border: '1px solid #30363d',
              borderLeft: '3px solid #1f6feb', borderRadius: '6px',
              padding: '14px', marginBottom: '14px'
            }}>
              <div style={{ fontSize: '10px', color: '#58a6ff', marginBottom: '12px', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                ── new agent registration
              </div>
              <form onSubmit={handleAddUser}>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginBottom: '10px' }}>
                  {[
                    { label: 'Username', key: 'username', type: 'text', placeholder: 'agent_username' },
                    { label: 'Password', key: 'password', type: 'password', placeholder: '••••••••' },
                    { label: 'Email (optional)', key: 'email', type: 'email', placeholder: 'user@domain.com' }
                  ].map(({ label, key, type, placeholder }) => (
                    <div key={key}>
                      <div style={{ fontSize: '10px', color: '#7d8590', marginBottom: '4px', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{label}</div>
                      <input
                        type={type}
                        value={newUser[key]}
                        onChange={e => setNewUser({ ...newUser, [key]: e.target.value })}
                        placeholder={placeholder}
                        required={key !== 'email'}
                        style={{
                          width: '100%', background: '#0d1117', border: '1px solid #30363d',
                          borderRadius: '4px', color: '#e6edf3', fontSize: '11px',
                          padding: '6px 10px', fontFamily: mono, boxSizing: 'border-box',
                          outline: 'none'
                        }}
                      />
                    </div>
                  ))}
                  <div>
                    <div style={{ fontSize: '10px', color: '#7d8590', marginBottom: '4px', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Role</div>
                    <select
                      value={newUser.role}
                      onChange={e => setNewUser({ ...newUser, role: e.target.value })}
                      style={{
                        width: '100%', background: '#0d1117', border: '1px solid #30363d',
                        borderRadius: '4px', color: '#e6edf3', fontSize: '11px',
                        padding: '6px 10px', fontFamily: mono, boxSizing: 'border-box'
                      }}
                    >
                      <option value="user">user — read only</option>
                      <option value="admin">admin — full access</option>
                    </select>
                  </div>
                </div>
                <div style={{ display: 'flex', gap: '6px' }}>
                  <button type="submit" style={{
                    background: '#238636', border: '1px solid #2ea043', color: '#fff',
                    fontSize: '11px', padding: '5px 14px', borderRadius: '4px',
                    cursor: 'pointer', fontFamily: mono
                  }}>Register</button>
                  <button type="button" onClick={() => { setShowAddUser(false); setNewUser({ username: '', password: '', role: 'user', email: '' }); }} style={{
                    background: 'transparent', border: '1px solid #30363d', color: '#7d8590',
                    fontSize: '11px', padding: '5px 14px', borderRadius: '4px',
                    cursor: 'pointer', fontFamily: mono
                  }}>Cancel</button>
                </div>
              </form>
            </div>
          )}

          {/* Table */}
          <div style={{ border: '1px solid #21262d', borderRadius: '6px', overflow: 'hidden' }}>

            {/* Table header bar */}
            <div style={{
              background: '#161b22', borderBottom: '1px solid #21262d',
              padding: '6px 14px', display: 'flex', alignItems: 'center', gap: '6px'
            }}>
              <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#3fb950', display: 'inline-block' }}/>
              <span style={{ fontSize: '10px', color: '#7d8590', letterSpacing: '0.06em', textTransform: 'uppercase' }}>
                agent registry
              </span>
            </div>

            {loading ? (
              <div style={{ padding: '30px', textAlign: 'center', fontSize: '11px', color: '#484f58', fontFamily: mono }}>
                loading agents...
              </div>
            ) : (
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '11px' }}>
                <thead>
                  <tr style={{ background: '#0d1117' }}>
                    {['Agent ID', 'Email', 'Role', 'Alert Status', 'Last login', 'Actions'].map(h => (
                      <th key={h} style={{
                        padding: '7px 14px', textAlign: 'left', fontSize: '9px',
                        fontWeight: 500, color: '#484f58', textTransform: 'uppercase',
                        letterSpacing: '0.08em', borderBottom: '1px solid #21262d',
                        fontFamily: mono
                      }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {users.map((u, i) => (
                    <tr key={u.username} style={{
                      borderBottom: i < users.length - 1 ? '1px solid #161b22' : 'none',
                      background: editingUser === u.username ? '#1f6feb08' : 'transparent'
                    }}>

                      {/* Agent */}
                      <td style={{ padding: '10px 14px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <div style={{
                            width: '26px', height: '26px', borderRadius: '50%',
                            background: u.role === 'admin' ? '#6e40c918' : '#1f6feb12',
                            border: `1px solid ${u.role === 'admin' ? '#6e40c955' : '#1f6feb33'}`,
                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                            fontSize: '10px', fontWeight: 500,
                            color: u.role === 'admin' ? '#a371f7' : '#58a6ff'
                          }}>
                            {u.username.charAt(0).toUpperCase()}
                          </div>
                          <div>
                            <div style={{ color: '#e6edf3', fontWeight: 500, fontSize: '11px' }}>{u.username}</div>
                            <div style={{ fontSize: '9px', color: '#484f58' }}>#{String(i + 1).padStart(3, '0')}</div>
                          </div>
                        </div>
                      </td>

                      {/* Email */}
                      <td style={{ padding: '10px 14px', fontSize: '11px' }}>
                        {u.email
                          ? <span style={{ color: '#58a6ff' }}>{u.email}</span>
                          : <span style={{ color: '#30363d' }}>—</span>
                        }
                      </td>

                      {/* Role */}
                      <td style={{ padding: '10px 14px' }}>
                        <span style={{
                          background: u.role === 'admin' ? '#6e40c912' : '#1f6feb10',
                          border: `1px solid ${u.role === 'admin' ? '#6e40c966' : '#1f6feb44'}`,
                          color: u.role === 'admin' ? '#a371f7' : '#58a6ff',
                          fontSize: '9px', fontWeight: 500, padding: '2px 7px',
                          borderRadius: '20px', letterSpacing: '0.04em'
                        }}>
                          {u.role}
                        </span>
                      </td>

                      {/* Alert Status */}
                      <td style={{ padding: '10px 14px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                          <span style={{
                            width: '5px', height: '5px', borderRadius: '50%',
                            background: u.email ? '#3fb950' : '#30363d',
                            display: 'inline-block'
                          }}/>
                          <span style={{ fontSize: '10px', color: u.email ? '#3fb950' : '#484f58' }}>
                            {u.email ? 'subscribed' : 'no alerts'}
                          </span>
                        </div>
                      </td>

                      {/* Last Login */}
                      <td style={{ padding: '10px 14px', fontSize: '10px', color: '#7d8590' }}>
                        {u.last_login ? new Date(u.last_login).toLocaleString() : '—'}
                      </td>

                      {/* Actions */}
                      <td style={{ padding: '10px 14px' }}>
                        {u.username === 'admin' ? (
                          <span style={{ fontSize: '9px', color: '#30363d', letterSpacing: '0.05em' }}>PROTECTED</span>
                        ) : editingUser === u.username ? (
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '5px', minWidth: '180px' }}>
                            <input
                              type="email"
                              value={editForm.email}
                              onChange={e => setEditForm({ ...editForm, email: e.target.value })}
                              placeholder="email@domain.com"
                              style={{
                                background: '#0d1117', border: '1px solid #1f6feb55',
                                borderRadius: '3px', color: '#e6edf3', fontSize: '10px',
                                padding: '4px 8px', fontFamily: mono, width: '100%', boxSizing: 'border-box'
                              }}
                            />
                            <select
                              value={editForm.role}
                              onChange={e => setEditForm({ ...editForm, role: e.target.value })}
                              style={{
                                background: '#0d1117', border: '1px solid #30363d',
                                borderRadius: '3px', color: '#e6edf3', fontSize: '10px',
                                padding: '4px 8px', fontFamily: mono, width: '100%', boxSizing: 'border-box'
                              }}
                            >
                              <option value="user">user</option>
                              <option value="admin">admin</option>
                            </select>
                            <div style={{ display: 'flex', gap: '4px' }}>
                              <button onClick={handleSaveEdit} style={{
                                background: '#238636', border: '1px solid #2ea043',
                                color: '#fff', fontSize: '10px', padding: '3px 8px',
                                borderRadius: '3px', cursor: 'pointer', fontFamily: mono
                              }}>Save</button>
                              <button onClick={() => setEditingUser(null)} style={{
                                background: 'transparent', border: '1px solid #30363d',
                                color: '#7d8590', fontSize: '10px', padding: '3px 8px',
                                borderRadius: '3px', cursor: 'pointer', fontFamily: mono
                              }}>Cancel</button>
                            </div>
                          </div>
                        ) : (
                          <div style={{ display: 'flex', gap: '5px' }}>
                            <button onClick={() => handleEditUser(u)} style={{
                              background: 'transparent', border: '1px solid #1f6feb33',
                              color: '#58a6ff', fontSize: '9px', fontWeight: 500,
                              padding: '3px 9px', borderRadius: '3px', cursor: 'pointer',
                              fontFamily: mono, letterSpacing: '0.04em'
                            }}>EDIT</button>
                            <button onClick={() => handleDeleteUser(u.username)} style={{
                              background: 'transparent', border: '1px solid #da363344',
                              color: '#f85149', fontSize: '9px', fontWeight: 500,
                              padding: '3px 9px', borderRadius: '3px', cursor: 'pointer',
                              fontFamily: mono, letterSpacing: '0.04em'
                            }}>REMOVE</button>
                          </div>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* ── Footer ── */}
        <div style={{
          background: '#161b22', borderTop: '1px solid #21262d',
          padding: '8px 20px', display: 'flex', alignItems: 'center', justifyContent: 'space-between'
        }}>
          <span style={{ fontSize: '9px', color: '#30363d', letterSpacing: '0.05em' }}>
            ● MONITORING AGENTS HAVE READ-ONLY ACCESS
          </span>
          <button onClick={onClose} style={{
            background: 'transparent', border: '1px solid #30363d',
            color: '#7d8590', fontSize: '10px', padding: '4px 12px',
            borderRadius: '4px', cursor: 'pointer', fontFamily: mono
          }}>
            Close
          </button>
        </div>

      </div>
    </div>
  );
}
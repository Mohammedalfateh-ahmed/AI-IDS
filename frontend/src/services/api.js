import axios from 'axios';

const API_BASE_URL = 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      window.location.href = '/';
    }
    return Promise.reject(error);
  }
);

export const login = async (username, password) => {
  const response = await axios.post(`${API_BASE_URL}/auth/login`, {
    username,
    password
  });
  return response.data;
};

export const getCurrentUser = async () => {
  const response = await api.get('/auth/me');
  return response.data;
};

export const getAllUsers = async () => {
  const response = await api.get('/users');
  return response.data;
};

export const registerUser = async (userData) => {
  const response = await api.post('/users', userData);
  return response.data;
};

export const deleteUser = async (username) => {
  const response = await api.delete(`/users/${username}`);
  return response.data;
};
export const updateUser = async (username, userData) => {
  const response = await api.patch(`/users/${username}`, userData);
  return response.data;
};

export const getStats = async () => {
  const response = await api.get('/stats');
  return response.data;
};

export const getAlerts = async (limit = 100) => {
  const response = await api.get(`/alerts?limit=${limit}`);
  return response.data;
};

export const getModelInfo = async () => {
  const response = await api.get('/model/info');
  return response.data;
};

export const simulateAttack = async (attackType) => {
  const response = await api.post(`/simulate?attack_type=${attackType}`);
  return response.data;
};

export const clearAlerts = async () => {
  const response = await api.post('/alerts/clear');
  return response.data;
};

export const getCaptureStatus = async () => {
  const response = await api.get('/capture/stats');
  return response.data;
};

export const startCapture = async () => {
  const response = await api.post('/capture/start');
  return response.data;
};

export const stopCapture = async () => {
  const response = await api.post('/capture/stop');
  return response.data;
};

export const logout = () => {
  localStorage.removeItem('token');
  localStorage.removeItem('user');
};

export const isAuthenticated = () => {
  return !!localStorage.getItem('token');
};

export const getStoredUser = () => {
  const userStr = localStorage.getItem('user');
  return userStr ? JSON.parse(userStr) : null;
};

export const getLogs = async (limit = 50) => {
  const response = await api.get(`/logs?limit=${limit}`);
  return response.data;
};
export default api; 

import { useState, useEffect } from 'react';
import axios from 'axios';

export default function AttackPrediction() {
  const [prediction, setPrediction] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchPrediction();
    const interval = setInterval(fetchPrediction, 30000);
    return () => clearInterval(interval);
  }, []);

  const fetchPrediction = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('http://localhost:8000/attack-prediction', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setPrediction(response.data);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching prediction:', error);
      setLoading(false);
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
        <h2 className="text-lg font-bold text-gray-800 flex items-center space-x-2">
          <svg className="w-5 h-5 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
          <span>Threat Prediction</span>
        </h2>
      </div>

      <div className="p-6">
        {prediction && prediction.prediction ? (
          <div className="space-y-4">
            <div className="p-4 bg-red-50 border-2 border-red-200 rounded-lg">
              <div className="mb-3">
                <span className="text-xs text-red-600 font-medium uppercase">Prediction</span>
                <div className="text-sm text-red-700 mt-1">{prediction.prediction}</div>
              </div>

              {prediction.next_likely_attack && (
                <div className="mb-3">
                  <span className="text-xs text-red-600 font-medium uppercase">Next Likely Attack</span>
                  <div className="text-lg font-bold text-red-900">{prediction.next_likely_attack}</div>
                </div>
              )}

              <div className="grid grid-cols-2 gap-3 text-sm">
                <div>
                  <span className="text-red-600">Confidence</span>
                  <div className="font-bold text-red-900">{(prediction.confidence * 100).toFixed(1)}%</div>
                </div>
                <div>
                  <span className="text-red-600">Time Window</span>
                  <div className="font-bold text-red-900">{prediction.time_window}</div>
                </div>
              </div>

              {prediction.patterns && prediction.patterns.length > 0 && (
                <div className="mt-3 pt-3 border-t border-red-200">
                  <span className="text-xs text-red-600 font-medium">Pattern Analysis</span>
                  <div className="mt-2 space-y-1">
                    {prediction.patterns.map((pattern, idx) => (
                      <div key={idx} className="text-xs text-red-700">• {pattern}</div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {prediction.threat_info && (
              <div className="p-4 bg-orange-50 border border-orange-200 rounded-lg">
                <div className="text-xs text-orange-600 font-medium mb-2">Threat Information</div>
                <div className="space-y-2 text-sm text-orange-700">
                  <div><span className="font-medium">Name:</span> {prediction.threat_info.name}</div>
                  <div><span className="font-medium">Category:</span> {prediction.threat_info.category}</div>
                  <div>
                    <span className={`inline-block px-2 py-1 rounded text-xs font-bold ${
                      prediction.threat_info.severity === 'CRITICAL' ? 'bg-red-200 text-red-800' :
                      prediction.threat_info.severity === 'HIGH' ? 'bg-orange-200 text-orange-800' :
                      'bg-yellow-200 text-yellow-800'
                    }`}>
                      {prediction.threat_info.severity}
                    </span>
                  </div>
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="text-center py-8 text-gray-500">
            <svg className="w-12 h-12 text-gray-300 mx-auto mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
            </svg>
            <p className="text-sm font-medium">Insufficient Data</p>
            <p className="text-xs mt-1">Need more alerts for prediction analysis</p>
          </div>
        )}
      </div>
    </div>
  );
}
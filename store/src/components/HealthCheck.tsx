import React, { useState, useEffect } from 'react';
import { Shield, Server, CheckCircle, XCircle, AlertCircle, RefreshCw } from 'lucide-react';

interface ServiceStatus {
  name: string;
  url: string;
  description: string;
  enabled: boolean;
  status: 'pending' | 'success' | 'error' | 'timeout' | 'disabled';
  response?: any;
  error?: string;
  latency?: number;
}

const SERVICES = [
  {
    name: 'Ultra Inventory System',
    url: '/api/health',
    description: 'Backend API - Categories, Products & Collections',
    enabled: true
  },
  {
    name: 'Payment Gateway',
    url: window.location.protocol + '//' + window.location.hostname + ':8080/health',
    description: 'Quantum-resistant Payment Processing',
    enabled: true
  },
  {
    name: 'Security Service',
    url: window.location.protocol + '//' + window.location.hostname + ':8000/health',
    description: 'FIPS 140-3 Security & Audit Trail',
    enabled: true
  },
  {
    name: 'Ultra Shipping Service',
    url: window.location.protocol + '//' + window.location.hostname + ':6800/health',
    description: 'Ultra Shipping with AI Optimization',
    enabled: true
  },
  {
    name: 'Advanced Analytics',
    url: window.location.protocol + '//' + window.location.hostname + '/health',
    description: 'AI/ML Analytics & Fraud Detection',
    enabled: true
  },
  {
    name: 'API Gateway',
    url: '',
    description: 'Enterprise API Gateway (Not Running)',
    enabled: false
  },
  {
    name: 'Auth Service',
    url: '',
    description: 'WebAuthn & DID Authentication (Not Running)',
    enabled: false
  }
];

export default function HealthCheck() {
  const [services, setServices] = useState<ServiceStatus[]>(
    SERVICES.map(s => ({ ...s, status: 'pending' as const }))
  );
  const [isChecking, setIsChecking] = useState(false);
  const [wsStatus, setWsStatus] = useState<'pending' | 'connected' | 'error'>('pending');

  const checkService = async (service: typeof SERVICES[0]): Promise<ServiceStatus> => {
    if (!service.enabled) {
      return {
        ...service,
        status: 'disabled',
        error: 'Service not running'
      };
    }

    const startTime = Date.now();
    
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000);
      
      const response = await fetch(service.url, {
        method: 'GET',
        signal: controller.signal,
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        },
      });
      
      clearTimeout(timeoutId);
      const latency = Date.now() - startTime;
      
      if (response.ok) {
        const data = await response.json().catch(() => ({ status: 'ok' }));
        return {
          ...service,
          status: 'success',
          response: data,
          latency
        };
      } else {
        return {
          ...service,
          status: 'error',
          error: `HTTP ${response.status}: ${response.statusText}`,
          latency
        };
      }
    } catch (error: any) {
      const latency = Date.now() - startTime;
      return {
        ...service,
        status: error.name === 'AbortError' ? 'timeout' : 'error',
        error: error.name === 'AbortError' ? 'Request timeout' : error.message,
        latency
      };
    }
  };

  const checkWebSocket = () => {
    setWsStatus('error');
  };

  const runHealthCheck = async () => {
    setIsChecking(true);
    setWsStatus('pending');
    
    // Reset all services to pending
    setServices(services => services.map(s => ({ ...s, status: 'pending' as const })));
    
    // Check WebSocket connection
    checkWebSocket();
    
    // Check all services in parallel
    const promises = SERVICES.map(checkService);
    const results = await Promise.all(promises);
    
    setServices(results);
    setIsChecking(false);
  };

  useEffect(() => {
    runHealthCheck();
  }, []);

  const getStatusIcon = (status: ServiceStatus['status']) => {
    switch (status) {
      case 'success':
        return <CheckCircle className="w-5 h-5 text-green-500" />;
      case 'error':
        return <XCircle className="w-5 h-5 text-red-500" />;
      case 'timeout':
        return <AlertCircle className="w-5 h-5 text-orange-500" />;
      case 'disabled':
        return <AlertCircle className="w-5 h-5 text-gray-400" />;
      default:
        return <RefreshCw className="w-5 h-5 text-gray-400 animate-spin" />;
    }
  };

  const getWsStatusIcon = () => {
    switch (wsStatus) {
      case 'connected':
        return <CheckCircle className="w-5 h-5 text-green-500" />;
      case 'error':
        return <XCircle className="w-5 h-5 text-red-500" />;
      default:
        return <RefreshCw className="w-5 h-5 text-gray-400 animate-spin" />;
    }
  };

  const successCount = services.filter(s => s.status === 'success').length;
  const totalCount = services.length;

  return (
    <div className="max-w-4xl mx-auto p-6 bg-white rounded-lg shadow-lg">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-3">
          <Shield className="w-8 h-8 text-blue-600" />
          <div>
            <h2 className="text-2xl font-bold text-gray-900">Ultra Professional Backend Status</h2>
            <p className="text-gray-600">Enterprise-grade microservices health check</p>
          </div>
        </div>
        <button
          onClick={runHealthCheck}
          disabled={isChecking}
          className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${isChecking ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      <div className="grid gap-4 mb-6">
        <div className="bg-gray-50 rounded-lg p-4">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold text-gray-900">System Overview</h3>
            <div className="text-sm text-gray-600">
              {successCount}/{totalCount} services healthy
            </div>
          </div>
          <div className="mt-2 bg-gray-200 rounded-full h-2">
            <div 
              className="bg-green-500 h-2 rounded-full transition-all duration-300"
              style={{ width: `${(successCount / totalCount) * 100}%` }}
            />
          </div>
        </div>

        {/* WebSocket Status */}
        <div className="bg-gray-50 rounded-lg p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              {getWsStatusIcon()}
              <div>
                <h4 className="font-medium text-gray-900">WebSocket Connection</h4>
                <p className="text-sm text-gray-600">Real-time updates</p>
              </div>
            </div>
            <div className="text-sm font-medium">
              {wsStatus === 'connected' ? 'Connected' : wsStatus === 'error' ? 'Failed' : 'Connecting...'}
            </div>
          </div>
        </div>
      </div>

      <div className="grid gap-4">
        {services.map((service) => (
          <div key={service.name} className="bg-gray-50 rounded-lg p-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                {getStatusIcon(service.status)}
                <div>
                  <h4 className="font-medium text-gray-900">{service.name}</h4>
                  <p className="text-sm text-gray-600">{service.description}</p>
                </div>
              </div>
              <div className="text-right">
                <div className="text-sm font-medium">
                  {service.status === 'success' ? 'Healthy' : 
                   service.status === 'error' ? 'Error' :
                   service.status === 'timeout' ? 'Timeout' : 'Checking...'}
                </div>
                {service.latency && (
                  <div className="text-xs text-gray-500">{service.latency}ms</div>
                )}
              </div>
            </div>
            
            {service.error && (
              <div className="mt-2 text-sm text-red-600 bg-red-50 p-2 rounded">
                {service.error}
              </div>
            )}
            
            {service.response && service.status === 'success' && (
              <div className="mt-2 text-xs text-gray-500 bg-green-50 p-2 rounded">
                <pre>{JSON.stringify(service.response, null, 2)}</pre>
              </div>
            )}
          </div>
        ))}
      </div>

      <div className="mt-6 text-center text-sm text-gray-500">
        <p>🔐 FIPS 140-3 Level 3 • ⚛️ Quantum-Resistant • 🤖 AI/ML Enhanced</p>
      </div>
    </div>
  );
}
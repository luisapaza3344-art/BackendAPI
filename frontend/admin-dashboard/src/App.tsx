import React, { useState, useEffect } from 'react';
import { Shield, Activity, DollarSign, Users, AlertTriangle, CheckCircle, Settings, BarChart3 } from 'lucide-react';
import './App.css';

interface SystemMetrics {
  paymentGateway: {
    status: string;
    requestsPerSecond: number;
    errorRate: number;
    fipsCompliance: boolean;
  };
  securityService: {
    status: string;
    hsmOperations: number;
    blockchainAnchors: number;
    auditRecords: number;
  };
  fraudDetection: {
    riskScore: number;
    blockedTransactions: number;
    falsePositives: number;
  };
  compliance: {
    fipsLevel: string;
    pciDss: string;
    quantumResistant: boolean;
  };
}

const EnterpriseAdminDashboard: React.FC = () => {
  const [metrics, setMetrics] = useState<SystemMetrics>({
    paymentGateway: {
      status: 'healthy',
      requestsPerSecond: 847.3,
      errorRate: 0.02,
      fipsCompliance: true
    },
    securityService: {
      status: 'healthy',
      hsmOperations: 1234,
      blockchainAnchors: 45,
      auditRecords: 8921
    },
    fraudDetection: {
      riskScore: 23.5,
      blockedTransactions: 12,
      falsePositives: 2
    },
    compliance: {
      fipsLevel: 'FIPS 140-3 Level 3',
      pciDss: 'PCI-DSS Level 1',
      quantumResistant: true
    }
  });

  const [activeTab, setActiveTab] = useState<string>('overview');
  const [isLoading, setIsLoading] = useState<boolean>(false);

  useEffect(() => {
    // Simulate real-time data updates
    const interval = setInterval(() => {
      setMetrics(prev => ({
        ...prev,
        paymentGateway: {
          ...prev.paymentGateway,
          requestsPerSecond: prev.paymentGateway.requestsPerSecond + (Math.random() - 0.5) * 20,
          errorRate: Math.max(0, prev.paymentGateway.errorRate + (Math.random() - 0.5) * 0.01)
        },
        securityService: {
          ...prev.securityService,
          hsmOperations: prev.securityService.hsmOperations + Math.floor(Math.random() * 5),
          auditRecords: prev.securityService.auditRecords + Math.floor(Math.random() * 3)
        }
      }));
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  const StatusBadge: React.FC<{ status: string }> = ({ status }) => (
    <span className={`px-3 py-1 rounded-full text-sm font-medium ${
      status === 'healthy' 
        ? 'bg-green-100 text-green-800 border border-green-200' 
        : 'bg-red-100 text-red-800 border border-red-200'
    }`}>
      {status === 'healthy' ? (
        <>
          <CheckCircle className="inline w-4 h-4 mr-1" />
          Healthy
        </>
      ) : (
        <>
          <AlertTriangle className="inline w-4 h-4 mr-1" />
          Degraded
        </>
      )}
    </span>
  );

  const MetricCard: React.FC<{
    title: string;
    value: string | number;
    subtitle?: string;
    icon: React.ReactNode;
    trend?: 'up' | 'down' | 'stable';
    color?: 'blue' | 'green' | 'red' | 'purple';
  }> = ({ title, value, subtitle, icon, trend, color = 'blue' }) => (
    <div className={`bg-white rounded-xl shadow-sm border border-gray-200 p-6 hover:shadow-md transition-shadow`}>
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-gray-600">{title}</p>
          <p className="text-3xl font-bold text-gray-900 mt-2">{value}</p>
          {subtitle && <p className="text-sm text-gray-500 mt-1">{subtitle}</p>}
        </div>
        <div className={`p-3 rounded-full ${
          color === 'blue' ? 'bg-blue-50 text-blue-600' :
          color === 'green' ? 'bg-green-50 text-green-600' :
          color === 'red' ? 'bg-red-50 text-red-600' :
          'bg-purple-50 text-purple-600'
        }`}>
          {icon}
        </div>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center">
              <Shield className="h-8 w-8 text-blue-600 mr-3" />
              <div>
                <h1 className="text-2xl font-bold text-gray-900">Enterprise Payment Gateway</h1>
                <p className="text-sm text-gray-500">FIPS 140-3 Level 3 Compliance Dashboard</p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <div className="flex items-center bg-green-50 px-3 py-2 rounded-lg">
                <div className="w-2 h-2 bg-green-500 rounded-full mr-2"></div>
                <span className="text-sm font-medium text-green-700">All Systems Operational</span>
              </div>
              <button className="p-2 text-gray-400 hover:text-gray-500 rounded-lg hover:bg-gray-100">
                <Settings className="h-5 w-5" />
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Navigation Tabs */}
      <nav className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex space-x-8 mt-6">
          {[
            { id: 'overview', label: 'System Overview', icon: Activity },
            { id: 'payments', label: 'Payment Processing', icon: DollarSign },
            { id: 'security', label: 'Security & Compliance', icon: Shield },
            { id: 'analytics', label: 'Analytics', icon: BarChart3 },
            { id: 'users', label: 'User Management', icon: Users }
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center px-4 py-2 rounded-lg font-medium text-sm transition-colors ${
                activeTab === tab.id
                  ? 'bg-blue-100 text-blue-700 border border-blue-200'
                  : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
              }`}
            >
              <tab.icon className="h-4 w-4 mr-2" />
              {tab.label}
            </button>
          ))}
        </div>
      </nav>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* Key Metrics Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <MetricCard
                title="Payment Requests"
                value={`${metrics.paymentGateway.requestsPerSecond.toFixed(1)}`}
                subtitle="per second"
                icon={<DollarSign className="h-6 w-6" />}
                color="green"
              />
              <MetricCard
                title="Error Rate"
                value={`${(metrics.paymentGateway.errorRate * 100).toFixed(3)}%`}
                subtitle="Last 24 hours"
                icon={<AlertTriangle className="h-6 w-6" />}
                color="red"
              />
              <MetricCard
                title="HSM Operations"
                value={metrics.securityService.hsmOperations.toLocaleString()}
                subtitle="ECDSA P-384 signatures"
                icon={<Shield className="h-6 w-6" />}
                color="blue"
              />
              <MetricCard
                title="Audit Records"
                value={metrics.securityService.auditRecords.toLocaleString()}
                subtitle="Blockchain anchored"
                icon={<CheckCircle className="h-6 w-6" />}
                color="purple"
              />
            </div>

            {/* Service Status */}
            <div className="bg-white rounded-xl shadow-sm border border-gray-200">
              <div className="px-6 py-4 border-b border-gray-200">
                <h2 className="text-lg font-semibold text-gray-900">Enterprise Services Status</h2>
              </div>
              <div className="p-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-4">
                    <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                      <div className="flex items-center">
                        <DollarSign className="h-5 w-5 text-blue-600 mr-3" />
                        <span className="font-medium">Payment Gateway</span>
                      </div>
                      <StatusBadge status={metrics.paymentGateway.status} />
                    </div>
                    <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                      <div className="flex items-center">
                        <Shield className="h-5 w-5 text-green-600 mr-3" />
                        <span className="font-medium">Security Service</span>
                      </div>
                      <StatusBadge status={metrics.securityService.status} />
                    </div>
                  </div>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                      <div className="flex items-center">
                        <Users className="h-5 w-5 text-purple-600 mr-3" />
                        <span className="font-medium">Authentication Service</span>
                      </div>
                      <StatusBadge status="healthy" />
                    </div>
                    <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                      <div className="flex items-center">
                        <Activity className="h-5 w-5 text-orange-600 mr-3" />
                        <span className="font-medium">Crypto Attestation Agent</span>
                      </div>
                      <StatusBadge status="healthy" />
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Compliance Status */}
            <div className="bg-white rounded-xl shadow-sm border border-gray-200">
              <div className="px-6 py-4 border-b border-gray-200">
                <h2 className="text-lg font-semibold text-gray-900">Enterprise Compliance Status</h2>
              </div>
              <div className="p-6">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  <div className="text-center p-4 bg-green-50 rounded-lg border border-green-200">
                    <CheckCircle className="h-8 w-8 text-green-600 mx-auto mb-2" />
                    <p className="font-semibold text-green-900">{metrics.compliance.fipsLevel}</p>
                    <p className="text-sm text-green-700">Hardware Security Module</p>
                  </div>
                  <div className="text-center p-4 bg-blue-50 rounded-lg border border-blue-200">
                    <Shield className="h-8 w-8 text-blue-600 mx-auto mb-2" />
                    <p className="font-semibold text-blue-900">{metrics.compliance.pciDss}</p>
                    <p className="text-sm text-blue-700">Payment Card Security</p>
                  </div>
                  <div className="text-center p-4 bg-purple-50 rounded-lg border border-purple-200">
                    <Activity className="h-8 w-8 text-purple-600 mx-auto mb-2" />
                    <p className="font-semibold text-purple-900">Quantum Resistant</p>
                    <p className="text-sm text-purple-700">Post-Quantum Cryptography</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'payments' && (
          <div className="bg-white rounded-xl shadow-sm border border-gray-200">
            <div className="px-6 py-4 border-b border-gray-200">
              <h2 className="text-lg font-semibold text-gray-900">Payment Processing Management</h2>
            </div>
            <div className="p-6">
              <p className="text-gray-600">Payment processing controls and real-time transaction monitoring will be displayed here.</p>
            </div>
          </div>
        )}

        {activeTab === 'security' && (
          <div className="space-y-6">
            <div className="bg-white rounded-xl shadow-sm border border-gray-200">
              <div className="px-6 py-4 border-b border-gray-200">
                <h2 className="text-lg font-semibold text-gray-900">Enterprise Security Monitoring</h2>
              </div>
              <div className="p-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <h3 className="font-medium text-gray-900 mb-3">Cryptographic Operations</h3>
                    <div className="space-y-2">
                      <div className="flex justify-between items-center p-3 bg-gray-50 rounded">
                        <span>HSM ECDSA P-384 Signatures</span>
                        <span className="font-medium">{metrics.securityService.hsmOperations.toLocaleString()}</span>
                      </div>
                      <div className="flex justify-between items-center p-3 bg-gray-50 rounded">
                        <span>Blockchain Anchors Created</span>
                        <span className="font-medium">{metrics.securityService.blockchainAnchors}</span>
                      </div>
                      <div className="flex justify-between items-center p-3 bg-gray-50 rounded">
                        <span>Immutable Audit Records</span>
                        <span className="font-medium">{metrics.securityService.auditRecords.toLocaleString()}</span>
                      </div>
                    </div>
                  </div>
                  <div>
                    <h3 className="font-medium text-gray-900 mb-3">Fraud Detection</h3>
                    <div className="space-y-2">
                      <div className="flex justify-between items-center p-3 bg-gray-50 rounded">
                        <span>Current Risk Score</span>
                        <span className="font-medium">{metrics.fraudDetection.riskScore.toFixed(1)}%</span>
                      </div>
                      <div className="flex justify-between items-center p-3 bg-gray-50 rounded">
                        <span>Blocked Transactions</span>
                        <span className="font-medium">{metrics.fraudDetection.blockedTransactions}</span>
                      </div>
                      <div className="flex justify-between items-center p-3 bg-gray-50 rounded">
                        <span>False Positives</span>
                        <span className="font-medium">{metrics.fraudDetection.falsePositives}</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {(activeTab === 'analytics' || activeTab === 'users') && (
          <div className="bg-white rounded-xl shadow-sm border border-gray-200">
            <div className="px-6 py-4 border-b border-gray-200">
              <h2 className="text-lg font-semibold text-gray-900">
                {activeTab === 'analytics' ? 'Advanced Analytics' : 'User Management'}
              </h2>
            </div>
            <div className="p-6">
              <p className="text-gray-600">
                {activeTab === 'analytics' 
                  ? 'Advanced analytics and reporting features will be implemented here.'
                  : 'Enterprise user management and RBAC controls will be available here.'
                }
              </p>
            </div>
          </div>
        )}
      </main>
    </div>
  );
};

export default EnterpriseAdminDashboard;
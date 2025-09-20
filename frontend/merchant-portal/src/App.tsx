import React, { useState, useEffect } from 'react';
import { 
  CreditCard, 
  DollarSign, 
  TrendingUp, 
  Shield, 
  Users, 
  AlertCircle,
  CheckCircle,
  Clock,
  BarChart3,
  Settings,
  Wallet
} from 'lucide-react';

interface TransactionData {
  id: string;
  amount: number;
  currency: string;
  status: 'completed' | 'pending' | 'failed';
  customer: string;
  timestamp: string;
  method: string;
}

interface MerchantMetrics {
  totalRevenue: number;
  transactionCount: number;
  successRate: number;
  avgTransactionValue: number;
  recentTransactions: TransactionData[];
}

const EnterpriseMerchantPortal: React.FC = () => {
  const [metrics, setMetrics] = useState<MerchantMetrics>({
    totalRevenue: 1247832.45,
    transactionCount: 8943,
    successRate: 99.97,
    avgTransactionValue: 139.52,
    recentTransactions: [
      {
        id: 'txn_1234567890',
        amount: 299.99,
        currency: 'USD',
        status: 'completed',
        customer: 'john.doe@example.com',
        timestamp: '2025-09-20T21:45:12Z',
        method: 'Stripe'
      },
      {
        id: 'txn_1234567891',
        amount: 89.50,
        currency: 'USD',
        status: 'pending',
        customer: 'jane.smith@example.com',
        timestamp: '2025-09-20T21:44:33Z',
        method: 'PayPal'
      },
      {
        id: 'txn_1234567892',
        amount: 450.00,
        currency: 'USD',
        status: 'completed',
        customer: 'enterprise.client@corp.com',
        timestamp: '2025-09-20T21:43:18Z',
        method: 'Coinbase Commerce'
      }
    ]
  });

  const [activeTab, setActiveTab] = useState<string>('dashboard');

  useEffect(() => {
    // Simulate real-time updates
    const interval = setInterval(() => {
      setMetrics(prev => ({
        ...prev,
        totalRevenue: prev.totalRevenue + (Math.random() * 1000),
        transactionCount: prev.transactionCount + Math.floor(Math.random() * 5),
        successRate: Math.min(100, prev.successRate + (Math.random() - 0.5) * 0.1)
      }));
    }, 10000);

    return () => clearInterval(interval);
  }, []);

  const formatCurrency = (amount: number): string => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD'
    }).format(amount);
  };

  const formatDate = (dateString: string): string => {
    return new Date(dateString).toLocaleString();
  };

  const getStatusColor = (status: string): string => {
    switch (status) {
      case 'completed': return 'text-green-600 bg-green-50 border-green-200';
      case 'pending': return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      case 'failed': return 'text-red-600 bg-red-50 border-red-200';
      default: return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed': return <CheckCircle className="h-4 w-4" />;
      case 'pending': return <Clock className="h-4 w-4" />;
      case 'failed': return <AlertCircle className="h-4 w-4" />;
      default: return <Clock className="h-4 w-4" />;
    }
  };

  const MetricCard: React.FC<{
    title: string;
    value: string | number;
    subtitle?: string;
    icon: React.ReactNode;
    color?: 'blue' | 'green' | 'purple' | 'indigo';
    trend?: number;
  }> = ({ title, value, subtitle, icon, color = 'blue', trend }) => (
    <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 hover:shadow-md transition-all duration-300">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-gray-600">{title}</p>
          <p className="text-3xl font-bold text-gray-900 mt-2">{value}</p>
          {subtitle && <p className="text-sm text-gray-500 mt-1">{subtitle}</p>}
          {trend !== undefined && (
            <div className={`flex items-center mt-2 ${trend >= 0 ? 'text-green-600' : 'text-red-600'}`}>
              <TrendingUp className={`h-4 w-4 mr-1 ${trend < 0 ? 'transform rotate-180' : ''}`} />
              <span className="text-sm font-medium">
                {trend >= 0 ? '+' : ''}{trend.toFixed(1)}%
              </span>
            </div>
          )}
        </div>
        <div className={`p-3 rounded-full ${
          color === 'blue' ? 'bg-blue-50 text-blue-600' :
          color === 'green' ? 'bg-green-50 text-green-600' :
          color === 'purple' ? 'bg-purple-50 text-purple-600' :
          'bg-indigo-50 text-indigo-600'
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
              <Wallet className="h-8 w-8 text-indigo-600 mr-3" />
              <div>
                <h1 className="text-2xl font-bold text-gray-900">Merchant Portal</h1>
                <p className="text-sm text-gray-500">Enterprise Payment Management</p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <div className="flex items-center bg-green-50 px-3 py-2 rounded-lg">
                <Shield className="h-4 w-4 text-green-600 mr-2" />
                <span className="text-sm font-medium text-green-700">FIPS 140-3 Secure</span>
              </div>
              <button className="p-2 text-gray-400 hover:text-gray-500 rounded-lg hover:bg-gray-100">
                <Settings className="h-5 w-5" />
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Navigation */}
      <nav className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex space-x-8 mt-6">
          {[
            { id: 'dashboard', label: 'Dashboard', icon: BarChart3 },
            { id: 'transactions', label: 'Transactions', icon: CreditCard },
            { id: 'customers', label: 'Customers', icon: Users },
            { id: 'analytics', label: 'Analytics', icon: TrendingUp },
            { id: 'settings', label: 'Settings', icon: Settings }
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center px-4 py-2 rounded-lg font-medium text-sm transition-colors ${
                activeTab === tab.id
                  ? 'bg-indigo-100 text-indigo-700 border border-indigo-200'
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
        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            {/* Key Metrics */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <MetricCard
                title="Total Revenue"
                value={formatCurrency(metrics.totalRevenue)}
                subtitle="This month"
                icon={<DollarSign className="h-6 w-6" />}
                color="green"
                trend={12.5}
              />
              <MetricCard
                title="Transactions"
                value={metrics.transactionCount.toLocaleString()}
                subtitle="This month"
                icon={<CreditCard className="h-6 w-6" />}
                color="blue"
                trend={8.3}
              />
              <MetricCard
                title="Success Rate"
                value={`${metrics.successRate.toFixed(2)}%`}
                subtitle="Last 30 days"
                icon={<CheckCircle className="h-6 w-6" />}
                color="green"
                trend={0.1}
              />
              <MetricCard
                title="Avg Transaction"
                value={formatCurrency(metrics.avgTransactionValue)}
                subtitle="Per transaction"
                icon={<TrendingUp className="h-6 w-6" />}
                color="purple"
                trend={-2.1}
              />
            </div>

            {/* Recent Transactions */}
            <div className="bg-white rounded-xl shadow-sm border border-gray-200">
              <div className="px-6 py-4 border-b border-gray-200">
                <h2 className="text-lg font-semibold text-gray-900">Recent Transactions</h2>
              </div>
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Transaction
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Customer
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Amount
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Method
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Status
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Date
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {metrics.recentTransactions.map((transaction) => (
                      <tr key={transaction.id} className="hover:bg-gray-50">
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                          {transaction.id}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          {transaction.customer}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                          {formatCurrency(transaction.amount)}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          {transaction.method}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${getStatusColor(transaction.status)}`}>
                            {getStatusIcon(transaction.status)}
                            <span className="ml-1 capitalize">{transaction.status}</span>
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          {formatDate(transaction.timestamp)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Payment Methods */}
            <div className="bg-white rounded-xl shadow-sm border border-gray-200">
              <div className="px-6 py-4 border-b border-gray-200">
                <h2 className="text-lg font-semibold text-gray-900">Enterprise Payment Methods</h2>
              </div>
              <div className="p-6">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="flex items-center p-4 bg-blue-50 rounded-lg border border-blue-200">
                    <CreditCard className="h-8 w-8 text-blue-600 mr-3" />
                    <div>
                      <p className="font-semibold text-blue-900">Stripe</p>
                      <p className="text-sm text-blue-700">Credit & Debit Cards</p>
                    </div>
                  </div>
                  <div className="flex items-center p-4 bg-purple-50 rounded-lg border border-purple-200">
                    <Wallet className="h-8 w-8 text-purple-600 mr-3" />
                    <div>
                      <p className="font-semibold text-purple-900">PayPal</p>
                      <p className="text-sm text-purple-700">Digital Wallet</p>
                    </div>
                  </div>
                  <div className="flex items-center p-4 bg-orange-50 rounded-lg border border-orange-200">
                    <DollarSign className="h-8 w-8 text-orange-600 mr-3" />
                    <div>
                      <p className="font-semibold text-orange-900">Coinbase Commerce</p>
                      <p className="text-sm text-orange-700">Cryptocurrency</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {(activeTab !== 'dashboard') && (
          <div className="bg-white rounded-xl shadow-sm border border-gray-200">
            <div className="px-6 py-4 border-b border-gray-200">
              <h2 className="text-lg font-semibold text-gray-900">
                {activeTab.charAt(0).toUpperCase() + activeTab.slice(1)}
              </h2>
            </div>
            <div className="p-6">
              <p className="text-gray-600">
                {activeTab} functionality will be implemented here with enterprise-grade features and FIPS compliance.
              </p>
            </div>
          </div>
        )}
      </main>
    </div>
  );
};

export default EnterpriseMerchantPortal;
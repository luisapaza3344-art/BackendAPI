/**
 * Payment Status Tracker - Real-time Payment Monitoring
 * 
 * FEATURES:
 * - Real-time payment status updates
 * - WebSocket connection for live updates
 * - Payment confirmation handling
 * - Error state management
 * - Fraud detection alerts
 */

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { createWebhookService } from '../../services/webhookService';
import { SecurityService } from '../../services/cryptoService';
import { 
  CheckCircle, 
  AlertCircle, 
  Clock, 
  CreditCard, 
  DollarSign, 
  Bitcoin,
  Shield,
  Loader2,
  RefreshCw
} from 'lucide-react';

interface PaymentStatusTrackerProps {
  tempPaymentId: string;
  onPaymentComplete: (result: any) => void;
  onPaymentFailed: (error: string) => void;
}

interface PaymentUpdate {
  status: 'pending' | 'processing' | 'requires_action' | 'succeeded' | 'failed' | 'cancelled';
  provider: 'stripe' | 'paypal' | 'coinbase';
  paymentId: string;
  orderId?: string;
  amount: number;
  currency: string;
  timestamp: string;
  error?: string;
  fraudScore?: number;
}

/**
 * Real-time payment status tracker
 */
export const PaymentStatusTracker: React.FC<PaymentStatusTrackerProps> = ({
  tempPaymentId,
  onPaymentComplete,
  onPaymentFailed
}) => {
  const [paymentUpdate, setPaymentUpdate] = useState<PaymentUpdate | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [connectionError, setConnectionError] = useState<string>('');

  // Establish WebSocket connection for real-time updates
  useEffect(() => {
    const webhookService = createWebhookService();
    
    const cleanup = webhookService.listenForPaymentUpdates((update) => {
      if (update.temp_payment_id === tempPaymentId) {
        setPaymentUpdate(update);
        setIsConnected(true);
        setConnectionError('');

        // Log payment update
        SecurityService.logSecurityEvent('payment_status_update', {
          tempPaymentId,
          status: update.status,
          provider: update.provider,
          paymentId: update.paymentId
        });

        // Handle payment completion
        if (update.status === 'succeeded') {
          onPaymentComplete({
            orderId: update.orderId,
            paymentId: update.paymentId,
            provider: update.provider,
            amount: update.amount,
            currency: update.currency
          });
        } else if (update.status === 'failed') {
          onPaymentFailed(update.error || 'Payment failed');
        }
      }
    });

    // Handle connection errors
    const handleConnectionError = () => {
      setIsConnected(false);
      setConnectionError('Connection lost. Attempting to reconnect...');
    };

    // Set up error handling
    window.addEventListener('websocket-error', handleConnectionError);

    return () => {
      cleanup();
      window.removeEventListener('websocket-error', handleConnectionError);
    };
  }, [tempPaymentId, onPaymentComplete, onPaymentFailed]);

  /**
   * Get status icon based on payment status
   */
  const getStatusIcon = () => {
    if (!paymentUpdate) return <Clock className="w-5 h-5 text-gray-400" />;

    switch (paymentUpdate.status) {
      case 'pending':
        return <Clock className="w-5 h-5 text-yellow-500" />;
      case 'processing':
        return <Loader2 className="w-5 h-5 text-blue-500 animate-spin" />;
      case 'requires_action':
        return <AlertCircle className="w-5 h-5 text-orange-500" />;
      case 'succeeded':
        return <CheckCircle className="w-5 h-5 text-green-500" />;
      case 'failed':
        return <AlertCircle className="w-5 h-5 text-red-500" />;
      case 'cancelled':
        return <AlertCircle className="w-5 h-5 text-gray-500" />;
      default:
        return <Clock className="w-5 h-5 text-gray-400" />;
    }
  };

  /**
   * Get provider icon
   */
  const getProviderIcon = () => {
    if (!paymentUpdate) return null;

    switch (paymentUpdate.provider) {
      case 'stripe':
        return <CreditCard className="w-4 h-4" />;
      case 'paypal':
        return <DollarSign className="w-4 h-4" />;
      case 'coinbase':
        return <Bitcoin className="w-4 h-4" />;
      default:
        return null;
    }
  };

  /**
   * Get status message
   */
  const getStatusMessage = () => {
    if (!paymentUpdate) return 'Waiting for payment...';

    switch (paymentUpdate.status) {
      case 'pending':
        return 'Payment initiated, waiting for confirmation...';
      case 'processing':
        return 'Processing your payment securely...';
      case 'requires_action':
        return 'Additional authentication required. Please complete the verification.';
      case 'succeeded':
        return 'Payment completed successfully!';
      case 'failed':
        return `Payment failed: ${paymentUpdate.error || 'Unknown error'}`;
      case 'cancelled':
        return 'Payment was cancelled.';
      default:
        return 'Processing payment...';
    }
  };

  /**
   * Retry connection
   */
  const retryConnection = () => {
    setConnectionError('');
    window.location.reload(); // Simple retry by reloading
  };

  return (
    <Card className="w-full max-w-md mx-auto">
      <CardHeader>
        <CardTitle className="flex items-center space-x-2">
          <Shield className="w-5 h-5" />
          <span>Payment Status</span>
          {isConnected && (
            <Badge variant="outline" className="text-xs text-green-600">
              LIVE
            </Badge>
          )}
        </CardTitle>
      </CardHeader>

      <CardContent className="space-y-6">
        {/* Connection Status */}
        {connectionError && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            className="flex items-center justify-between p-3 bg-yellow-50 dark:bg-yellow-950 border border-yellow-200 dark:border-yellow-800 rounded-lg"
          >
            <div className="flex items-center space-x-2">
              <AlertCircle className="w-4 h-4 text-yellow-600" />
              <span className="text-sm text-yellow-800 dark:text-yellow-200">
                {connectionError}
              </span>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={retryConnection}
              className="text-xs"
            >
              <RefreshCw className="w-3 h-3 mr-1" />
              Retry
            </Button>
          </motion.div>
        )}

        {/* Payment Status Display */}
        <div className="space-y-4">
          <div className="flex items-center space-x-3">
            {getStatusIcon()}
            <div className="flex-1">
              <p className="font-medium text-foreground">
                {getStatusMessage()}
              </p>
              {paymentUpdate && (
                <div className="flex items-center space-x-2 mt-1">
                  {getProviderIcon()}
                  <span className="text-xs text-muted-foreground capitalize">
                    {paymentUpdate.provider}
                  </span>
                  <span className="text-xs text-muted-foreground">
                    ${(paymentUpdate.amount / 100).toFixed(2)} {paymentUpdate.currency.toUpperCase()}
                  </span>
                </div>
              )}
            </div>
          </div>

          {/* Payment ID */}
          {paymentUpdate?.paymentId && (
            <div className="text-xs text-muted-foreground">
              Payment ID: {paymentUpdate.paymentId}
            </div>
          )}

          {/* Order ID (when available) */}
          {paymentUpdate?.orderId && (
            <div className="text-xs text-muted-foreground">
              Order ID: {paymentUpdate.orderId}
            </div>
          )}

          {/* Fraud Score Alert */}
          {paymentUpdate?.fraudScore && paymentUpdate.fraudScore > 0.7 && (
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              className="p-3 bg-red-50 dark:bg-red-950 border border-red-200 dark:border-red-800 rounded-lg"
            >
              <div className="flex items-center space-x-2">
                <AlertCircle className="w-4 h-4 text-red-600" />
                <span className="text-sm text-red-800 dark:text-red-200">
                  High-risk transaction detected. Additional verification may be required.
                </span>
              </div>
            </motion.div>
          )}
        </div>

        {/* Progress Indicator */}
        <div className="space-y-2">
          <div className="flex justify-between text-xs text-muted-foreground">
            <span>Payment Progress</span>
            <span>
              {paymentUpdate?.status === 'succeeded' ? '100%' : 
               paymentUpdate?.status === 'processing' ? '50%' : 
               paymentUpdate?.status === 'requires_action' ? '75%' : '25%'}
            </span>
          </div>
          <div className="w-full bg-muted rounded-full h-2">
            <motion.div
              className="bg-primary rounded-full h-2"
              initial={{ width: '0%' }}
              animate={{ 
                width: paymentUpdate?.status === 'succeeded' ? '100%' : 
                       paymentUpdate?.status === 'processing' ? '50%' : 
                       paymentUpdate?.status === 'requires_action' ? '75%' : '25%'
              }}
              transition={{ duration: 0.5 }}
            />
          </div>
        </div>

        {/* Security Notice */}
        <div className="text-xs text-center text-muted-foreground space-y-1">
          <div className="flex items-center justify-center space-x-1">
            <Shield className="w-3 h-3" />
            <span>End-to-end encrypted • PCI DSS Level 1</span>
          </div>
          {import.meta.env.NODE_ENV !== 'production' && (
            <div className="text-yellow-600 font-medium">
              TEST MODE - Using test payment credentials
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
};

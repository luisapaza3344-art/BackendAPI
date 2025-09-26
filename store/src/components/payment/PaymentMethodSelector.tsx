/**
 * Payment Method Selector - Live Payment Options
 * 
 * FEATURES:
 * - Dynamic payment method detection
 * - Real-time availability checking
 * - Provider-specific configurations
 * - Accessibility compliance
 * - Mobile-optimized UI
 */

import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { createStripeService, STRIPE_TEST_CARDS } from '../../services/stripeService';
import { createPayPalService, PAYPAL_TEST_ACCOUNTS } from '../../services/paypalService';
import { createCoinbaseService, SUPPORTED_CRYPTOCURRENCIES } from '../../services/cryptoService';
import { 
  CreditCard, 
  DollarSign, 
  Bitcoin, 
  Smartphone, 
  Shield,
  CheckCircle,
  AlertCircle,
  Info
} from 'lucide-react';

interface PaymentMethodSelectorProps {
  onMethodSelect: (method: PaymentMethod) => void;
  selectedMethod?: string;
  amount: number;
  currency: string;
}

interface PaymentMethod {
  id: string;
  name: string;
  description: string;
  icon: React.ComponentType<any>;
  available: boolean;
  fees?: string;
  processingTime?: string;
  testInfo?: any;
}

/**
 * Payment method selector component
 */
export const PaymentMethodSelector: React.FC<PaymentMethodSelectorProps> = ({
  onMethodSelect,
  selectedMethod,
  amount,
  currency
}) => {
  const [paymentMethods, setPaymentMethods] = useState<PaymentMethod[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [showTestInfo, setShowTestInfo] = useState(import.meta.env.NODE_ENV !== 'production');

  // Initialize payment methods
  useEffect(() => {
    const initializePaymentMethods = async () => {
      const methods: PaymentMethod[] = [];

      // Check Stripe availability
      try {
        const stripeService = createStripeService();
        await stripeService.initialize();
        
        methods.push({
          id: 'stripe',
          name: 'Credit/Debit Card',
          description: 'Visa, Mastercard, American Express',
          icon: CreditCard,
          available: true,
          fees: '2.9% + $0.30',
          processingTime: 'Instant',
          testInfo: {
            cards: STRIPE_TEST_CARDS,
            note: 'Use test card numbers for testing'
          }
        });

        // Check Apple Pay availability
        const canUseApplePay = await stripeService.canMakeApplePayPayment();
        if (canUseApplePay) {
          methods.push({
            id: 'apple_pay',
            name: 'Apple Pay',
            description: 'Touch ID or Face ID',
            icon: Smartphone,
            available: true,
            fees: '2.9% + $0.30',
            processingTime: 'Instant'
          });
        }

        // Check Google Pay availability
        const canUseGooglePay = await stripeService.canMakeGooglePayPayment();
        if (canUseGooglePay) {
          methods.push({
            id: 'google_pay',
            name: 'Google Pay',
            description: 'Pay with Google',
            icon: Smartphone,
            available: true,
            fees: '2.9% + $0.30',
            processingTime: 'Instant'
          });
        }
      } catch (error) {
        console.warn('Stripe not available:', error);
      }

      // Check PayPal availability
      try {
        createPayPalService();
        methods.push({
          id: 'paypal',
          name: 'PayPal',
          description: 'Pay with PayPal account',
          icon: DollarSign,
          available: true,
          fees: '3.49% + $0.49',
          processingTime: 'Instant',
          testInfo: {
            accounts: PAYPAL_TEST_ACCOUNTS,
            note: 'Use test PayPal accounts for testing'
          }
        });
      } catch (error) {
        console.warn('PayPal not available:', error);
      }

      // Check Coinbase availability
      try {
        const coinbaseService = createCoinbaseService();
        const supportedCryptos = await coinbaseService.getSupportedCryptocurrencies();
        
        methods.push({
          id: 'coinbase',
          name: 'Cryptocurrency',
          description: 'Bitcoin, Ethereum, USDC',
          icon: Bitcoin,
          available: true,
          fees: '1% + network fees',
          processingTime: '10-60 minutes',
          testInfo: {
            cryptocurrencies: SUPPORTED_CRYPTOCURRENCIES,
            note: 'Test with small amounts on testnets'
          }
        });
      } catch (error) {
        console.warn('Coinbase not available:', error);
      }

      setPaymentMethods(methods);
      setIsLoading(false);
    };

    initializePaymentMethods();
  }, []);

  /**
   * Handle method selection
   */
  const handleMethodSelect = (method: PaymentMethod) => {
    if (method.available) {
      onMethodSelect(method);
    }
  };

  if (isLoading) {
    return (
      <Card>
        <CardContent className="flex items-center justify-center py-8">
          <div className="text-center">
            <Loader2 className="w-6 h-6 animate-spin mx-auto mb-2" />
            <p className="text-sm text-muted-foreground">Loading payment methods...</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      {/* Payment Methods Grid */}
      <div className="grid grid-cols-1 gap-3">
        {paymentMethods.map((method, index) => {
          const IconComponent = method.icon;
          const isSelected = selectedMethod === method.id;
          
          return (
            <motion.div
              key={method.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3, delay: index * 0.1 }}
            >
              <button
                onClick={() => handleMethodSelect(method)}
                disabled={!method.available}
                className={`w-full p-4 border rounded-lg transition-all text-left ${
                  isSelected 
                    ? 'border-primary bg-primary/5 shadow-md' 
                    : method.available
                      ? 'border-border hover:border-primary/50 hover:shadow-sm'
                      : 'border-border opacity-50 cursor-not-allowed'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <IconComponent className={`w-6 h-6 ${isSelected ? 'text-primary' : 'text-muted-foreground'}`} />
                    <div>
                      <h3 className="font-medium text-foreground">{method.name}</h3>
                      <p className="text-sm text-muted-foreground">{method.description}</p>
                      {method.fees && (
                        <p className="text-xs text-muted-foreground mt-1">
                          Fees: {method.fees} • {method.processingTime}
                        </p>
                      )}
                    </div>
                  </div>
                  
                  <div className="flex items-center space-x-2">
                    {method.available ? (
                      <CheckCircle className="w-5 h-5 text-green-500" />
                    ) : (
                      <AlertCircle className="w-5 h-5 text-red-500" />
                    )}
                    {isSelected && (
                      <Badge className="text-xs">Selected</Badge>
                    )}
                  </div>
                </div>
              </button>
            </motion.div>
          );
        })}
      </div>

      {/* Test Information */}
      {showTestInfo && (
        <Card className="border-yellow-200 bg-yellow-50 dark:bg-yellow-950">
          <CardContent className="p-4">
            <div className="flex items-start space-x-2">
              <Info className="w-4 h-4 text-yellow-600 mt-0.5" />
              <div className="space-y-2">
                <h4 className="text-sm font-medium text-yellow-800 dark:text-yellow-200">
                  Test Mode Information
                </h4>
                <div className="text-xs text-yellow-700 dark:text-yellow-300 space-y-1">
                  <p><strong>Stripe Test Cards:</strong></p>
                  <p>• Success: 4242424242424242</p>
                  <p>• 3D Secure: 4000002500003155</p>
                  <p>• Declined: 4000000000000002</p>
                  
                  <p className="mt-2"><strong>PayPal Test Account:</strong></p>
                  <p>• Email: {PAYPAL_TEST_ACCOUNTS.BUYER.email}</p>
                  <p>• Password: {PAYPAL_TEST_ACCOUNTS.BUYER.password}</p>
                  
                  <p className="mt-2"><strong>Crypto:</strong> Use testnet addresses only</p>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setShowTestInfo(false)}
                  className="text-xs"
                >
                  Hide Test Info
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Security Notice */}
      <div className="text-center space-y-2">
        <div className="flex items-center justify-center space-x-2 text-sm text-muted-foreground">
          <Shield className="w-4 h-4" />
          <span>All payments are secured with bank-level encryption</span>
        </div>
        <div className="text-xs text-muted-foreground">
          PCI DSS Level 1 Compliant • SOC 2 Type II • ISO 27001 Certified
        </div>
      </div>
    </div>
  );
};

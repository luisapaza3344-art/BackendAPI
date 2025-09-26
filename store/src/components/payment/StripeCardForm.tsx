import React, { useState, useEffect } from 'react';
import { CardElement, useStripe, useElements } from '@stripe/react-stripe-js';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { AlertCircle, CreditCard, Shield } from 'lucide-react';
import { SecureApiClient } from '../../utils/securityHardening';
import { SecurityService } from '../../services/cryptoService';

interface StripeCardFormProps {
  onSuccess: (paymentIntent: any) => void;
  onError: (error: string) => void;
  tempPaymentId: string;
  disabled?: boolean;
}

/**
 * Ultra-secure Stripe card payment form component
 * 
 * SECURITY FEATURES:
 * - No amount handling in frontend
 * - Client secret from backend only
 * - 3D Secure support
 * - Comprehensive error handling
 * - Security event logging
 */
export const StripeCardForm: React.FC<StripeCardFormProps> = ({
  onSuccess,
  onError,
  tempPaymentId,
  disabled = false
}) => {
  const stripe = useStripe();
  const elements = useElements();
  const [isProcessing, setIsProcessing] = useState(false);
  const [error, setError] = useState<string>('');
  const [clientSecret, setClientSecret] = useState<string>('');

  /**
   * Get LIVE client secret from backend
   */
  useEffect(() => {
    const getClientSecret = async () => {
      try {
        // Call LIVE backend API to create PaymentIntent
        const response = await fetch(`${import.meta.env.VITE_BACKEND_URL}/api/stripe/create-payment-intent`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${localStorage.getItem('auth_token')}`,
            'X-CSRF-Token': localStorage.getItem('csrf_token') || '',
            'X-Session-ID': localStorage.getItem('session_id') || ''
          },
          body: JSON.stringify({
            temp_payment_id: tempPaymentId,
            timestamp: Date.now(),
            nonce: SecurityService.generateNonce()
          })
        });

        if (!response.ok) {
          throw new Error('Failed to create payment intent');
        }

        const data = await response.json();
        
        if (!data.client_secret || !data.client_secret.startsWith('pi_')) {
          throw new Error('Invalid payment intent received');
        }

        setClientSecret(data.client_secret);
        
        SecurityService.logSecurityEvent('stripe_payment_intent_created', {
          paymentIntentId: data.id,
          tempPaymentId
        });
      } catch (error) {
        console.error('Failed to get client secret:', error);
        onError('Failed to initialize secure payment. Please try again.');
      }
    };

    if (tempPaymentId) {
      getClientSecret();
    }
  }, [tempPaymentId, onError]);

  /**
   * Handle secure card payment submission
   * @param event - Form submit event
   */
  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();

    if (!stripe || !elements || !clientSecret) {
      setError('Payment system not ready. Please wait or refresh the page.');
      return;
    }

    const cardElement = elements.getElement(CardElement);
    if (!cardElement) {
      setError('Card input not found. Please refresh the page.');
      return;
    }

    setIsProcessing(true);
    setError('');

    try {
      SecurityService.logSecurityEvent('stripe_payment_attempt', {
        tempPaymentId,
        timestamp: Date.now()
      });

      // Confirm LIVE payment with Stripe
      const { error: confirmError, paymentIntent } = await stripe.confirmCardPayment(clientSecret, {
        payment_method: {
          card: cardElement,
        }
      });

      if (confirmError) {
        SecurityService.logSecurityEvent('stripe_payment_failed', {
          error: confirmError.message,
          code: confirmError.code,
          tempPaymentId
        }, 'warn');
        
        throw new Error(confirmError.message || 'Payment failed');
      }

      // Handle 3D Secure if required
      if (paymentIntent.status === 'requires_action') {
        SecurityService.logSecurityEvent('stripe_3ds_required', { tempPaymentId });
        
        const { error: actionError, paymentIntent: confirmedIntent } = await stripe.confirmCardPayment(clientSecret);
        
        if (actionError) {
          throw new Error(actionError.message || '3D Secure authentication failed');
        }
        
        SecurityService.logSecurityEvent('stripe_3ds_completed', { tempPaymentId });
        onSuccess(confirmedIntent);
      } else {
        SecurityService.logSecurityEvent('stripe_payment_success', { 
          paymentIntentId: paymentIntent.id,
          tempPaymentId 
        });
        onSuccess(paymentIntent);
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Payment failed';
      setError(errorMessage);
      onError(errorMessage);
      
      SecurityService.logSecurityEvent('stripe_payment_error', {
        error: errorMessage,
        tempPaymentId
      }, 'error');
    } finally {
      setIsProcessing(false);
    }
  };

  const cardElementOptions = {
    style: {
      base: {
        fontSize: '16px',
        color: '#1f2937', // Fixed color instead of CSS variable
        fontFamily: 'Inter, sans-serif',
        '::placeholder': {
          color: '#9ca3af', // Fixed color instead of CSS variable
        },
      },
      invalid: {
        color: '#ef4444',
      },
    },
    hidePostalCode: true,
    disabled: disabled || isProcessing,
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center space-x-2 text-sm text-muted-foreground">
        <Shield className="w-4 h-4" />
        <span>Secured by Stripe • PCI DSS Level 1 Compliant</span>
      </div>
      
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <Label className="text-sm font-light text-muted-foreground mb-3 block">
            <CreditCard className="w-4 h-4 inline mr-2" />
            Card Information
          </Label>
          <div className="p-3 border border-border rounded-md bg-background">
            <CardElement options={cardElementOptions} />
          </div>
        </div>

        {error && (
          <div className="flex items-center p-3 text-sm text-red-600 bg-red-50 dark:bg-red-950 rounded-lg">
            <AlertCircle className="w-4 h-4 mr-2" />
            {error}
          </div>
        )}

        <Button
          type="submit"
          disabled={!stripe || !clientSecret || isProcessing || disabled}
          className="w-full bg-primary text-primary-foreground hover:bg-primary/90"
        >
          {isProcessing ? 'Processing Secure Payment...' : 'Complete Secure Payment'}
        </Button>
      </form>
    </div>
  );
};

import React, { useEffect, useState } from 'react';
import { useStripe } from '@stripe/react-stripe-js';
import { Button } from '@/components/ui/button';
import { Smartphone } from 'lucide-react';

interface GooglePayButtonProps {
  amount: number;
  onSuccess: (paymentIntent: any) => void;
  onError: (error: string) => void;
  disabled?: boolean;
}

/**
 * Google Pay payment button component
 */
export const GooglePayButton: React.FC<GooglePayButtonProps> = ({
  amount,
  onSuccess,
  onError,
  disabled = false
}) => {
  const stripe = useStripe();
  const [canUseGooglePay, setCanUseGooglePay] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);

  /**
   * Check Google Pay availability on component mount
   */
  useEffect(() => {
    const checkGooglePayAvailability = async () => {
      if (!stripe) return;

      const paymentRequest = stripe.paymentRequest({
        country: 'US',
        currency: 'usd',
        total: {
          label: 'Total',
          amount: Math.round(amount * 100),
        },
        requestPayerName: true,
        requestPayerEmail: true,
      });

      const result = await paymentRequest.canMakePayment();
      setCanUseGooglePay(result?.googlePay === true);
    };

    checkGooglePayAvailability();
  }, [stripe, amount]);

  /**
   * Handle Google Pay payment
   */
  const handleGooglePayment = async () => {
    if (!stripe || !canUseGooglePay) return;

    setIsProcessing(true);

    try {
      const paymentRequest = stripe.paymentRequest({
        country: 'US',
        currency: 'usd',
        total: {
          label: 'Minimal Gallery',
          amount: Math.round(amount * 100),
        },
        requestPayerName: true,
        requestPayerEmail: true,
      });

      paymentRequest.on('paymentmethod', async (event) => {
        try {
          // In production, create payment intent on your backend
          const { error, paymentIntent } = await stripe.confirmCardPayment(
            'pi_demo_client_secret', // This would come from your backend
            {
              payment_method: event.paymentMethod.id
            }
          );

          if (error) {
            event.complete('fail');
            throw new Error(error.message || 'Google Pay payment failed');
          } else {
            event.complete('success');
            onSuccess(paymentIntent);
          }
        } catch (error) {
          event.complete('fail');
          const errorMessage = error instanceof Error ? error.message : 'Google Pay payment failed';
          onError(errorMessage);
        } finally {
          setIsProcessing(false);
        }
      });

      paymentRequest.show();
    } catch (error) {
      setIsProcessing(false);
      const errorMessage = error instanceof Error ? error.message : 'Google Pay not available';
      onError(errorMessage);
    }
  };

  if (!canUseGooglePay) {
    return (
      <div className="bg-muted border border-border rounded-lg p-6 text-center">
        <Smartphone className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
        <h3 className="text-lg font-medium text-foreground mb-2">Google Pay</h3>
        <p className="text-muted-foreground font-light">
          Google Pay is not available on this device or browser.
        </p>
      </div>
    );
  }

  return (
    <div className="bg-muted border border-border rounded-lg p-6 text-center">
      <Smartphone className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
      <h3 className="text-lg font-medium text-foreground mb-2">Google Pay</h3>
      <p className="text-muted-foreground font-light mb-4">
        Pay quickly and securely with Google Pay.
      </p>
      
      <Button
        onClick={handleGooglePayment}
        disabled={disabled || isProcessing}
        className="w-full bg-blue-600 text-white hover:bg-blue-700"
      >
        {isProcessing ? 'Processing...' : `Pay with Google Pay - $${amount.toFixed(2)}`}
      </Button>
    </div>
  );
};

import React from 'react';

// Apple Pay types
declare global {
  interface Window {
    ApplePaySession?: any;
  }
  
  var ApplePaySession: any;
}

interface ApplePayButtonProps {
  amount?: number;
  onPaymentAuthorized?: (paymentData: any) => void;
  onPaymentCanceled?: () => void;
  className?: string;
}

export const ApplePayButton: React.FC<ApplePayButtonProps> = ({
  amount = 0,
  onPaymentAuthorized,
  onPaymentCanceled,
  className = ""
}) => {
  const handleApplePayClick = () => {
    // Check if Apple Pay is available
    if (window.ApplePaySession && ApplePaySession.canMakePayments()) {
      // Create Apple Pay session
      const request = {
        countryCode: 'US',
        currencyCode: 'USD',
        supportedNetworks: ['visa', 'masterCard', 'amex'],
        merchantCapabilities: ['supports3DS'],
        total: {
          label: 'Ultra Professional Store',
          amount: amount.toString()
        }
      };

      try {
        const session = new ApplePaySession(3, request);
        
        session.onvalidatemerchant = (event: any) => {
          // Validate merchant with your backend
          console.log('🍎 Apple Pay merchant validation required');
        };
        
        session.onpaymentauthorized = (event: any) => {
          console.log('🍎 Apple Pay payment authorized');
          if (onPaymentAuthorized) {
            onPaymentAuthorized(event.payment);
          }
          session.completePayment(ApplePaySession.STATUS_SUCCESS);
        };
        
        session.oncancel = () => {
          console.log('🍎 Apple Pay payment canceled');
          if (onPaymentCanceled) {
            onPaymentCanceled();
          }
        };
        
        session.begin();
      } catch (error) {
        console.error('🍎 Apple Pay session error:', error);
      }
    } else {
      console.log('🍎 Apple Pay not available on this device');
    }
  };

  // Check if Apple Pay is supported
  const isApplePayAvailable = () => {
    return window.ApplePaySession && ApplePaySession.canMakePayments();
  };

  if (!isApplePayAvailable()) {
    return null; // Don't render if Apple Pay is not available
  }

  return (
    <button
      className={`apple-pay-button ${className}`}
      onClick={handleApplePayClick}
      style={{
        background: 'linear-gradient(135deg, #000 0%, #333 100%)',
        color: 'white',
        border: 'none',
        borderRadius: '8px',
        padding: '12px 24px',
        fontSize: '16px',
        fontWeight: '600',
        cursor: 'pointer',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '8px',
        transition: 'all 0.2s ease',
        boxShadow: '0 2px 8px rgba(0, 0, 0, 0.15)',
        minHeight: '48px'
      }}
      onMouseOver={(e) => {
        e.currentTarget.style.transform = 'translateY(-1px)';
        e.currentTarget.style.boxShadow = '0 4px 12px rgba(0, 0, 0, 0.2)';
      }}
      onMouseOut={(e) => {
        e.currentTarget.style.transform = 'translateY(0)';
        e.currentTarget.style.boxShadow = '0 2px 8px rgba(0, 0, 0, 0.15)';
      }}
    >
      <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
        <path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-1.07 3.81-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M13 3.5c.73-.83 1.94-1.46 2.94-1.5.13 1.17-.34 2.35-1.04 3.19-.69.85-1.83 1.51-2.95 1.42-.15-1.15.41-2.35 1.05-3.11z"/>
      </svg>
      Pay with Apple Pay
    </button>
  );
};


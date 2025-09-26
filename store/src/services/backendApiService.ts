/**
 * Backend API Service for Live Payment Processing
 * 
 * PRODUCTION ENDPOINTS:
 * - POST /api/checkout/initialize - Initialize secure checkout session
 * - POST /api/stripe/create-payment-intent - Create Stripe PaymentIntent
 * - POST /api/paypal/create-order - Create PayPal order
 * - POST /api/coinbase/create-charge - Create Coinbase charge
 * - POST /api/webhooks/stripe - Handle Stripe webhooks
 * - POST /api/webhooks/paypal - Handle PayPal webhooks
 * - POST /api/webhooks/coinbase - Handle Coinbase webhooks
 * - GET /api/orders/:id/status - Get order status
 * 
 * SECURITY FEATURES:
 * - JWT authentication
 * - CSRF protection
 * - Rate limiting
 * - Request signing
 * - Comprehensive logging
 */

import { SecurityService } from './cryptoService';

/**
 * Backend API configuration
 */
interface BackendConfig {
  readonly baseUrl: string;
  readonly timeout: number;
  readonly apiVersion: string;
}

/**
 * Checkout session data
 */
export interface CheckoutSession {
  readonly tempPaymentId: string;
  readonly csrfToken: string;
  readonly expiresAt: number;
  readonly cartHash: string;
  readonly sessionId: string;
}

/**
 * Payment intent response
 */
export interface PaymentIntentResponse {
  readonly clientSecret: string;
  readonly paymentIntentId: string;
  readonly amount: number;
  readonly currency: string;
  readonly status: string;
}

/**
 * Order status response
 */
export interface OrderStatusResponse {
  readonly orderId?: string;
  readonly status: 'pending' | 'processing' | 'paid' | 'failed' | 'cancelled';
  readonly paymentProvider?: string;
  readonly paymentId?: string;
  readonly amount?: number;
  readonly currency?: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

/**
 * Backend API service for live payment processing
 */
export class BackendApiService {
  private readonly config: BackendConfig;

  /**
   * Initialize backend API service
   * @param config - Backend configuration
   */
  constructor(config: BackendConfig) {
    this.config = Object.freeze(config);
  }

  /**
   * Initialize secure checkout session
   * @param cartItems - Cart items for validation
   * @returns Promise with checkout session
   */
  async initializeCheckout(cartItems: any[]): Promise<CheckoutSession> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);

    try {
      const response = await fetch(`${this.config.baseUrl}/api/checkout/initialize`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.getAuthToken()}`,
          'X-API-Version': this.config.apiVersion,
          'X-CSRF-Token': this.getCSRFToken(),
          'X-Session-ID': this.getSessionId(),
          'X-Timestamp': Date.now().toString(),
          'X-Nonce': SecurityService.generateNonce()
        },
        body: JSON.stringify({
          cart_items: cartItems,
          client_fingerprint: this.getClientFingerprint()
        }),
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorBody = await response.json().catch(() => ({}));
        throw new Error(`Checkout initialization failed: ${response.status} - ${errorBody.message || 'Unknown error'}`);
      }

      const result = await response.json();
      
      if (!result.temp_payment_id || !result.csrf_token || !result.expires_at) {
        throw new Error('Invalid checkout session response');
      }

      return result as CheckoutSession;
    } catch (error) {
      clearTimeout(timeoutId);
      throw error;
    }
  }

  /**
   * Create Stripe PaymentIntent
   * @param tempPaymentId - Temporary payment ID
   * @param shippingInfo - Customer shipping information
   * @returns Promise with PaymentIntent
   */
  async createStripePaymentIntent(tempPaymentId: string, shippingInfo: any): Promise<PaymentIntentResponse> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);

    try {
      const response = await fetch(`${this.config.baseUrl}/api/stripe/create-payment-intent`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.getAuthToken()}`,
          'X-API-Version': this.config.apiVersion,
          'X-CSRF-Token': this.getCSRFToken(),
          'X-Idempotency-Key': `stripe_${tempPaymentId}_${Date.now()}`
        },
        body: JSON.stringify({
          temp_payment_id: tempPaymentId,
          shipping_info: shippingInfo,
          payment_method_types: ['card', 'apple_pay', 'google_pay'],
          capture_method: 'automatic'
        }),
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorBody = await response.json().catch(() => ({}));
        throw new Error(`Stripe PaymentIntent creation failed: ${response.status} - ${errorBody.message || 'Unknown error'}`);
      }

      return await response.json() as PaymentIntentResponse;
    } catch (error) {
      clearTimeout(timeoutId);
      throw error;
    }
  }

  /**
   * Create PayPal order
   * @param tempPaymentId - Temporary payment ID
   * @param shippingInfo - Customer shipping information
   * @returns Promise with PayPal order
   */
  async createPayPalOrder(tempPaymentId: string, shippingInfo: any): Promise<any> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);

    try {
      const response = await fetch(`${this.config.baseUrl}/api/paypal/create-order`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.getAuthToken()}`,
          'X-API-Version': this.config.apiVersion,
          'X-CSRF-Token': this.getCSRFToken(),
          'X-Idempotency-Key': `paypal_${tempPaymentId}_${Date.now()}`
        },
        body: JSON.stringify({
          temp_payment_id: tempPaymentId,
          shipping_info: shippingInfo,
          return_url: `${window.location.origin}/checkout/paypal/success`,
          cancel_url: `${window.location.origin}/checkout/paypal/cancel`
        }),
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorBody = await response.json().catch(() => ({}));
        throw new Error(`PayPal order creation failed: ${response.status} - ${errorBody.message || 'Unknown error'}`);
      }

      return await response.json();
    } catch (error) {
      clearTimeout(timeoutId);
      throw error;
    }
  }

  /**
   * Create Coinbase Commerce charge
   * @param tempPaymentId - Temporary payment ID
   * @param shippingInfo - Customer shipping information
   * @returns Promise with Coinbase charge
   */
  async createCoinbaseCharge(tempPaymentId: string, shippingInfo: any): Promise<any> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);

    try {
      const response = await fetch(`${this.config.baseUrl}/api/coinbase/create-charge`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.getAuthToken()}`,
          'X-API-Version': this.config.apiVersion,
          'X-CSRF-Token': this.getCSRFToken(),
          'X-Idempotency-Key': `coinbase_${tempPaymentId}_${Date.now()}`
        },
        body: JSON.stringify({
          temp_payment_id: tempPaymentId,
          shipping_info: shippingInfo,
          redirect_url: `${window.location.origin}/checkout/crypto/success`,
          cancel_url: `${window.location.origin}/checkout/crypto/cancel`
        }),
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorBody = await response.json().catch(() => ({}));
        throw new Error(`Coinbase charge creation failed: ${response.status} - ${errorBody.message || 'Unknown error'}`);
      }

      return await response.json();
    } catch (error) {
      clearTimeout(timeoutId);
      throw error;
    }
  }

  /**
   * Get order status
   * @param tempPaymentId - Temporary payment ID
   * @returns Promise with order status
   */
  async getOrderStatus(tempPaymentId: string): Promise<OrderStatusResponse> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);

    try {
      const response = await fetch(`${this.config.baseUrl}/api/orders/${tempPaymentId}/status`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${this.getAuthToken()}`,
          'X-API-Version': this.config.apiVersion,
          'X-Session-ID': this.getSessionId()
        },
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorBody = await response.json().catch(() => ({}));
        throw new Error(`Order status retrieval failed: ${response.status} - ${errorBody.message || 'Unknown error'}`);
      }

      return await response.json() as OrderStatusResponse;
    } catch (error) {
      clearTimeout(timeoutId);
      throw error;
    }
  }

  /**
   * Get authentication token
   * @returns Auth token
   * @private
   */
  private getAuthToken(): string {
    return localStorage.getItem('auth_token') || '';
  }

  /**
   * Get CSRF token
   * @returns CSRF token
   * @private
   */
  private getCSRFToken(): string {
    return localStorage.getItem('csrf_token') || '';
  }

  /**
   * Get session ID
   * @returns Session ID
   * @private
   */
  private getSessionId(): string {
    return localStorage.getItem('session_id') || '';
  }

  /**
   * Get client fingerprint
   * @returns Client fingerprint
   * @private
   */
  private getClientFingerprint(): string {
    const components = [
      navigator.userAgent,
      navigator.language,
      screen.width + 'x' + screen.height,
      new Date().getTimezoneOffset().toString()
    ];
    
    let hash = 0;
    const str = components.join('|');
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return hash.toString(36);
  }
}

/**
 * Create backend API service instance
 * @returns Configured backend API service
 */
export function createBackendApiService(): BackendApiService {
  const config: BackendConfig = {
    baseUrl: import.meta.env.VITE_PAYMENT_API || 'https://85a7dab0-f42c-425c-b5f9-606630150d16-00-3lj5tee1xmhhc.janeway.replit.dev:8080',
    timeout: parseInt(import.meta.env.VITE_API_TIMEOUT || '30000'),
    apiVersion: 'v1'
  };

  return new BackendApiService(config);
}

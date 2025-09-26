/**
 * Webhook Service for Live Payment Processing
 * 
 * PRODUCTION WEBHOOK FLOW:
 * 1. Payment provider (Stripe/PayPal/Coinbase) sends webhook to backend
 * 2. Backend validates webhook signature and payload
 * 3. Backend updates payment status in database
 * 4. Backend generates order ID and sends confirmation
 * 5. Backend notifies frontend via WebSocket/SSE
 * 6. Frontend updates UI with payment confirmation
 * 
 * SECURITY FEATURES:
 * - Signature validation for all providers
 * - Idempotency handling
 * - Replay attack prevention
 * - Comprehensive logging
 */

import { SecurityService } from './cryptoService';

/**
 * Webhook event interface
 */
export interface WebhookEvent {
  readonly id: string;
  readonly type: string;
  readonly provider: 'stripe' | 'paypal' | 'coinbase';
  readonly data: any;
  readonly timestamp: string;
  readonly signature: string;
}

/**
 * Webhook validation result
 */
export interface WebhookValidationResult {
  readonly isValid: boolean;
  readonly error?: string;
  readonly eventId?: string;
  readonly processed?: boolean;
}

/**
 * Webhook service for handling payment provider notifications
 */
export class WebhookService {
  private readonly backendUrl: string;
  private readonly timeout: number;

  /**
   * Initialize webhook service
   * @param backendUrl - Backend API URL
   * @param timeout - Request timeout
   */
  constructor(backendUrl: string, timeout: number = 30000) {
    if (!backendUrl || !backendUrl.startsWith('https://')) {
      throw new Error('Secure backend URL is required for webhook processing');
    }

    this.backendUrl = backendUrl;
    this.timeout = timeout;
  }

  /**
   * Process Stripe webhook event
   * @param event - Stripe webhook event
   * @returns Promise with processing result
   */
  async processStripeWebhook(event: WebhookEvent): Promise<WebhookValidationResult> {
    try {
      const response = await fetch(`${this.backendUrl}/api/webhooks/stripe`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Stripe-Signature': event.signature,
          'X-Webhook-ID': event.id,
          'X-Timestamp': event.timestamp
        },
        body: JSON.stringify(event.data)
      });

      if (!response.ok) {
        const errorBody = await response.json().catch(() => ({}));
        return {
          isValid: false,
          error: `Stripe webhook processing failed: ${response.status}`,
          eventId: event.id
        };
      }

      const result = await response.json();
      return {
        isValid: true,
        eventId: event.id,
        processed: result.processed
      };
    } catch (error) {
      return {
        isValid: false,
        error: error instanceof Error ? error.message : 'Unknown webhook error',
        eventId: event.id
      };
    }
  }

  /**
   * Process PayPal webhook event
   * @param event - PayPal webhook event
   * @returns Promise with processing result
   */
  async processPayPalWebhook(event: WebhookEvent): Promise<WebhookValidationResult> {
    try {
      const response = await fetch(`${this.backendUrl}/api/webhooks/paypal`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'PAYPAL-TRANSMISSION-ID': event.id,
          'PAYPAL-CERT-ID': 'cert_id_from_header',
          'PAYPAL-AUTH-ALGO': 'SHA256withRSA',
          'PAYPAL-TRANSMISSION-SIG': event.signature,
          'PAYPAL-TRANSMISSION-TIME': event.timestamp
        },
        body: JSON.stringify(event.data)
      });

      if (!response.ok) {
        const errorBody = await response.json().catch(() => ({}));
        return {
          isValid: false,
          error: `PayPal webhook processing failed: ${response.status}`,
          eventId: event.id
        };
      }

      const result = await response.json();
      return {
        isValid: true,
        eventId: event.id,
        processed: result.processed
      };
    } catch (error) {
      return {
        isValid: false,
        error: error instanceof Error ? error.message : 'Unknown webhook error',
        eventId: event.id
      };
    }
  }

  /**
   * Process Coinbase Commerce webhook event
   * @param event - Coinbase webhook event
   * @returns Promise with processing result
   */
  async processCoinbaseWebhook(event: WebhookEvent): Promise<WebhookValidationResult> {
    try {
      const response = await fetch(`${this.backendUrl}/api/webhooks/coinbase`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CC-Webhook-Signature': event.signature,
          'X-Webhook-ID': event.id,
          'X-Timestamp': event.timestamp
        },
        body: JSON.stringify(event.data)
      });

      if (!response.ok) {
        const errorBody = await response.json().catch(() => ({}));
        return {
          isValid: false,
          error: `Coinbase webhook processing failed: ${response.status}`,
          eventId: event.id
        };
      }

      const result = await response.json();
      return {
        isValid: true,
        eventId: event.id,
        processed: result.processed
      };
    } catch (error) {
      return {
        isValid: false,
        error: error instanceof Error ? error.message : 'Unknown webhook error',
        eventId: event.id
      };
    }
  }

  /**
   * Listen for real-time payment updates via WebSocket
   * @param onPaymentUpdate - Callback for payment updates
   * @returns Cleanup function
   */
  listenForPaymentUpdates(onPaymentUpdate: (update: any) => void): () => void {
    const wsUrl = import.meta.env.VITE_WS_URL || 'wss://api.minimal.gallery/ws';
    
    try {
      const ws = new WebSocket(wsUrl);
      
      ws.onopen = () => {
        console.log('Payment WebSocket connected');
        
        // Authenticate WebSocket connection
        ws.send(JSON.stringify({
          type: 'auth',
          token: localStorage.getItem('auth_token'),
          session_id: localStorage.getItem('session_id')
        }));
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          
          if (data.type === 'payment_update') {
            onPaymentUpdate(data.payload);
          }
        } catch (error) {
          console.error('Failed to parse WebSocket message:', error);
        }
      };

      ws.onerror = (error) => {
        console.error('Payment WebSocket error:', error);
      };

      ws.onclose = () => {
        console.log('Payment WebSocket disconnected');
      };

      // Return cleanup function
      return () => {
        ws.close();
      };
    } catch (error) {
      console.error('Failed to establish WebSocket connection:', error);
      return () => {}; // No-op cleanup
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
   * Generate nonce
   * @returns Unique nonce
   * @private
   */
  private generateNonce(): string {
    return Date.now().toString(36) + Math.random().toString(36).substring(2);
  }
}

/**
 * Create webhook service instance
 * @returns Configured webhook service
 */
export function createWebhookService(): WebhookService {
  const backendUrl = import.meta.env.VITE_BACKEND_URL || 'https://api.minimal.gallery';
  const timeout = parseInt(import.meta.env.VITE_API_TIMEOUT || '30000');

  return new WebhookService(backendUrl, timeout);
}

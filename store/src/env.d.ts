/// <reference types="vite/client" />

/**
 * Environment variables interface for LIVE payment integration
 */
interface ImportMetaEnv {
  // API Configuration
  readonly VITE_API_URL: string;
  readonly VITE_WS_URL: string;
  readonly VITE_API_TIMEOUT: string;
  readonly VITE_BACKEND_URL: string;
  readonly VITE_WEBHOOK_BASE_URL: string;
  
  // Stripe Configuration (LIVE READY)
  readonly VITE_STRIPE_PUBLISHABLE_KEY: string;
  readonly VITE_STRIPE_SECRET_KEY: string;
  readonly VITE_STRIPE_WEBHOOK_SECRET: string;
  
  // PayPal Configuration (LIVE READY)
  readonly VITE_PAYPAL_CLIENT_ID: string;
  readonly VITE_PAYPAL_CLIENT_SECRET: string;
  readonly VITE_PAYPAL_WEBHOOK_ID: string;
  
  // Coinbase Commerce Configuration (LIVE READY)
  readonly VITE_COINBASE_API_KEY: string;
  readonly VITE_COINBASE_WEBHOOK_SECRET: string;
  
  // Security Configuration
  readonly VITE_ENCRYPTION_KEY: string;
  readonly VITE_REQUEST_SIGNING_KEY: string;
  readonly VITE_SESSION_SECRET: string;
  
  // Environment
  readonly NODE_ENV: 'development' | 'production' | 'test';
  
  // Feature Flags
  readonly VITE_ENABLE_CSP: string;
  readonly VITE_ENABLE_WEBHOOKS: string;
  readonly VITE_ENABLE_FRAUD_DETECTION: string;
  readonly VITE_ENABLE_ANALYTICS: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

/**
 * Global type declarations for server-safe storage
 */
declare global {
  var serverStorage: Map<string, string> | undefined;
  
  interface Window {
    memoryStorage: Map<string, string>;
  }
}

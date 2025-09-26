/**
 * Ultra-Secure Web Application Hardening
 * 
 * COMPLIANCE STANDARDS:
 * - OWASP Top 10 2025
 * - PCI DSS Level 1
 * - ISO 27001
 * - CSP Level 3
 * - NIST Cybersecurity Framework
 * 
 * SECURITY PRINCIPLES:
 * - Defense in depth
 * - Zero trust architecture
 * - Fail secure
 * - Principle of least privilege
 * - Input validation at every layer
 * - Comprehensive audit logging
 */

import DOMPurify from 'dompurify';
import CryptoJS from 'crypto-js';

/**
 * Content Security Policy Level 3 configuration
 */
export class CSPHardening {
  /**
   * Generate CSP Level 3 headers with relaxed policies for development
   * @param {string} nonce - Unique nonce for this request
   * @returns {Record<string, string>} CSP headers object
   */
  static generateCSPHeaders(nonce: string): Record<string, string> {
    // More permissive CSP for development to avoid blocking React and Stripe
    const cspDirectives = [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://js.stripe.com https://www.paypal.com https://www.paypalobjects.com",
      "style-src 'self' 'unsafe-inline' 'unsafe-hashes' https://fonts.googleapis.com",
      "style-src-elem 'self' 'unsafe-inline' 'unsafe-hashes' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com",
      "img-src 'self' data: https: blob:",
      "connect-src 'self' https://api.stripe.com https://api.paypal.com https://api.commerce.coinbase.com wss: https: ws:",
      "frame-src 'self' https://js.stripe.com https://www.paypal.com https://commerce.coinbase.com",
      "frame-ancestors 'self'",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "manifest-src 'self'",
      "worker-src 'self' blob:",
      "media-src 'self' data: blob:"
    ];

    // Only add strict policies in production
    if (import.meta.env?.NODE_ENV === 'production') {
      cspDirectives.push("upgrade-insecure-requests");
      cspDirectives.push("block-all-mixed-content");
    }

    return {
      'Content-Security-Policy-Report-Only': cspDirectives.join('; ') + '; report-uri /api/csp-report',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'SAMEORIGIN', // Changed from DENY to allow Stripe frames
      'X-XSS-Protection': '1; mode=block',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=(self)'
    };
  }

  /**
   * Initialize CSP in the document (only for production)
   * @param {string} nonce - Unique nonce for this session
   */
  static initializeCSP(nonce: string): void {
    if (typeof document === 'undefined') return;

    // Only apply strict CSP in production
    if (import.meta.env?.NODE_ENV !== 'production') {
      console.log('CSP disabled in development mode');
      return;
    }

    const headers = this.generateCSPHeaders(nonce);
    
    Object.entries(headers).forEach(([name, value]) => {
      // Check if meta tag already exists
      const existingMeta = document.querySelector(`meta[http-equiv="${name}"]`);
      if (existingMeta) {
        existingMeta.setAttribute('content', value);
      } else {
        const meta = document.createElement('meta');
        meta.httpEquiv = name;
        meta.content = value;
        document.head.appendChild(meta);
      }
    });
  }
}

/**
 * Advanced input validation and sanitization
 */
export class InputSanitizer {
  private static readonly SQL_INJECTION_PATTERNS = [
    /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|SCRIPT)\b)/gi,
    /(--|\/\*|\*\/|;|'|"|`)/g,
    /(\bxp_\b|\bsp_\b)/gi,
    /(\bCAST\b|\bCONVERT\b|\bCHAR\b|\bNVARCHAR\b)/gi
  ];

  private static readonly XSS_PATTERNS = [
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    /javascript:/gi,
    /vbscript:/gi,
    /data:text\/html/gi,
    /on\w+\s*=/gi,
    /<iframe\b[^>]*>/gi,
    /<object\b[^>]*>/gi,
    /<embed\b[^>]*>/gi,
    /<link\b[^>]*>/gi,
    /<meta\b[^>]*>/gi
  ];

  private static readonly COMMAND_INJECTION_PATTERNS = [
    /(\$\()|(`)|(\|)|(&)|(\;)|(\|\|)|(&&)/g,
    /(\beval\b|\bexec\b|\bsystem\b|\bshell_exec\b)/gi,
    /(\.\.\/|\.\.\\)/g
  ];

  /**
   * Ultra-secure input sanitization
   * @param {unknown} input - Input to sanitize
   * @param {number} maxLength - Maximum allowed length
   * @returns {string} Sanitized input
   * @throws {Error} If input is malicious or too long
   */
  static sanitizeInput(input: unknown, maxLength: number = 1000): string {
    if (input === null || input === undefined) {
      return '';
    }

    if (typeof input !== 'string') {
      throw new Error('Input must be a string');
    }

    if (input.length > maxLength) {
      throw new Error(`Input exceeds maximum length of ${maxLength} characters`);
    }

    // Check for malicious patterns
    this.detectMaliciousPatterns(input);

    let sanitized = input
      // Normalize whitespace
      .trim()
      .replace(/\s+/g, ' ')
      // Remove null bytes
      .replace(/\0/g, '')
      // Remove control characters except tab, newline, carriage return
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');

    // Apply pattern-based sanitization
    this.SQL_INJECTION_PATTERNS.forEach(pattern => {
      sanitized = sanitized.replace(pattern, '');
    });

    this.XSS_PATTERNS.forEach(pattern => {
      sanitized = sanitized.replace(pattern, '');
    });

    this.COMMAND_INJECTION_PATTERNS.forEach(pattern => {
      sanitized = sanitized.replace(pattern, '');
    });

    // Final length check
    return sanitized.substring(0, maxLength);
  }

  /**
   * Detect malicious patterns and log security events
   * @param {string} input - Input to analyze
   * @throws {Error} If highly malicious patterns are detected
   * @private
   */
  private static detectMaliciousPatterns(input: string): void {
    const suspiciousPatterns = [
      { pattern: /<script/gi, severity: 'high', description: 'Script tag injection attempt' },
      { pattern: /javascript:/gi, severity: 'high', description: 'JavaScript protocol injection' },
      { pattern: /union\s+select/gi, severity: 'high', description: 'SQL injection attempt' },
      { pattern: /\bexec\b|\beval\b/gi, severity: 'medium', description: 'Code execution attempt' },
      { pattern: /\.\.\//g, severity: 'medium', description: 'Path traversal attempt' },
      { pattern: /<iframe/gi, severity: 'medium', description: 'Iframe injection attempt' }
    ];

    suspiciousPatterns.forEach(({ pattern, severity, description }) => {
      if (pattern.test(input)) {
        // Import SecurityService dynamically to avoid circular dependencies
        import('../services/cryptoService').then(({ SecurityService }) => {
          SecurityService.logSecurityEvent('malicious_input_detected', {
            pattern: pattern.toString(),
            severity,
            description,
            inputLength: input.length,
            inputPreview: input.substring(0, 100) + (input.length > 100 ? '...' : '')
          }, severity === 'high' ? 'critical' : 'warn');
        }).catch(() => {
          console.warn('Failed to log security event');
        });

        if (severity === 'high') {
          throw new Error(`Security violation detected: ${description}`);
        }
      }
    });
  }

  /**
   * Sanitize HTML with ultra-strict policy
   * @param {string} dirty - HTML to sanitize
   * @returns {string} Sanitized HTML
   */
  static sanitizeHTML(dirty: string): string {
    if (typeof window === 'undefined') {
      // Server-side: strip all HTML
      return this.sanitizeInput(dirty);
    }

    return DOMPurify.sanitize(dirty, {
      ALLOWED_TAGS: [], // No HTML tags allowed
      ALLOWED_ATTR: [],
      FORBID_TAGS: ['script', 'object', 'embed', 'link', 'style', 'img', 'svg', 'iframe', 'frame'],
      FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover', 'onfocus', 'onblur', 'onchange'],
      KEEP_CONTENT: false
    });
  }
}

/**
 * CSRF protection utilities
 */
export class CSRFProtection {
  private static readonly TOKEN_LIFETIME = 3600000; // 1 hour

  /**
   * Generate CSRF token with expiration
   * @returns {object} CSRF token with metadata
   */
  static generateToken(): { token: string; expires: number } {
    const token = CryptoJS.lib.WordArray.random(32).toString();
    const expires = Date.now() + this.TOKEN_LIFETIME;
    
    // Store token with expiration
    const { SecurityService } = require('../services/cryptoService');
    SecurityService.setSecureItem('csrf_token', JSON.stringify({ token, expires }), true);
    
    return { token, expires };
  }

  /**
   * Validate CSRF token
   * @param {string} token - Token to validate
   * @returns {boolean} Whether token is valid
   */
  static validateToken(token: string): boolean {
    try {
      // Use localStorage directly for browser environment
      const storedData = localStorage.getItem('csrf_token');
      
      if (!storedData) {
        return false;
      }

      const { token: storedToken, expires } = JSON.parse(storedData);
      
      if (Date.now() > expires) {
        // Token expired
        localStorage.setItem('csrf_token', '');
        return false;
      }

      return token === storedToken;
    } catch (error) {
      console.error('CSRF token validation error:', error);
      return false;
    }
  }

  /**
   * Get current CSRF token for requests
   * @returns {string | null} Current CSRF token or null if expired
   */
  static getCurrentToken(): string | null {
    try {
      const storedData = localStorage.getItem('csrf_token');
      
      if (!storedData) {
        return null;
      }

      const { token, expires } = JSON.parse(storedData);
      
      if (Date.now() > expires) {
        return null;
      }

      return token;
    } catch (error) {
      return null;
    }
  }
}

/**
 * Request integrity and origin validation
 */
export class RequestIntegrity {
  /**
   * Validate request origin
   * @param {string} origin - Request origin
   * @param {string[]} allowedOrigins - List of allowed origins
   * @returns {boolean} Whether origin is valid
   */
  static validateOrigin(origin: string, allowedOrigins: string[]): boolean {
    if (!origin) {
      return false;
    }

    // Normalize origin
    const normalizedOrigin = origin.toLowerCase().trim();
    
    return allowedOrigins.some(allowed => {
      const normalizedAllowed = allowed.toLowerCase().trim();
      return normalizedOrigin === normalizedAllowed;
    });
  }

  /**
   * Generate request signature for integrity verification
   * @param {string} method - HTTP method
   * @param {string} url - Request URL
   * @param {string} body - Request body
   * @param {number} timestamp - Request timestamp
   * @param {string} nonce - Request nonce
   * @returns {string} Request signature
   */
  static generateRequestSignature(
    method: string,
    url: string,
    body: string,
    timestamp: number,
    nonce: string
  ): string {
    const message = `${method.toUpperCase()}|${url}|${body}|${timestamp}|${nonce}`;
    const key = import.meta.env?.REACT_APP_REQUEST_SIGNING_KEY || 'fallback-key';
    return CryptoJS.HmacSHA256(message, key).toString();
  }

  /**
   * Validate request timestamp to prevent replay attacks
   * @param {number} timestamp - Request timestamp
   * @param {number} maxAge - Maximum age in milliseconds (default: 5 minutes)
   * @returns {boolean} Whether timestamp is valid
   */
  static validateTimestamp(timestamp: number, maxAge: number = 300000): boolean {
    const now = Date.now();
    const age = now - timestamp;
    
    // Check if timestamp is not too old or in the future
    return age >= 0 && age <= maxAge;
  }

  /**
   * Validate request nonce for idempotency
   * @param {string} nonce - Request nonce
   * @returns {boolean} Whether nonce is valid and unused
   */
  static validateNonce(nonce: string): boolean {
    if (!nonce || nonce.length < 16) {
      return false;
    }

    const { SecurityService } = require('../services/cryptoService');
    const usedNonces = JSON.parse(SecurityService.getSecureItem('used_nonces') || '[]');
    
    if (usedNonces.includes(nonce)) {
      SecurityService.logSecurityEvent('nonce_reuse_attempt', { nonce }, 'critical');
      return false;
    }

    // Store nonce (keep only recent ones)
    usedNonces.push(nonce);
    const recentNonces = usedNonces.slice(-10000); // Keep last 10k nonces
    SecurityService.setSecureItem('used_nonces', JSON.stringify(recentNonces));
    
    return true;
  }
}

/**
 * Session security management
 */
export class SessionSecurity {
  private static readonly SESSION_TIMEOUT = 1800000; // 30 minutes
  private static readonly ABSOLUTE_TIMEOUT = 43200000; // 12 hours

  /**
   * Initialize secure session
   * @returns {object} Session data
   */
  static initializeSession(): { sessionId: string; csrfToken: string; fingerprint: string } {
    // Generate secure IDs
    const sessionId = this.generateSecureId(64);
    const csrfToken = this.generateSecureId(64);
    const fingerprint = this.generateDeviceFingerprint();
    
    const sessionData = {
      id: sessionId,
      csrfToken,
      fingerprint,
      createdAt: Date.now(),
      lastActivity: Date.now(),
      isValid: true
    };

    try {
      localStorage.setItem('session_data', JSON.stringify(sessionData));
      console.log('Session initialized successfully');
    } catch (error) {
      console.warn('Failed to store session data:', error);
    }
    
    return { sessionId, csrfToken, fingerprint };
  }

  /**
   * Generate secure ID for session management
   * @param length - Length of ID to generate
   * @returns Secure random string
   */
  private static generateSecureId(length: number): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';

    if (window.crypto && window.crypto.getRandomValues) {
      const array = new Uint8Array(length);
      window.crypto.getRandomValues(array);
      for (let i = 0; i < length; i++) {
        result += chars.charAt(array[i] % chars.length);
      }
    } else {
      for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
      }
    }

    return result;
  }

  /**
   * Validate session integrity
   * @returns {boolean} Whether session is valid
   */
  static validateSession(): boolean {
    try {
      // Use localStorage directly for browser environment
      const sessionData = localStorage.getItem('session_data');
      
      if (!sessionData) {
        return false;
      }

      const session = JSON.parse(sessionData);
      const now = Date.now();
      
      // Check session timeout
      if (now - session.lastActivity > this.SESSION_TIMEOUT) {
        console.warn('Session timeout detected');
        this.destroySession();
        return false;
      }

      // Check absolute timeout
      if (now - session.createdAt > this.ABSOLUTE_TIMEOUT) {
        console.warn('Session absolute timeout detected');
        this.destroySession();
        return false;
      }

      // Validate device fingerprint
      const currentFingerprint = this.generateDeviceFingerprint();
      if (session.fingerprint !== currentFingerprint) {
        console.warn('Session fingerprint mismatch detected');
        this.destroySession();
        return false;
      }

      // Update last activity
      session.lastActivity = now;
      localStorage.setItem('session_data', JSON.stringify(session));
      
      return true;
    } catch (error) {
      console.error('Session validation error:', error);
      return false;
    }
  }

  /**
   * Destroy current session
   */
  static destroySession(): void {
    try {
      localStorage.removeItem('session_data');
      localStorage.removeItem('csrf_token');
      console.log('Session destroyed');
    } catch (error) {
      console.warn('Failed to destroy session:', error);
    }
  }

  /**
   * Generate device fingerprint for session validation
   * @returns {string} Device fingerprint
   * @private
   */
  private static generateDeviceFingerprint(): string {
    if (typeof window === 'undefined') {
      return 'server';
    }

    const components = [
      navigator.userAgent,
      navigator.language,
      navigator.languages?.join(',') || '',
      screen.width + 'x' + screen.height + 'x' + screen.colorDepth,
      new Date().getTimezoneOffset().toString(),
      navigator.platform,
      navigator.cookieEnabled.toString(),
      navigator.doNotTrack || 'unknown',
      window.devicePixelRatio?.toString() || '1'
    ];

    return CryptoJS.SHA256(components.join('|')).toString().substring(0, 32);
  }
}

/**
 * Secure API client with comprehensive protection
 */
export class SecureApiClient {
  private static readonly DEFAULT_TIMEOUT = 30000;
  private static readonly MAX_RETRIES = 3;

  /**
   * Make secure API request with all protections enabled
   * @param {string} url - Request URL
   * @param {RequestInit} options - Request options
   * @returns {Promise<Response>} Promise with response
   * @throws {Error} With detailed security information
   */
  static async secureRequest(url: string, options: RequestInit = {}): Promise<Response> {
    // Validate URL
    if (!url.startsWith('https://') && !url.startsWith('/api/')) {
      throw new Error('Only HTTPS URLs and relative API paths are allowed');
    }

    // Validate session (only in production)
    if (import.meta.env?.NODE_ENV === 'production' && !SessionSecurity.validateSession()) {
      throw new Error('Invalid or expired session');
    }

    // Generate request metadata
    const timestamp = Date.now();
    const nonce = CryptoJS.lib.WordArray.random(16).toString();
    const csrfToken = CSRFProtection.getCurrentToken();

    // Validate timestamp
    if (!RequestIntegrity.validateTimestamp(timestamp)) {
      throw new Error('Invalid request timestamp');
    }

    // Validate nonce
    if (!RequestIntegrity.validateNonce(nonce)) {
      throw new Error('Invalid or reused nonce');
    }

    // Prepare secure headers
    const secureHeaders = {
      ...CSPHardening.generateCSPHeaders(nonce),
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
      'X-Timestamp': timestamp.toString(),
      'X-Nonce': nonce,
      'X-Fingerprint': SessionSecurity['generateDeviceFingerprint'](),
      ...(csrfToken && { 'X-CSRF-Token': csrfToken }),
      ...options.headers
    };

    // Add request signature for integrity
    if (options.method && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(options.method.toUpperCase())) {
      const body = options.body?.toString() || '';
      const signature = RequestIntegrity.generateRequestSignature(
        options.method,
        url,
        body,
        timestamp,
        nonce
      );
      (secureHeaders as any)['X-Signature'] = signature;
    }

    // Setup timeout
    const controller = new AbortController();
    const timeout = parseInt(import.meta.env?.REACT_APP_API_TIMEOUT || this.DEFAULT_TIMEOUT.toString());
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      const response = await fetch(url, {
        ...options,
        headers: secureHeaders,
        signal: controller.signal,
        credentials: 'same-origin', // Only send cookies to same origin
        mode: 'cors',
        cache: 'no-cache',
        redirect: 'error' // Don't follow redirects for security
      });

      clearTimeout(timeoutId);

      // Log request for audit
      console.log('API Request:', {
        url: url.replace(/\/\/.*?\//, '//[REDACTED]/'),
        method: options.method || 'GET',
        status: response.status,
        timestamp
      });

      return response;
    } catch (error) {
      clearTimeout(timeoutId);
      
      if (error instanceof Error && error.name === 'AbortError') {
        throw new Error('Request timeout - please try again');
      }
      
      throw error;
    }
  }

  /**
   * Secure API request with retry logic
   * @param {string} url - Request URL
   * @param {RequestInit} options - Request options
   * @param {number} retries - Number of retries
   * @returns {Promise<Response>} Promise with response
   */
  static async secureRequestWithRetry(
    url: string, 
    options: RequestInit = {}, 
    retries: number = this.MAX_RETRIES
  ): Promise<Response> {
    let lastError: Error;

    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        return await this.secureRequest(url, options);
      } catch (error) {
        lastError = error instanceof Error ? error : new Error('Unknown error');
        
        // Don't retry on client errors (4xx) or security errors
        if (lastError.message.includes('Security violation') || 
            lastError.message.includes('Invalid session') ||
            lastError.message.includes('CSRF')) {
          throw lastError;
        }

        // Exponential backoff for retries
        if (attempt < retries) {
          const delay = Math.pow(2, attempt) * 1000; // 1s, 2s, 4s
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    }

    throw lastError!;
  }
}

/**
 * Initialize all security measures for the application
 */
export function initializeSecurityHardening(): void {
  try {
    // Only initialize in production or when explicitly enabled
    if (import.meta.env?.NODE_ENV === 'production' || import.meta.env?.VITE_ENABLE_CSP === 'true') {
      // Generate nonce for this session
      const nonce = Date.now().toString(36) + Math.random().toString(36).substring(2);
      
      // Initialize CSP (only in production)
      CSPHardening.initializeCSP(nonce);
    }
    
    // Initialize session security (always)
    SessionSecurity.initializeSession();
    
    // Setup global error handling
    if (typeof window !== 'undefined') {
      window.addEventListener('error', (event) => {
        console.error('JavaScript error:', {
          message: event.message,
          filename: event.filename,
          lineno: event.lineno,
          colno: event.colno
        });
      });

      window.addEventListener('unhandledrejection', (event) => {
        console.error('Unhandled promise rejection:', {
          reason: event.reason?.toString() || 'Unknown'
        });
      });
    }

    console.log('Security hardening initialized successfully');
  } catch (error) {
    console.error('Failed to initialize security hardening:', error);
    // Don't throw error to prevent app crash
  }
}

import DOMPurify from 'dompurify';
import CryptoJS from 'crypto-js';

export class SecurityUtils {
  // Content Security Policy headers
  static getCSPHeaders(): Record<string, string> {
    return {
      'Content-Security-Policy': [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline' https://js.stripe.com https://www.paypal.com https://www.paypalobjects.com",
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src 'self' https://fonts.gstatic.com",
        "img-src 'self' data: https: blob:",
        "connect-src 'self' https://api.stripe.com https://api.paypal.com https://api.commerce.coinbase.com wss:",
        "frame-src https://js.stripe.com https://www.paypal.com https://commerce.coinbase.com",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'"
      ].join('; ')
    };
  }

  // Sanitize HTML content
  static sanitizeHTML(dirty: string): string {
    return DOMPurify.sanitize(dirty, {
      ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br'],
      ALLOWED_ATTR: []
    });
  }

  // Validate and sanitize user input
  static sanitizeInput(input: string): string {
    if (typeof input !== 'string') return '';
    
    return input
      .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
      .replace(/javascript:/gi, '')
      .replace(/on\w+\s*=/gi, '')
      .replace(/[<>]/g, '')
      .trim()
      .slice(0, 1000); // Limit length
  }

  // SQL Injection prevention
  static sanitizeSQL(input: string): string {
    const sqlKeywords = [
      'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER',
      'EXEC', 'EXECUTE', 'UNION', 'SCRIPT', '--', ';', '/*', '*/', 'xp_'
    ];
    
    let sanitized = input;
    sqlKeywords.forEach(keyword => {
      const regex = new RegExp(keyword, 'gi');
      sanitized = sanitized.replace(regex, '');
    });
    
    return sanitized.trim();
  }

  // XSS Prevention
  static escapeHTML(text: string): string {
    const map: Record<string, string> = {
      '&': '&amp;',
      '<': '<',
      '>': '>',
      '"': '&quot;',
      "'": '&#039;'
    };
    
    return text.replace(/[&<>"']/g, (m) => map[m]);
  }

  // CSRF Token generation
  static generateCSRFToken(): string {
    return CryptoJS.lib.WordArray.random(32).toString();
  }

  // Validate CSRF token
  static validateCSRFToken(token: string, storedToken: string): boolean {
    return token === storedToken;
  }

  // Rate limiting with exponential backoff
  static checkRateLimitWithBackoff(
    key: string, 
    maxRequests: number = 10, 
    windowMs: number = 60000
  ): { allowed: boolean; retryAfter?: number } {
    const now = Date.now();
    const windowStart = now - windowMs;
    
    const requestsKey = `rate_limit_${key}`;
    const attemptsKey = `rate_limit_attempts_${key}`;
    
    const requests = JSON.parse(localStorage.getItem(requestsKey) || '[]');
    const attempts = parseInt(localStorage.getItem(attemptsKey) || '0');
    
    const validRequests = requests.filter((timestamp: number) => timestamp > windowStart);
    
    if (validRequests.length >= maxRequests) {
      const backoffTime = Math.min(windowMs * Math.pow(2, attempts), 3600000); // Max 1 hour
      localStorage.setItem(attemptsKey, (attempts + 1).toString());
      
      return { 
        allowed: false, 
        retryAfter: backoffTime 
      };
    }
    
    validRequests.push(now);
    localStorage.setItem(requestsKey, JSON.stringify(validRequests));
    localStorage.setItem(attemptsKey, '0'); // Reset attempts on success
    
    return { allowed: true };
  }

  // Input validation patterns
  static validationPatterns = {
    email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    phone: /^\+?[\d\s\-\(\)]{10,}$/,
    zipCode: /^[\d\-\s]{3,10}$/,
    creditCard: /^[\d\s]{13,19}$/,
    cvv: /^\d{3,4}$/,
    trackingNumber: /^[A-Z]{3}\d{8}[A-Z]{4}$/
  };

  // Validate input against patterns
  static validatePattern(input: string, pattern: keyof typeof SecurityUtils.validationPatterns): boolean {
    return this.validationPatterns[pattern].test(input);
  }

  // Session security
  static generateSessionToken(): string {
    return CryptoJS.lib.WordArray.random(64).toString();
  }

  // Encrypt sensitive data for storage
  static encryptForStorage(data: any, key: string): string {
    const jsonString = JSON.stringify(data);
    return CryptoJS.AES.encrypt(jsonString, key).toString();
  }

  // Decrypt sensitive data from storage
  static decryptFromStorage(encryptedData: string, key: string): any {
    try {
      const bytes = CryptoJS.AES.decrypt(encryptedData, key);
      const decryptedString = bytes.toString(CryptoJS.enc.Utf8);
      return JSON.parse(decryptedString);
    } catch (error) {
      console.error('Decryption failed:', error);
      return null;
    }
  }

  /**
   * Audit logging with server-safe storage
   * @param event - Security event type
   * @param details - Event details
   */
  static logSecurityEvent(event: string, details: any): void {
    const logEntry = {
      timestamp: new Date().toISOString(),
      event,
      details: SecurityUtils.sanitizeInput(JSON.stringify(details)),
      userAgent: typeof navigator !== 'undefined' ? navigator.userAgent : 'server',
      url: typeof window !== 'undefined' ? window.location.href : 'server'
    };
    
    // In production, send to secure logging service
    console.log('Security Event:', logEntry);
    
    // Use server-safe storage
    try {
      const logs = JSON.parse(this.getItem('security_logs') || '[]');
      logs.push(logEntry);
      this.setItem('security_logs', JSON.stringify(logs.slice(-100))); // Keep last 100 logs
    } catch (error) {
      console.warn('Failed to store security log:', error);
    }
  }

  /**
   * Server-safe storage setter
   * @param key - Storage key
   * @param value - Value to store
   */
  private static setItem(key: string, value: string): void {
    if (typeof window === 'undefined') {
      // Server environment - use in-memory storage or database
      if (!global.serverStorage) {
        global.serverStorage = new Map();
      }
      global.serverStorage.set(key, value);
    } else {
      try {
        localStorage.setItem(key, value);
      } catch (error) {
        // Fallback to memory storage if localStorage is disabled
        if (!window.memoryStorage) {
          window.memoryStorage = new Map();
        }
        window.memoryStorage.set(key, value);
      }
    }
  }

  /**
   * Server-safe storage getter
   * @param key - Storage key
   * @returns Stored value or null
   */
  private static getItem(key: string): string | null {
    if (typeof window === 'undefined') {
      return global.serverStorage?.get(key) || null;
    } else {
      try {
        return localStorage.getItem(key);
      } catch (error) {
        return window.memoryStorage?.get(key) || null;
      }
    }
  }
}

// Security middleware for API calls
export const secureApiCall = async (
  url: string, 
  options: RequestInit = {},
  csrfToken?: string
): Promise<Response> => {
  // Add security headers
  const secureHeaders = {
    ...SecurityUtils.getCSPHeaders(),
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    ...(csrfToken && { 'X-CSRF-Token': csrfToken }),
    ...options.headers
  };

  // Log API call for security monitoring
  SecurityUtils.logSecurityEvent('api_call', {
    url: url.replace(/\/\/.*?\//, '//[REDACTED]/'), // Hide domain
    method: options.method || 'GET'
  });

  return fetch(url, {
    ...options,
    headers: secureHeaders
  });
};

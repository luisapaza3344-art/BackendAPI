/**
 * Validation result interface
 */
export interface ValidationResult {
  isValid: boolean;
  error?: string;
  code?: string;
}

/**
 * Valid email domains for security validation
 */
const VALID_EMAIL_DOMAINS = [
  'gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 'yahoo.es', 'yahoo.co.uk',
  'icloud.com', 'me.com', 'mac.com', 'aol.com', 'protonmail.com', 'tutanota.com',
  'zoho.com', 'yandex.com', 'mail.com', 'gmx.com', 'live.com', 'msn.com',
  'comcast.net', 'verizon.net', 'att.net', 'sbcglobal.net', 'cox.net',
  'earthlink.net', 'charter.net', 'optonline.net', 'rocketmail.com',
  'bellsouth.net', 'roadrunner.com', 'windstream.net', 'minimal.gallery', 'example.com'
];

/**
 * Validate email address with domain checking
 * @param email - Email address to validate
 * @returns Validation result with error details
 */
export const validateEmail = (email: string): ValidationResult => {
  if (!email) {
    return { isValid: false, error: 'Email is required', code: 'REQUIRED' };
  }

  // Remove extra spaces
  const trimmedEmail = email.trim();

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(trimmedEmail)) {
    return { isValid: false, error: 'Please enter a valid email address', code: 'INVALID_FORMAT' };
  }

  const domain = trimmedEmail.split('@')[1]?.toLowerCase();
  if (!VALID_EMAIL_DOMAINS.includes(domain)) {
    return { 
      isValid: false, 
      error: 'Please use a valid email provider (Gmail, Outlook, Yahoo, etc.)',
      code: 'INVALID_DOMAIN'
    };
  }

  return { isValid: true };
};

/**
 * Credit card validation result interface
 */
export interface CardValidationResult extends ValidationResult {
  cardType?: string;
}

/**
 * Validate credit card number using Luhn algorithm
 * @param cardNumber - Credit card number to validate
 * @returns Validation result with card type
 */
export const validateCreditCard = (cardNumber: string): CardValidationResult => {
  if (!cardNumber) {
    return { isValid: false, error: 'Card number is required', code: 'REQUIRED' };
  }

  // Remove extra spaces and non-digits
  const cleanNumber = cardNumber.replace(/\D/g, '');

  // Check length
  if (cleanNumber.length < 13 || cleanNumber.length > 19) {
    return { 
      isValid: false, 
      error: 'Card number must be between 13-19 digits',
      code: 'INVALID_LENGTH'
    };
  }

  // Luhn algorithm validation
  if (!luhnCheck(cleanNumber)) {
    return { 
      isValid: false, 
      error: 'Invalid card number',
      code: 'INVALID_CHECKSUM'
    };
  }

  // Determine card type
  const cardType = getCardType(cleanNumber);
  
  return { isValid: true, cardType };
};

// Luhn algorithm for credit card validation
const luhnCheck = (cardNumber: string): boolean => {
  let sum = 0;
  let isEven = false;

  for (let i = cardNumber.length - 1; i >= 0; i--) {
    let digit = parseInt(cardNumber.charAt(i), 10);

    if (isEven) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }

    sum += digit;
    isEven = !isEven;
  }

  return sum % 10 === 0;
};

// Determine card type based on number
const getCardType = (cardNumber: string): string => {
  const patterns = {
    visa: /^4[0-9]{12}(?:[0-9]{3})?$/,
    mastercard: /^5[1-5][0-9]{14}$/,
    amex: /^3[47][0-9]{13}$/,
    discover: /^6(?:011|5[0-9]{2})[0-9]{12}$/,
    diners: /^3[0689][0-9]{11}$/,
    jcb: /^(?:2131|1800|35\d{3})\d{11}$/
  };

  for (const [type, pattern] of Object.entries(patterns)) {
    if (pattern.test(cardNumber)) {
      return type.charAt(0).toUpperCase() + type.slice(1);
    }
  }

  return 'Unknown';
};

// Expiry date validation
export const validateExpiryDate = (expiryDate: string): { isValid: boolean; error?: string } => {
  if (!expiryDate) {
    return { isValid: false, error: 'Expiry date is required' };
  }

  const regex = /^(0[1-9]|1[0-2])\/([0-9]{2})$/;
  if (!regex.test(expiryDate)) {
    return { isValid: false, error: 'Please enter date in MM/YY format' };
  }

  const [month, year] = expiryDate.split('/');
  const currentDate = new Date();
  const currentYear = currentDate.getFullYear() % 100;
  const currentMonth = currentDate.getMonth() + 1;

  const expYear = parseInt(year, 10);
  const expMonth = parseInt(month, 10);

  if (expYear < currentYear || (expYear === currentYear && expMonth < currentMonth)) {
    return { isValid: false, error: 'Card has expired' };
  }

  return { isValid: true };
};

// CVV validation
export const validateCVV = (cvv: string, cardType?: string): { isValid: boolean; error?: string } => {
  if (!cvv) {
    return { isValid: false, error: 'CVV is required' };
  }

  const cleanCVV = cvv.replace(/\D/g, '');
  
  // American Express uses 4 digits, others use 3
  const expectedLength = cardType === 'Amex' ? 4 : 3;
  
  if (cleanCVV.length !== expectedLength) {
    return { 
      isValid: false, 
      error: `CVV must be ${expectedLength} digits for ${cardType || 'this card type'}` 
    };
  }

  return { isValid: true };
};

// Phone validation
export const validatePhone = (phone: string): { isValid: boolean; error?: string } => {
  if (!phone) {
    return { isValid: false, error: 'Phone number is required' };
  }

  const cleanPhone = phone.replace(/\D/g, '');
  
  if (cleanPhone.length < 10 || cleanPhone.length > 15) {
    return { isValid: false, error: 'Please enter a valid phone number' };
  }

  return { isValid: true };
};

/**
 * Format card number with spaces (removes extra spaces first)
 * @param value - Raw card number input
 * @returns Formatted card number with spaces
 */
export const formatCardNumber = (value: string): string => {
  const cleanValue = value.replace(/\D/g, '');
  const groups = cleanValue.match(/.{1,4}/g) || [];
  return groups.join(' ').substring(0, 23); // Max 19 digits + 4 spaces
};

/**
 * Format expiry date as MM/YY (removes extra spaces)
 * @param value - Raw expiry date input
 * @returns Formatted expiry date
 */
export const formatExpiryDate = (value: string): string => {
  const cleanValue = value.replace(/\D/g, '');
  if (cleanValue.length >= 2) {
    return cleanValue.substring(0, 2) + '/' + cleanValue.substring(2, 4);
  }
  return cleanValue;
};

/**
 * Format phone number as (XXX) XXX-XXXX (removes extra spaces)
 * @param value - Raw phone number input
 * @returns Formatted phone number
 */
export const formatPhoneNumber = (value: string): string => {
  const cleanValue = value.replace(/\D/g, '');
  if (cleanValue.length >= 6) {
    return `(${cleanValue.substring(0, 3)}) ${cleanValue.substring(3, 6)}-${cleanValue.substring(6, 10)}`;
  } else if (cleanValue.length >= 3) {
    return `(${cleanValue.substring(0, 3)}) ${cleanValue.substring(3)}`;
  }
  return cleanValue;
};

/**
 * Comprehensive input sanitization
 * @param input - User input to sanitize
 * @returns Sanitized input string
 */
export const sanitizeInput = (input: string): string => {
  if (typeof input !== 'string') return '';
  
  return input
    .trim() // Remove extra spaces
    .replace(/\s+/g, ' ') // Replace multiple spaces with single space
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    .replace(/javascript:/gi, '')
    .replace(/on\w+\s*=/gi, '')
    .replace(/[<>]/g, '')
    .slice(0, 1000); // Limit length
};

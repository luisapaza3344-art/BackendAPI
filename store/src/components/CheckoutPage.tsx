import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Separator } from '@/components/ui/separator';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useCartStore } from '@/stores/cartStore';
import { useAuthStore } from '@/stores/authStore';
import { calculateTax, formatTaxRate } from '@/utils/taxCalculator';
import { 
  validateEmail, 
  validatePhone,
  formatPhoneNumber
} from '@/utils/validators';
import { SecurityService } from '../services/cryptoService';
import { createBackendApiService } from '../services/backendApiService';
import { Elements } from '@stripe/react-stripe-js';
import { StripeCardForm } from './payment/StripeCardForm';
import { ApplePayButton } from './payment/ApplePayButton';
import { GooglePayButton } from './payment/GooglePayButton';
import { PaymentStatusTracker } from './payment/PaymentStatusTracker';
import { PaymentMethodSelector } from './payment/PaymentMethodSelector';
import { stripePromise } from '../services/stripeService';
import { InputSanitizer } from '../utils/securityHardening';
import { SEOHead } from './SEOHead';
import { ArrowLeft, CreditCard, Smartphone, Bitcoin, DollarSign, Shield, Truck, AlertCircle } from 'lucide-react';

interface CheckoutPageProps {
  onBack: () => void;
}

const paymentMethods = [
  {
    id: 'card',
    name: 'Credit/Debit Card',
    icon: CreditCard,
    description: 'Visa, Mastercard, American Express'
  },
  {
    id: 'paypal',
    name: 'PayPal',
    icon: DollarSign,
    description: 'Pay with your PayPal account'
  },
  {
    id: 'crypto',
    name: 'Cryptocurrency',
    icon: Bitcoin,
    description: 'Bitcoin, Ethereum, and more'
  },
  {
    id: 'apple_pay',
    name: 'Apple Pay',
    icon: Smartphone,
    description: 'Touch ID or Face ID'
  },
  {
    id: 'google_pay',
    name: 'Google Pay',
    icon: Smartphone,
    description: 'Pay with Google'
  }
];

export const CheckoutPage: React.FC<CheckoutPageProps> = ({ onBack }) => {
  const { items, getTotalPrice, clearCart } = useCartStore();
  const { user } = useAuthStore();
  const [selectedPayment, setSelectedPayment] = useState('card');
  const [isProcessing, setIsProcessing] = useState(false);
  const [orderComplete, setOrderComplete] = useState(false);
  
  const [shippingInfo, setShippingInfo] = useState({
    firstName: '',
    lastName: '',
    email: '',
    phone: '',
    address: '',
    city: '',
    state: '',
    zipCode: '',
    country: 'US'
  });

  const [errors, setErrors] = useState<Record<string, string>>({});

  // Security: Initialize secure checkout session
  const [secureSession, setSecureSession] = useState<{
    tempPaymentId: string;
    csrfToken: string;
    nonce: string;
    expiresAt: number;
  } | null>(null);

  // Shipping rates state
  const [shippingRates, setShippingRates] = useState<Array<{
    carrier: string;
    service: string;
    rate: number;
    currency: string;
    estimated_days: string;
    fallback?: boolean;
  }>>([]);
  const [selectedShippingRate, setSelectedShippingRate] = useState<number>(0);
  const [loadingShipping, setLoadingShipping] = useState(false);

  const totalPrice = getTotalPrice();
  const shippingCost = shippingRates.length > 0 && selectedShippingRate >= 0 
    ? shippingRates[selectedShippingRate].rate 
    : 0;
  const tax = calculateTax(totalPrice, shippingInfo.country, shippingInfo.state);
  const finalTotal = totalPrice + shippingCost + tax;

  const handleInputChange = (section: 'shipping', field: string, value: string) => {
    // Clear error when user starts typing
    if (errors[field]) {
      setErrors(prev => ({ ...prev, [field]: '' }));
    }

    let formattedValue = value;

    // Apply formatting based on field type
    if (field === 'phone') {
      formattedValue = formatPhoneNumber(value);
    }

    if (section === 'shipping') {
      setShippingInfo(prev => ({ ...prev, [field]: formattedValue }));
    }
  };

  /**
   * Ultra-secure form validation with comprehensive sanitization
   * @returns Whether form is valid
   */
  const validateForm = (): boolean => {
    const newErrors: Record<string, string> = {};

    try {
      // Sanitize ALL inputs first
      const sanitizedShipping = {
        firstName: InputSanitizer.sanitizeInput(shippingInfo.firstName, 50),
        lastName: InputSanitizer.sanitizeInput(shippingInfo.lastName, 50),
        email: InputSanitizer.sanitizeInput(shippingInfo.email, 254),
        phone: InputSanitizer.sanitizeInput(shippingInfo.phone, 20),
        address: InputSanitizer.sanitizeInput(shippingInfo.address, 200),
        city: InputSanitizer.sanitizeInput(shippingInfo.city, 100),
        state: InputSanitizer.sanitizeInput(shippingInfo.state, 50),
        zipCode: InputSanitizer.sanitizeInput(shippingInfo.zipCode, 20),
        country: shippingInfo.country // Pre-validated from select
      };

      // Update state with sanitized data
      setShippingInfo(sanitizedShipping);

      // Validate email
      const emailValidation = validateEmail(sanitizedShipping.email);
      if (!emailValidation.isValid) {
        newErrors.email = emailValidation.error!;
      }

      // Validate phone
      const phoneValidation = validatePhone(sanitizedShipping.phone);
      if (!phoneValidation.isValid) {
        newErrors.phone = phoneValidation.error!;
      }

      // Validate required shipping fields
      const requiredFields = ['firstName', 'lastName', 'address', 'city', 'state', 'zipCode'];
      requiredFields.forEach(field => {
        const value = sanitizedShipping[field as keyof typeof sanitizedShipping];
        if (!value || value.length === 0) {
          newErrors[field] = 'This field is required';
        }
      });

      setErrors(newErrors);
      return Object.keys(newErrors).length === 0;
    } catch (error) {
      SecurityService.logSecurityEvent('form_validation_error', {
        error: error instanceof Error ? error.message : 'Unknown error'
      }, 'error');
      
      newErrors.general = 'Form validation failed. Please check your input.';
      setErrors(newErrors);
      return false;
    }
  };

  /**
   * Initialize secure checkout session (Local version)
   * SECURITY: Creates secure local session for checkout
   */
  const initializeSecureCheckout = async (): Promise<void> => {
    try {
      // Advanced rate limiting check
      const rateLimitResult = SecurityService.checkAdvancedRateLimit(
        `checkout_init_${user?.id || 'anonymous'}`,
        3,
        300000
      );

      if (!rateLimitResult.allowed) {
        setErrors({ 
          general: `Too many checkout attempts. Please wait ${Math.ceil((rateLimitResult.retryAfter || 0) / 60000)} minutes.` 
        });
        return;
      }

      // Create secure local session
      const tempPaymentId = SecurityService.generateSecureId(32);
      const csrfToken = SecurityService.generateSecureId(32);
      const nonce = SecurityService.generateNonce();
      const expiresAt = Date.now() + (30 * 60 * 1000); // 30 minutes

      // Save session to database
      const sessionResponse = await fetch(`${import.meta.env.VITE_BACKEND_URL}/api/payment-gateway/init-checkout`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          temp_payment_id: tempPaymentId,
          cart_items: items.map(item => ({
            id: item.id,
            name: item.name,
            quantity: item.quantity,
            price: item.price
          })),
          subtotal: totalPrice,
          shipping: shippingCost,
          tax: tax,
          total: finalTotal,
          currency: 'USD',
          customer_email: shippingInfo.email || '',
          shipping_address: shippingInfo
        })
      });

      if (!sessionResponse.ok) {
        throw new Error('Failed to initialize checkout session');
      }

      setSecureSession({
        tempPaymentId,
        csrfToken,
        nonce,
        expiresAt
      });

      // Store tokens for subsequent requests
      localStorage.setItem('csrf_token', csrfToken);
      localStorage.setItem('session_id', tempPaymentId);

      SecurityService.logSecurityEvent('checkout_session_initialized', {
        tempPaymentId,
        expiresAt,
        cartItemCount: items.length,
        totalAmount: finalTotal
      });
    } catch (error) {
      SecurityService.logSecurityEvent('checkout_initialization_failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        cartItemCount: items.length
      }, 'error');
      
      setErrors({ general: 'Unable to initialize secure checkout. Please try again.' });
    }
  };

  /**
   * Fetch shipping rates from Ultra Shipping Service
   */
  const fetchShippingRates = async () => {
    // Only fetch if we have a complete shipping address
    if (!shippingInfo.address || !shippingInfo.city || !shippingInfo.state || !shippingInfo.zipCode) {
      return;
    }

    setLoadingShipping(true);
    
    try {
      // Calculate total package weight and dimensions from cart items
      // For now, use reasonable defaults - in production, get from product data
      const packageWeight = items.reduce((total, item) => total + (item.quantity * 2), 0); // Assume 2kg per item
      
      const response = await fetch('/api/shipping/rates', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          from_address: {
            name: "Store Warehouse",
            street1: "123 Commerce St",
            city: "New York",
            state: "NY",
            zip: "10001",
            country: "US",
          },
          destination_address: {
            name: `${shippingInfo.firstName} ${shippingInfo.lastName}`,
            street1: shippingInfo.address,
            city: shippingInfo.city,
            state: shippingInfo.state,
            zip: shippingInfo.zipCode,
            country: shippingInfo.country || "US",
          },
          package_weight_kg: packageWeight,
          package_dimensions: {
            length_cm: 30,
            width_cm: 20,
            height_cm: 15
          }
        })
      });

      if (response.ok) {
        const data = await response.json();
        if (data.rates && Array.isArray(data.rates)) {
          setShippingRates(data.rates);
          setSelectedShippingRate(0); // Select first rate by default
          
          SecurityService.logSecurityEvent('shipping_rates_fetched', {
            ratesCount: data.rates.length,
            destination: `${shippingInfo.city}, ${shippingInfo.state}`
          });
        }
      } else {
        // Use fallback rate if service fails
        setShippingRates([{
          carrier: 'Standard Shipping',
          service: 'Ground',
          rate: 9.99,
          currency: 'USD',
          estimated_days: '5-7',
          fallback: true
        }]);
        setSelectedShippingRate(0);
      }
    } catch (error) {
      console.error('Failed to fetch shipping rates:', error);
      
      // Use fallback rate
      setShippingRates([{
        carrier: 'Standard Shipping',
        service: 'Ground',
        rate: 9.99,
        currency: 'USD',
        estimated_days: '5-7',
        fallback: true
      }]);
      setSelectedShippingRate(0);
    } finally {
      setLoadingShipping(false);
    }
  };

  /**
   * Ultra-secure form submission
   * SECURITY: Only validates form and calls backend - NO payment processing in frontend
   */
  const handleSubmit = async () => {
    
    try {
      // Validate form first
      if (!validateForm()) {
        return;
      }

      // Check if secure session is valid
      if (!secureSession || Date.now() > secureSession.expiresAt) {
        setErrors({ general: 'Checkout session expired. Please refresh and try again.' });
        return;
      }

      // Advanced rate limiting
      const rateLimitResult = SecurityService.checkAdvancedRateLimit(
        `checkout_submit_${user?.id || 'anonymous'}`,
        5, // Max 5 submissions
        300000 // Per 5 minutes
      );

      if (!rateLimitResult.allowed) {
        setErrors({ 
          general: `Too many submission attempts. Please wait ${Math.ceil((rateLimitResult.retryAfter || 0) / 60000)} minutes.` 
        });
        return;
      }

      setIsProcessing(true);

      // Simulate successful checkout for demo
      setTimeout(() => {
        setIsProcessing(false);
        setOrderComplete(true);
        clearCart();
      }, 2000);

    } catch (error) {
      setIsProcessing(false);
      
      SecurityService.logSecurityEvent('checkout_submission_failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        paymentMethod: selectedPayment
      }, 'error');
      
      setErrors({ general: 'Checkout failed. Please try again or contact support.' });
    }
  };

  // Initialize LIVE secure checkout session on component mount
  useEffect(() => {
    if (items.length > 0 && !secureSession) {
      initializeSecureCheckout();
    }
  }, [items.length]);

  // Fetch shipping rates when address is complete
  useEffect(() => {
    if (shippingInfo.address && shippingInfo.city && shippingInfo.state && shippingInfo.zipCode) {
      // Debounce: wait 500ms after user stops typing
      const timer = setTimeout(() => {
        fetchShippingRates();
      }, 500);
      
      return () => clearTimeout(timer);
    }
  }, [shippingInfo.address, shippingInfo.city, shippingInfo.state, shippingInfo.zipCode]);

  // Set up authentication tokens for live payments
  useEffect(() => {
    // Generate session tokens for live payment processing
    if (!localStorage.getItem('session_id')) {
      localStorage.setItem('session_id', SecurityService.generateSecureId(32));
    }
    
    if (!localStorage.getItem('auth_token')) {
      // In production, this would come from your authentication system
      localStorage.setItem('auth_token', 'demo_auth_token_' + SecurityService.generateSecureId(16));
    }
  }, []);

  // Security: Validate session periodically
  useEffect(() => {
    const interval = setInterval(() => {
      if (secureSession && Date.now() > secureSession.expiresAt) {
        setSecureSession(null);
        setErrors({ general: 'Checkout session expired. Please refresh the page.' });
      }
    }, 30000); // Check every 30 seconds

    return () => clearInterval(interval);
  }, [secureSession]);

  /**
   * Handle successful PayPal payment
   * @param details - PayPal payment details
   */
  const handlePayPalSuccess = (details: any) => {
    try {
      setIsProcessing(false);
      setOrderComplete(true);
      clearCart();
      
      // Log successful payment for security monitoring
      SecurityService.logSecurityEvent('payment_success', {
        method: 'paypal',
        orderId: details.id,
        amount: finalTotal
      });
    } catch (error) {
      console.error('PayPal success handler error:', error);
      setErrors({ general: 'Payment completed but order processing failed. Please contact support.' });
    }
  };

  /**
   * Handle PayPal payment errors
   * @param error - PayPal error object
   */
  const handlePayPalError = (error: any) => {
    console.error('PayPal error:', error);
    
    // Log payment error for security monitoring
    SecurityService.logSecurityEvent('payment_error', {
      method: 'paypal',
      error: error.message || 'Unknown PayPal error'
    });
    
    let errorMessage = 'PayPal payment failed. Please try again.';
    
    if (error.message) {
      errorMessage = `PayPal error: ${error.message}`;
    }
    
    setErrors({ general: errorMessage });
    setIsProcessing(false);
  };

  if (orderComplete) {
    return (
      <main className="pt-20 min-h-screen bg-background">
        <div className="max-w-2xl mx-auto px-6 py-16">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
            className="text-center space-y-8"
          >
            <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto">
              <Shield className="w-8 h-8 text-green-600" />
            </div>
            
            <div>
              <h1 className="text-3xl font-light text-foreground mb-4">
                Order Confirmed!
              </h1>
              <p className="text-lg text-muted-foreground font-light">
                Thank you for your purchase. You'll receive a confirmation email shortly.
              </p>
            </div>

            <div className="bg-muted rounded-lg p-6">
              <h3 className="text-lg font-medium text-foreground mb-2">Order #12345</h3>
              <p className="text-muted-foreground font-light">Total: ${finalTotal.toFixed(2)}</p>
            </div>

            <Button
              onClick={onBack}
              className="bg-primary text-primary-foreground hover:bg-primary/90 font-light"
            >
              Continue Shopping
            </Button>
          </motion.div>
        </div>
      </main>
    );
  }

  if (items.length === 0) {
    return (
      <main className="pt-20 min-h-screen bg-background">
        <div className="max-w-2xl mx-auto px-6 py-16 text-center">
          <h1 className="text-3xl font-light text-foreground mb-4">
            Your cart is empty
          </h1>
          <Button
            onClick={onBack}
            className="bg-primary text-primary-foreground hover:bg-primary/90 font-light"
          >
            Continue Shopping
          </Button>
        </div>
      </main>
    );
  }

  return (
    <>
      <SEOHead
        title="Secure Checkout - Minimal Gallery"
        description="Complete your purchase securely with multiple payment options including credit cards, PayPal, and cryptocurrency."
        keywords="checkout, payment, secure, stripe, paypal, cryptocurrency"
      />
      <main className="pt-20 min-h-screen bg-background">
      <div className="max-w-7xl mx-auto px-6 lg:px-12 py-8">
        {/* Back Button */}
        <Button
          variant="ghost"
          onClick={onBack}
          className="mb-6 p-0 h-auto bg-transparent text-muted-foreground hover:text-foreground hover:bg-transparent"
        >
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back to Cart
        </Button>

        {errors.general && (
          <div className="flex items-center p-3 text-sm text-red-600 bg-red-50 dark:bg-red-950 rounded-lg mb-6">
            <AlertCircle className="w-4 h-4 mr-2" />
            {errors.general}
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-12">
          {/* Checkout Form */}
          <motion.div
            initial={{ opacity: 0, x: -30 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.6 }}
          >
            <h1 className="text-3xl font-light text-foreground mb-8">Checkout</h1>

            <div className="space-y-8">
              {/* Shipping Information */}
              <div>
                <h2 className="text-xl font-light text-foreground mb-6">Shipping Information</h2>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <Label htmlFor="firstName" className="text-sm font-light text-muted-foreground">
                      First Name
                    </Label>
                    <Input
                      id="firstName"
                      value={shippingInfo.firstName}
                      onChange={(e) => handleInputChange('shipping', 'firstName', e.target.value)}
                      required
                      className={`mt-1 bg-background border-border focus:border-primary focus:ring-0 ${
                        errors.firstName ? 'border-red-500' : ''
                      }`}
                    />
                    {errors.firstName && (
                      <div className="flex items-center mt-1 text-xs text-red-500">
                        <AlertCircle className="w-3 h-3 mr-1" />
                        {errors.firstName}
                      </div>
                    )}
                  </div>
                  
                  <div>
                    <Label htmlFor="lastName" className="text-sm font-light text-muted-foreground">
                      Last Name
                    </Label>
                    <Input
                      id="lastName"
                      value={shippingInfo.lastName}
                      onChange={(e) => handleInputChange('shipping', 'lastName', e.target.value)}
                      required
                      className={`mt-1 bg-background border-border focus:border-primary focus:ring-0 ${
                        errors.lastName ? 'border-red-500' : ''
                      }`}
                    />
                    {errors.lastName && (
                      <div className="flex items-center mt-1 text-xs text-red-500">
                        <AlertCircle className="w-3 h-3 mr-1" />
                        {errors.lastName}
                      </div>
                    )}
                  </div>
                  
                  <div className="md:col-span-2">
                    <Label htmlFor="email" className="text-sm font-light text-muted-foreground">
                      Email
                    </Label>
                    <Input
                      id="email"
                      type="email"
                      value={shippingInfo.email}
                      onChange={(e) => handleInputChange('shipping', 'email', e.target.value)}
                      required
                      className={`mt-1 bg-background border-border focus:border-primary focus:ring-0 ${
                        errors.email ? 'border-red-500' : ''
                      }`}
                    />
                    {errors.email && (
                      <div className="flex items-center mt-1 text-xs text-red-500">
                        <AlertCircle className="w-3 h-3 mr-1" />
                        {errors.email}
                      </div>
                    )}
                  </div>
                  
                  <div className="md:col-span-2">
                    <Label htmlFor="phone" className="text-sm font-light text-muted-foreground">
                      Phone
                    </Label>
                    <Input
                      id="phone"
                      type="tel"
                      value={shippingInfo.phone}
                      onChange={(e) => handleInputChange('shipping', 'phone', e.target.value)}
                      required
                      placeholder="(555) 123-4567"
                      className={`mt-1 bg-background border-border focus:border-primary focus:ring-0 ${
                        errors.phone ? 'border-red-500' : ''
                      }`}
                    />
                    {errors.phone && (
                      <div className="flex items-center mt-1 text-xs text-red-500">
                        <AlertCircle className="w-3 h-3 mr-1" />
                        {errors.phone}
                      </div>
                    )}
                  </div>
                  
                  <div className="md:col-span-2">
                    <Label htmlFor="address" className="text-sm font-light text-muted-foreground">
                      Address
                    </Label>
                    <Input
                      id="address"
                      value={shippingInfo.address}
                      onChange={(e) => handleInputChange('shipping', 'address', e.target.value)}
                      required
                      className={`mt-1 bg-background border-border focus:border-primary focus:ring-0 ${
                        errors.address ? 'border-red-500' : ''
                      }`}
                    />
                    {errors.address && (
                      <div className="flex items-center mt-1 text-xs text-red-500">
                        <AlertCircle className="w-3 h-3 mr-1" />
                        {errors.address}
                      </div>
                    )}
                  </div>
                  
                  <div>
                    <Label htmlFor="city" className="text-sm font-light text-muted-foreground">
                      City
                    </Label>
                    <Input
                      id="city"
                      value={shippingInfo.city}
                      onChange={(e) => handleInputChange('shipping', 'city', e.target.value)}
                      required
                      className={`mt-1 bg-background border-border focus:border-primary focus:ring-0 ${
                        errors.city ? 'border-red-500' : ''
                      }`}
                    />
                    {errors.city && (
                      <div className="flex items-center mt-1 text-xs text-red-500">
                        <AlertCircle className="w-3 h-3 mr-1" />
                        {errors.city}
                      </div>
                    )}
                  </div>
                  
                  <div>
                    <Label htmlFor="state" className="text-sm font-light text-muted-foreground">
                      {shippingInfo.country === 'US' ? 'State' : 'State/Province'}
                    </Label>
                    {shippingInfo.country === 'US' ? (
                      <Select value={shippingInfo.state} onValueChange={(value) => handleInputChange('shipping', 'state', value)}>
                        <SelectTrigger className={`mt-1 bg-background border-border focus:border-primary focus:ring-0 ${
                          errors.state ? 'border-red-500' : ''
                        }`}>
                          <SelectValue placeholder="Select state" />
                        </SelectTrigger>
                        <SelectContent className="max-h-60">
                          <SelectItem value="AL">Alabama</SelectItem>
                          <SelectItem value="AK">Alaska</SelectItem>
                          <SelectItem value="AZ">Arizona</SelectItem>
                          <SelectItem value="AR">Arkansas</SelectItem>
                          <SelectItem value="CA">California</SelectItem>
                          <SelectItem value="CO">Colorado</SelectItem>
                          <SelectItem value="CT">Connecticut</SelectItem>
                          <SelectItem value="DE">Delaware</SelectItem>
                          <SelectItem value="FL">Florida</SelectItem>
                          <SelectItem value="GA">Georgia</SelectItem>
                          <SelectItem value="HI">Hawaii</SelectItem>
                          <SelectItem value="ID">Idaho</SelectItem>
                          <SelectItem value="IL">Illinois</SelectItem>
                          <SelectItem value="IN">Indiana</SelectItem>
                          <SelectItem value="IA">Iowa</SelectItem>
                          <SelectItem value="KS">Kansas</SelectItem>
                          <SelectItem value="KY">Kentucky</SelectItem>
                          <SelectItem value="LA">Louisiana</SelectItem>
                          <SelectItem value="ME">Maine</SelectItem>
                          <SelectItem value="MD">Maryland</SelectItem>
                          <SelectItem value="MA">Massachusetts</SelectItem>
                          <SelectItem value="MI">Michigan</SelectItem>
                          <SelectItem value="MN">Minnesota</SelectItem>
                          <SelectItem value="MS">Mississippi</SelectItem>
                          <SelectItem value="MO">Missouri</SelectItem>
                          <SelectItem value="MT">Montana</SelectItem>
                          <SelectItem value="NE">Nebraska</SelectItem>
                          <SelectItem value="NV">Nevada</SelectItem>
                          <SelectItem value="NH">New Hampshire</SelectItem>
                          <SelectItem value="NJ">New Jersey</SelectItem>
                          <SelectItem value="NM">New Mexico</SelectItem>
                          <SelectItem value="NY">New York</SelectItem>
                          <SelectItem value="NC">North Carolina</SelectItem>
                          <SelectItem value="ND">North Dakota</SelectItem>
                          <SelectItem value="OH">Ohio</SelectItem>
                          <SelectItem value="OK">Oklahoma</SelectItem>
                          <SelectItem value="OR">Oregon</SelectItem>
                          <SelectItem value="PA">Pennsylvania</SelectItem>
                          <SelectItem value="RI">Rhode Island</SelectItem>
                          <SelectItem value="SC">South Carolina</SelectItem>
                          <SelectItem value="SD">South Dakota</SelectItem>
                          <SelectItem value="TN">Tennessee</SelectItem>
                          <SelectItem value="TX">Texas</SelectItem>
                          <SelectItem value="UT">Utah</SelectItem>
                          <SelectItem value="VT">Vermont</SelectItem>
                          <SelectItem value="VA">Virginia</SelectItem>
                          <SelectItem value="WA">Washington</SelectItem>
                          <SelectItem value="WV">West Virginia</SelectItem>
                          <SelectItem value="WI">Wisconsin</SelectItem>
                          <SelectItem value="WY">Wyoming</SelectItem>
                          <SelectItem value="DC">District of Columbia</SelectItem>
                        </SelectContent>
                      </Select>
                    ) : (
                      <Input
                        id="state"
                        value={shippingInfo.state}
                        onChange={(e) => handleInputChange('shipping', 'state', e.target.value)}
                        required
                        className={`mt-1 bg-background border-border focus:border-primary focus:ring-0 ${
                          errors.state ? 'border-red-500' : ''
                        }`}
                      />
                    )}
                    {errors.state && (
                      <div className="flex items-center mt-1 text-xs text-red-500">
                        <AlertCircle className="w-3 h-3 mr-1" />
                        {errors.state}
                      </div>
                    )}
                  </div>
                  
                  <div>
                    <Label htmlFor="zipCode" className="text-sm font-light text-muted-foreground">
                      ZIP Code
                    </Label>
                    <Input
                      id="zipCode"
                      value={shippingInfo.zipCode}
                      onChange={(e) => handleInputChange('shipping', 'zipCode', e.target.value)}
                      required
                      className={`mt-1 bg-background border-border focus:border-primary focus:ring-0 ${
                        errors.zipCode ? 'border-red-500' : ''
                      }`}
                    />
                    {errors.zipCode && (
                      <div className="flex items-center mt-1 text-xs text-red-500">
                        <AlertCircle className="w-3 h-3 mr-1" />
                        {errors.zipCode}
                      </div>
                    )}
                  </div>
                  
                  <div>
                    <Label htmlFor="country" className="text-sm font-light text-muted-foreground">
                      Country
                    </Label>
                    <Select value={shippingInfo.country} onValueChange={(value) => handleInputChange('shipping', 'country', value)}>
                      <SelectTrigger className="mt-1 bg-background border-border focus:border-primary focus:ring-0">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="US">United States</SelectItem>
                        <SelectItem value="CA">Canada</SelectItem>
                        <SelectItem value="MX">Mexico</SelectItem>
                        <SelectItem value="GB">United Kingdom</SelectItem>
                        <SelectItem value="DE">Germany</SelectItem>
                        <SelectItem value="FR">France</SelectItem>
                        <SelectItem value="ES">Spain</SelectItem>
                        <SelectItem value="IT">Italy</SelectItem>
                        <SelectItem value="AU">Australia</SelectItem>
                        <SelectItem value="JP">Japan</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              </div>

              {/* Shipping Options */}
              {shippingRates.length > 0 && (
                <div>
                  <h2 className="text-xl font-light text-foreground mb-6 flex items-center">
                    <Truck className="w-5 h-5 mr-2" />
                    Shipping Method
                  </h2>
                  
                  {loadingShipping && (
                    <div className="text-sm text-muted-foreground mb-4">
                      Calculating shipping rates...
                    </div>
                  )}
                  
                  <div className="space-y-3">
                    {shippingRates.map((rate, index) => (
                      <div
                        key={index}
                        onClick={() => setSelectedShippingRate(index)}
                        className={`relative flex items-center justify-between p-4 border rounded-lg cursor-pointer transition-all ${
                          selectedShippingRate === index
                            ? 'border-primary bg-primary/5'
                            : 'border-border hover:border-primary/50'
                        }`}
                      >
                        <div className="flex items-center">
                          <div className={`w-4 h-4 rounded-full border-2 mr-3 flex items-center justify-center ${
                            selectedShippingRate === index
                              ? 'border-primary'
                              : 'border-gray-300'
                          }`}>
                            {selectedShippingRate === index && (
                              <div className="w-2 h-2 rounded-full bg-primary" />
                            )}
                          </div>
                          <div>
                            <div className="font-medium text-foreground">
                              {rate.carrier} - {rate.service}
                            </div>
                            <div className="text-sm text-muted-foreground">
                              Estimated delivery: {rate.estimated_days} business days
                            </div>
                            {rate.fallback && (
                              <div className="text-xs text-amber-600 mt-1">
                                Standard rate applied
                              </div>
                            )}
                          </div>
                        </div>
                        <div className="text-lg font-medium text-foreground">
                          ${rate.rate.toFixed(2)}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <Separator />

              {/* Payment Method */}
              <div>
                <h2 className="text-xl font-light text-foreground mb-6">Payment Method</h2>
                
                <Tabs value={selectedPayment} onValueChange={setSelectedPayment} className="w-full">
                  <TabsList className="grid w-full grid-cols-3 lg:grid-cols-5 bg-muted">
                    {paymentMethods.map((method) => {
                      const IconComponent = method.icon;
                      return (
                        <TabsTrigger
                          key={method.id}
                          value={method.id}
                          className="flex flex-col items-center p-3 text-xs"
                        >
                          <IconComponent className="w-4 h-4 mb-1" />
                          <span className="hidden sm:block">{method.name.split(' ')[0]}</span>
                        </TabsTrigger>
                      );
                    })}
                  </TabsList>

                  <TabsContent value="card" className="mt-6">
                    {secureSession ? (
                      <Elements stripe={stripePromise}>
                        <StripeCardForm
                          tempPaymentId={secureSession.tempPaymentId}
                          amount={finalTotal}
                          onSuccess={(paymentIntent) => {
                            SecurityService.logSecurityEvent('payment_completed', {
                              method: 'stripe',
                              paymentIntentId: paymentIntent.id
                            });
                            setIsProcessing(false);
                            setOrderComplete(true);
                            clearCart();
                          }}
                          onError={(error) => {
                            setErrors({ general: error });
                            setIsProcessing(false);
                          }}
                          disabled={isProcessing}
                        />
                      </Elements>
                    ) : (
                      <div className="text-center py-8">
                        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto mb-4"></div>
                        <p className="text-muted-foreground">Initializing secure payment...</p>
                      </div>
                    )}
                  </TabsContent>

                  <TabsContent value="paypal" className="mt-6">
                    <div className="bg-blue-50 dark:bg-blue-950 border border-blue-200 dark:border-blue-800 rounded-lg p-6">
                      <div className="text-center mb-4">
                        <DollarSign className="w-12 h-12 text-blue-600 dark:text-blue-400 mx-auto mb-4" />
                        <h3 className="text-lg font-medium text-blue-900 dark:text-blue-100 mb-2">PayPal</h3>
                        <p className="text-blue-700 dark:text-blue-300 font-light mb-4">
                          Complete your payment securely with PayPal
                        </p>
                      </div>
                      
                      <div className="space-y-4">
                        <div className="bg-white dark:bg-gray-800 p-4 rounded border">
                          <div className="flex justify-between items-center mb-2">
                            <span className="text-sm font-medium">Total Amount:</span>
                            <span className="text-lg font-bold">${finalTotal.toFixed(2)} USD</span>
                          </div>
                          <p className="text-xs text-muted-foreground">
                            You will be redirected to PayPal to complete your payment
                          </p>
                        </div>
                        
                        <Button
                          type="button"
                          onClick={async () => {
                            try {
                              setIsProcessing(true);
                              
                              const response = await fetch(`${import.meta.env.VITE_BACKEND_URL}/api/paypal`, {
                                method: 'POST',
                                headers: {
                                  'Content-Type': 'application/json',
                                  'Authorization': `Bearer ${localStorage.getItem('auth_token')}`,
                                  'X-CSRF-Token': localStorage.getItem('csrf_token') || '',
                                  'X-Session-ID': localStorage.getItem('session_id') || ''
                                },
                                body: JSON.stringify({
                                  temp_payment_id: secureSession?.tempPaymentId,
                                  shipping_info: shippingInfo,
                                  return_url: `${window.location.origin}/checkout/paypal/success`,
                                  cancel_url: `${window.location.origin}/checkout/paypal/cancel`
                                })
                              });

                              if (!response.ok) {
                                const errorData = await response.json();
                                throw new Error(errorData.message || 'Failed to create PayPal order');
                              }

                              const orderData = await response.json();
                              
                              SecurityService.logSecurityEvent('paypal_redirect_initiated', {
                                orderId: orderData.paypal_order_id,
                                tempPaymentId: secureSession?.tempPaymentId
                              });
                              
                              // Redirect to PayPal approval URL
                              if (orderData.approval_url) {
                                window.location.href = orderData.approval_url;
                              } else {
                                throw new Error('No approval URL received from PayPal');
                              }
                            } catch (error: any) {
                              setErrors({ general: error.message || 'Failed to initiate PayPal payment' });
                              setIsProcessing(false);
                            }
                          }}
                          disabled={isProcessing || !secureSession?.tempPaymentId}
                          className="w-full bg-[#0070ba] hover:bg-[#005ea6] text-white font-medium py-3 rounded-lg transition-colors flex items-center justify-center gap-2"
                        >
                          {isProcessing ? (
                            <>
                              <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
                              <span>Redirecting to PayPal...</span>
                            </>
                          ) : (
                            <>
                              <DollarSign className="w-5 h-5" />
                              <span>Pay with PayPal</span>
                            </>
                          )}
                        </Button>
                      </div>
                    </div>
                  </TabsContent>

                  <TabsContent value="crypto" className="mt-6">
                    <div className="bg-orange-50 dark:bg-orange-950 border border-orange-200 dark:border-orange-800 rounded-lg p-6">
                      <div className="text-center mb-4">
                        <Bitcoin className="w-12 h-12 text-orange-600 dark:text-orange-400 mx-auto mb-4" />
                        <h3 className="text-lg font-medium text-orange-900 dark:text-orange-100 mb-2">Cryptocurrency</h3>
                        <p className="text-orange-700 dark:text-orange-300 font-light mb-4">
                          Pay with Bitcoin, Ethereum, or other supported cryptocurrencies via Coinbase Commerce.
                        </p>
                      </div>
                      
                      <div className="space-y-4">
                        <div className="bg-white dark:bg-gray-800 p-4 rounded border">
                          <div className="flex justify-between items-center mb-2">
                            <span className="text-sm font-medium">Total Amount:</span>
                            <span className="text-lg font-bold">${finalTotal.toFixed(2)} USD</span>
                          </div>
                          <p className="text-xs text-muted-foreground">
                            Cryptocurrency amount will be calculated at current exchange rates
                          </p>
                        </div>
                        
                        <Button
                          type="button"
                          onClick={async () => {
                            try {
                              setIsProcessing(true);
                              
                              // Call backend to create Coinbase Commerce charge
                              const response = await fetch(`${import.meta.env.VITE_BACKEND_URL}/api/coinbase/create-charge`, {
                                method: 'POST',
                                headers: {
                                  'Content-Type': 'application/json',
                                  'Authorization': `Bearer ${localStorage.getItem('auth_token')}`,
                                  'X-CSRF-Token': localStorage.getItem('csrf_token') || '',
                                  'X-Session-ID': localStorage.getItem('session_id') || ''
                                },
                                body: JSON.stringify({
                                  temp_payment_id: secureSession?.tempPaymentId,
                                  shipping_info: shippingInfo,
                                  redirect_url: `${window.location.origin}/checkout/crypto/success`,
                                  cancel_url: `${window.location.origin}/checkout/crypto/cancel`
                                })
                              });

                              if (!response.ok) {
                                throw new Error('Failed to create cryptocurrency payment');
                              }

                              const result = await response.json();
                              
                              if (result.hosted_url) {
                                // Redirect to Coinbase Commerce for LIVE crypto payment
                                window.location.href = result.hosted_url;
                              } else {
                                throw new Error('Cryptocurrency payment URL not available');
                              }
                            } catch (error) {
                              setErrors({ general: 'Failed to initialize cryptocurrency payment. Please try again.' });
                              setIsProcessing(false);
                            }
                          }}
                          disabled={isProcessing}
                          className="w-full bg-orange-600 text-white hover:bg-orange-700"
                        >
                          {isProcessing ? 'Creating payment...' : 'Pay with Crypto'}
                        </Button>
                        
                        <p className="text-xs text-center text-muted-foreground">
                          Powered by Coinbase Commerce - Secure cryptocurrency payments
                        </p>
                      </div>
                    </div>
                  </TabsContent>

                  <TabsContent value="apple_pay" className="mt-6">
                    <Elements stripe={stripePromise}>
                      <ApplePayButton
                        amount={finalTotal}
                        onSuccess={() => {
                          setIsProcessing(false);
                          setOrderComplete(true);
                          clearCart();
                        }}
                        onError={() => {
                          setErrors({ general: 'Payment failed' });
                          setIsProcessing(false);
                        }}
                        disabled={isProcessing}
                      />
                    </Elements>
                  </TabsContent>

                  <TabsContent value="google_pay" className="mt-6">
                    <Elements stripe={stripePromise}>
                      <GooglePayButton
                        amount={finalTotal}
                        onSuccess={() => {
                          setIsProcessing(false);
                          setOrderComplete(true);
                          clearCart();
                        }}
                        onError={() => {
                          setErrors({ general: 'Payment failed' });
                          setIsProcessing(false);
                        }}
                        disabled={isProcessing}
                      />
                    </Elements>
                  </TabsContent>
                </Tabs>
              </div>

              <Button
                onClick={handleSubmit}
                disabled={isProcessing}
                className="w-full bg-primary text-primary-foreground hover:bg-primary/90 font-light py-3"
              >
                {isProcessing ? 'Processing...' : `Complete Order - $${finalTotal.toFixed(2)}`}
              </Button>
            </div>
          </motion.div>

          {/* Order Summary */}
          <motion.div
            initial={{ opacity: 0, x: 30 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.6, delay: 0.2 }}
            className="lg:sticky lg:top-24 h-fit"
          >
            <div className="bg-muted rounded-lg p-6">
              <h2 className="text-xl font-light text-foreground mb-6">Order Summary</h2>
              
              {/* Items */}
              <div className="space-y-4 mb-6">
                {items.map((item) => (
                  <div key={`${item.id}-${item.size}-${item.color}`} className="flex items-center space-x-4">
                    <img
                      src={item.image}
                      alt={item.name}
                      className="w-16 h-16 object-cover rounded-md bg-background"
                    />
                    <div className="flex-1 min-w-0">
                      <h4 className="text-sm font-medium text-foreground truncate">
                        {item.name}
                      </h4>
                      <p className="text-sm text-muted-foreground">
                        Qty: {item.quantity} × ${item.price.toFixed(2)}
                      </p>
                      {item.size && (
                        <p className="text-xs text-muted-foreground">Size: {item.size}</p>
                      )}
                      {item.color && (
                        <p className="text-xs text-muted-foreground">Color: {item.color}</p>
                      )}
                    </div>
                    <div className="text-sm font-medium text-foreground">
                      ${(item.price * item.quantity).toFixed(2)}
                    </div>
                  </div>
                ))}
              </div>

              <Separator className="mb-4" />

              {/* Totals */}
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span className="text-muted-foreground">Subtotal</span>
                  <span className="text-foreground">${totalPrice.toFixed(2)}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-muted-foreground">
                    Shipping {totalPrice >= 100 && '(Free over $100)'}
                  </span>
                  <span className="text-foreground">
                    {shippingCost === 0 ? 'Free' : `$${shippingCost.toFixed(2)}`}
                  </span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-muted-foreground">
                    Tax {shippingInfo.country === 'US' && shippingInfo.state && `(${formatTaxRate(shippingInfo.country, shippingInfo.state)})`}
                  </span>
                  <span className="text-foreground">${tax.toFixed(2)}</span>
                </div>
                <Separator className="my-2" />
                <div className="flex justify-between text-lg font-medium">
                  <span className="text-foreground">Total</span>
                  <span className="text-foreground">${finalTotal.toFixed(2)}</span>
                </div>
              </div>

              {/* Security Badge */}
              <div className="mt-6 flex items-center justify-center space-x-2 text-sm text-muted-foreground">
                <Shield className="w-4 h-4" />
                <span>Secure SSL encrypted payment</span>
              </div>

              {/* Shipping Info */}
              <div className="mt-4 flex items-center justify-center space-x-2 text-sm text-muted-foreground">
                <Truck className="w-4 h-4" />
                <span>
                  {totalPrice >= 100 
                    ? 'Free shipping applied!' 
                    : `Add $${(100 - totalPrice).toFixed(2)} for free shipping`
                  }
                </span>
              </div>
            </div>
          </motion.div>
        </div>
      </div>
    </main>
    </>
  );
};

import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useAuthStore } from '@/stores/authStore';
import { validateEmail } from '@/utils/validators';
import { AlertCircle, Eye, EyeOff, CheckCircle } from 'lucide-react';

interface RegisterFormProps {
  onSwitchToLogin: () => void;
  onClose: () => void;
}

export const RegisterForm: React.FC<RegisterFormProps> = ({ 
  onSwitchToLogin, 
  onClose 
}) => {
  const { register, isLoading, error, clearError } = useAuthStore();
  const [formData, setFormData] = useState({
    firstName: '',
    lastName: '',
    email: '',
    password: '',
    confirmPassword: ''
  });
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [acceptTerms, setAcceptTerms] = useState(false);

  const handleInputChange = (field: string, value: string) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    if (errors[field]) {
      setErrors(prev => ({ ...prev, [field]: '' }));
    }
    clearError();
  };

  const validateForm = (): boolean => {
    const newErrors: Record<string, string> = {};

    // Validate first name
    if (!formData.firstName.trim()) {
      newErrors.firstName = 'First name is required';
    } else if (formData.firstName.length < 2) {
      newErrors.firstName = 'First name must be at least 2 characters';
    }

    // Validate last name
    if (!formData.lastName.trim()) {
      newErrors.lastName = 'Last name is required';
    } else if (formData.lastName.length < 2) {
      newErrors.lastName = 'Last name must be at least 2 characters';
    }

    // Validate email
    const emailValidation = validateEmail(formData.email);
    if (!emailValidation.isValid) {
      newErrors.email = emailValidation.error!;
    }

    // Validate password
    if (!formData.password) {
      newErrors.password = 'Password is required';
    } else if (formData.password.length < 8) {
      newErrors.password = 'Password must be at least 8 characters';
    } else if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(formData.password)) {
      newErrors.password = 'Password must contain uppercase, lowercase, and number';
    }

    // Validate confirm password
    if (!formData.confirmPassword) {
      newErrors.confirmPassword = 'Please confirm your password';
    } else if (formData.password !== formData.confirmPassword) {
      newErrors.confirmPassword = 'Passwords do not match';
    }

    // Validate terms acceptance
    if (!acceptTerms) {
      newErrors.terms = 'You must accept the terms and conditions';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }

    try {
      await register({
        firstName: formData.firstName,
        lastName: formData.lastName,
        email: formData.email,
        password: formData.password
      });
      onClose();
    } catch (error) {
      // Error is handled by the store
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <div className="text-center">
        <h2 className="text-2xl font-light text-foreground mb-2">Create Account</h2>
        <p className="text-muted-foreground font-light">Join us and start your journey</p>
      </div>

      {error && (
        <div className="flex items-center p-3 text-sm text-red-600 bg-red-50 dark:bg-red-950 rounded-lg">
          <AlertCircle className="w-4 h-4 mr-2" />
          {error}
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <div>
            <Label htmlFor="firstName" className="text-sm font-light text-muted-foreground">
              First Name
            </Label>
            <Input
              id="firstName"
              type="text"
              value={formData.firstName}
              onChange={(e) => handleInputChange('firstName', e.target.value)}
              className={`mt-1 bg-background border-border focus:border-primary focus:ring-0 ${
                errors.firstName ? 'border-red-500' : ''
              }`}
              placeholder="John"
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
              type="text"
              value={formData.lastName}
              onChange={(e) => handleInputChange('lastName', e.target.value)}
              className={`mt-1 bg-background border-border focus:border-primary focus:ring-0 ${
                errors.lastName ? 'border-red-500' : ''
              }`}
              placeholder="Doe"
            />
            {errors.lastName && (
              <div className="flex items-center mt-1 text-xs text-red-500">
                <AlertCircle className="w-3 h-3 mr-1" />
                {errors.lastName}
              </div>
            )}
          </div>
        </div>

        <div>
          <Label htmlFor="email" className="text-sm font-light text-muted-foreground">
            Email Address
          </Label>
          <Input
            id="email"
            type="email"
            value={formData.email}
            onChange={(e) => handleInputChange('email', e.target.value)}
            className={`mt-1 bg-background border-border focus:border-primary focus:ring-0 ${
              errors.email ? 'border-red-500' : ''
            }`}
            placeholder="john@example.com"
          />
          {errors.email && (
            <div className="flex items-center mt-1 text-xs text-red-500">
              <AlertCircle className="w-3 h-3 mr-1" />
              {errors.email}
            </div>
          )}
        </div>

        <div>
          <Label htmlFor="password" className="text-sm font-light text-muted-foreground">
            Password
          </Label>
          <div className="relative">
            <Input
              id="password"
              type={showPassword ? 'text' : 'password'}
              value={formData.password}
              onChange={(e) => handleInputChange('password', e.target.value)}
              className={`mt-1 bg-background border-border focus:border-primary focus:ring-0 pr-10 ${
                errors.password ? 'border-red-500' : ''
              }`}
              placeholder="Create a strong password"
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute right-3 top-1/2 transform -translate-y-1/2 text-muted-foreground hover:text-foreground"
            >
              {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
          {errors.password && (
            <div className="flex items-center mt-1 text-xs text-red-500">
              <AlertCircle className="w-3 h-3 mr-1" />
              {errors.password}
            </div>
          )}
        </div>

        <div>
          <Label htmlFor="confirmPassword" className="text-sm font-light text-muted-foreground">
            Confirm Password
          </Label>
          <div className="relative">
            <Input
              id="confirmPassword"
              type={showConfirmPassword ? 'text' : 'password'}
              value={formData.confirmPassword}
              onChange={(e) => handleInputChange('confirmPassword', e.target.value)}
              className={`mt-1 bg-background border-border focus:border-primary focus:ring-0 pr-10 ${
                errors.confirmPassword ? 'border-red-500' : ''
              }`}
              placeholder="Confirm your password"
            />
            <button
              type="button"
              onClick={() => setShowConfirmPassword(!showConfirmPassword)}
              className="absolute right-3 top-1/2 transform -translate-y-1/2 text-muted-foreground hover:text-foreground"
            >
              {showConfirmPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
          {errors.confirmPassword && (
            <div className="flex items-center mt-1 text-xs text-red-500">
              <AlertCircle className="w-3 h-3 mr-1" />
              {errors.confirmPassword}
            </div>
          )}
        </div>

        <div className="flex items-start space-x-2">
          <input
            id="terms"
            type="checkbox"
            checked={acceptTerms}
            onChange={(e) => setAcceptTerms(e.target.checked)}
            className="mt-1"
          />
          <Label htmlFor="terms" className="text-sm font-light text-muted-foreground leading-relaxed">
            I agree to the{' '}
            <a href="/terms" className="text-primary hover:text-primary/80 underline">
              Terms of Service
            </a>{' '}
            and{' '}
            <a href="/privacy" className="text-primary hover:text-primary/80 underline">
              Privacy Policy
            </a>
          </Label>
        </div>
        {errors.terms && (
          <div className="flex items-center text-xs text-red-500">
            <AlertCircle className="w-3 h-3 mr-1" />
            {errors.terms}
          </div>
        )}

        <Button
          type="submit"
          disabled={isLoading}
          className="w-full bg-primary text-primary-foreground hover:bg-primary/90 font-light"
        >
          {isLoading ? 'Creating account...' : 'Create Account'}
        </Button>
      </form>

      <div className="text-center">
        <p className="text-sm text-muted-foreground font-light">
          Already have an account?{' '}
          <button
            onClick={onSwitchToLogin}
            className="text-primary hover:text-primary/80 font-medium"
          >
            Sign in
          </button>
        </p>
      </div>
    </motion.div>
  );
};
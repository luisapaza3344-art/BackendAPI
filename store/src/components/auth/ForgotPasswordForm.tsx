import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useAuthStore } from '@/stores/authStore';
import { validateEmail } from '@/utils/validators';
import { AlertCircle, ArrowLeft, CheckCircle } from 'lucide-react';

interface ForgotPasswordFormProps {
  onSwitchToLogin: () => void;
}

export const ForgotPasswordForm: React.FC<ForgotPasswordFormProps> = ({ 
  onSwitchToLogin 
}) => {
  const { forgotPassword, isLoading, error, clearError } = useAuthStore();
  const [email, setEmail] = useState('');
  const [emailError, setEmailError] = useState('');
  const [isSuccess, setIsSuccess] = useState(false);

  const handleInputChange = (value: string) => {
    setEmail(value);
    if (emailError) {
      setEmailError('');
    }
    clearError();
  };

  const validateForm = (): boolean => {
    const emailValidation = validateEmail(email);
    if (!emailValidation.isValid) {
      setEmailError(emailValidation.error!);
      return false;
    }
    return true;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }

    try {
      await forgotPassword(email);
      setIsSuccess(true);
    } catch (error) {
      // Error is handled by the store
    }
  };

  if (isSuccess) {
    return (
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className="space-y-6 text-center"
      >
        <div className="w-16 h-16 bg-green-100 dark:bg-green-950 rounded-full flex items-center justify-center mx-auto">
          <CheckCircle className="w-8 h-8 text-green-600 dark:text-green-400" />
        </div>
        
        <div>
          <h2 className="text-2xl font-light text-foreground mb-2">Check Your Email</h2>
          <p className="text-muted-foreground font-light">
            We've sent a password reset link to <strong>{email}</strong>
          </p>
        </div>

        <div className="space-y-4">
          <p className="text-sm text-muted-foreground font-light">
            Didn't receive the email? Check your spam folder or try again.
          </p>
          
          <Button
            onClick={() => setIsSuccess(false)}
            variant="outline"
            className="w-full"
          >
            Try Again
          </Button>
          
          <Button
            onClick={onSwitchToLogin}
            variant="ghost"
            className="w-full"
          >
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back to Sign In
          </Button>
        </div>
      </motion.div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <div className="text-center">
        <h2 className="text-2xl font-light text-foreground mb-2">Reset Password</h2>
        <p className="text-muted-foreground font-light">
          Enter your email address and we'll send you a link to reset your password.
        </p>
      </div>

      {error && (
        <div className="flex items-center p-3 text-sm text-red-600 bg-red-50 dark:bg-red-950 rounded-lg">
          <AlertCircle className="w-4 h-4 mr-2" />
          {error}
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <Label htmlFor="email" className="text-sm font-light text-muted-foreground">
            Email Address
          </Label>
          <Input
            id="email"
            type="email"
            value={email}
            onChange={(e) => handleInputChange(e.target.value)}
            className={`mt-1 bg-background border-border focus:border-primary focus:ring-0 ${
              emailError ? 'border-red-500' : ''
            }`}
            placeholder="Enter your email"
          />
          {emailError && (
            <div className="flex items-center mt-1 text-xs text-red-500">
              <AlertCircle className="w-3 h-3 mr-1" />
              {emailError}
            </div>
          )}
        </div>

        <Button
          type="submit"
          disabled={isLoading}
          className="w-full bg-primary text-primary-foreground hover:bg-primary/90 font-light"
        >
          {isLoading ? 'Sending...' : 'Send Reset Link'}
        </Button>
      </form>

      <div className="text-center">
        <button
          onClick={onSwitchToLogin}
          className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground font-light"
        >
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back to Sign In
        </button>
      </div>
    </motion.div>
  );
};

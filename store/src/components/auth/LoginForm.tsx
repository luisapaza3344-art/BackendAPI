import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useAuthStore } from '@/stores/authStore';
import { validateEmail } from '@/utils/validators';
import { AlertCircle, Eye, EyeOff } from 'lucide-react';

interface LoginFormProps {
  onSwitchToRegister: () => void;
  onSwitchToForgotPassword: () => void;
  onClose: () => void;
}

export const LoginForm: React.FC<LoginFormProps> = ({ 
  onSwitchToRegister, 
  onSwitchToForgotPassword,
  onClose 
}) => {
  const { login, isLoading, error, clearError } = useAuthStore();
  const [formData, setFormData] = useState({
    email: '',
    password: ''
  });
  const [showPassword, setShowPassword] = useState(false);
  const [errors, setErrors] = useState<Record<string, string>>({});

  const handleInputChange = (field: string, value: string) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    if (errors[field]) {
      setErrors(prev => ({ ...prev, [field]: '' }));
    }
    clearError();
  };

  const validateForm = (): boolean => {
    const newErrors: Record<string, string> = {};

    // Validate email
    const emailValidation = validateEmail(formData.email);
    if (!emailValidation.isValid) {
      newErrors.email = emailValidation.error!;
    }

    // Validate password
    if (!formData.password) {
      newErrors.password = 'Password is required';
    } else if (formData.password.length < 6) {
      newErrors.password = 'Password must be at least 6 characters';
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
      await login(formData.email, formData.password);
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
        <h2 className="text-2xl font-light text-foreground mb-2">Welcome Back</h2>
        <p className="text-muted-foreground font-light">Sign in to your account</p>
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
            value={formData.email}
            onChange={(e) => handleInputChange('email', e.target.value)}
            className={`mt-1 bg-background border-border focus:border-primary focus:ring-0 ${
              errors.email ? 'border-red-500' : ''
            }`}
            placeholder="Enter your email"
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
              placeholder="Enter your password"
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

        <div className="flex items-center justify-between">
          <div className="text-sm">
            <button
              type="button"
              onClick={onSwitchToForgotPassword}
              className="text-primary hover:text-primary/80 font-light"
            >
              Forgot password?
            </button>
          </div>
        </div>

        <Button
          type="submit"
          disabled={isLoading}
          className="w-full bg-primary text-primary-foreground hover:bg-primary/90 font-light"
        >
          {isLoading ? 'Signing in...' : 'Sign In'}
        </Button>
      </form>

      <div className="text-center">
        <p className="text-sm text-muted-foreground font-light">
          Don't have an account?{' '}
          <button
            onClick={onSwitchToRegister}
            className="text-primary hover:text-primary/80 font-medium"
          >
            Sign up
          </button>
        </p>
      </div>

      {/* Demo Credentials */}
      <div className="mt-6 p-4 bg-muted rounded-lg">
        <p className="text-xs text-muted-foreground font-light mb-2">Demo Credentials:</p>
        <div className="space-y-1 text-xs">
          <p><strong>Admin:</strong> admin@minimal.gallery / admin123</p>
          <p><strong>User:</strong> user@example.com / user123</p>
        </div>
      </div>
    </motion.div>
  );
};

import React, { useState } from 'react';
import { Dialog, DialogContent } from '../ui/dialog';
import { LoginForm } from './LoginForm';
import { RegisterForm } from './RegisterForm';
import { ForgotPasswordForm } from './ForgotPasswordForm';

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  initialMode?: 'login' | 'register' | 'forgot-password';
}

export const AuthModal: React.FC<AuthModalProps> = ({ 
  isOpen, 
  onClose, 
  initialMode = 'login' 
}) => {
  const [mode, setMode] = useState<'login' | 'register' | 'forgot-password'>(initialMode);

  const handleClose = () => {
    onClose();
    // Reset to login mode when modal closes
    setTimeout(() => setMode('login'), 300);
  };

  return (
    <Dialog open={isOpen} onOpenChange={handleClose}>
      <DialogContent className="sm:max-w-md bg-background text-foreground border-border">
        {mode === 'login' && (
          <LoginForm
            onSwitchToRegister={() => setMode('register')}
            onSwitchToForgotPassword={() => setMode('forgot-password')}
            onClose={handleClose}
          />
        )}
        
        {mode === 'register' && (
          <RegisterForm
            onSwitchToLogin={() => setMode('login')}
            onClose={handleClose}
          />
        )}
        
        {mode === 'forgot-password' && (
          <ForgotPasswordForm
            onSwitchToLogin={() => setMode('login')}
          />
        )}
      </DialogContent>
    </Dialog>
  );
};

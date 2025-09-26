import React from 'react';
import { cn } from '@/lib/utils';

interface LoadingSpinnerProps {
  size?: 'sm' | 'md' | 'lg';
  message?: string;
  className?: string;
}

/**
 * Accessible loading spinner component
 */
export const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({
  size = 'md',
  message = 'Loading...',
  className
}) => {
  const sizeClasses = {
    sm: 'h-4 w-4',
    md: 'h-8 w-8',
    lg: 'h-12 w-12'
  };

  return (
    <div 
      className={cn('flex flex-col items-center justify-center', className)}
      role="status"
      aria-live="polite"
      aria-label={message}
    >
      <div 
        className={cn(
          'animate-spin rounded-full border-b-2 border-primary',
          sizeClasses[size]
        )}
        aria-hidden="true"
      />
      <span className="sr-only">{message}</span>
      {size === 'lg' && (
        <p className="mt-4 text-muted-foreground font-light">{message}</p>
      )}
    </div>
  );
};

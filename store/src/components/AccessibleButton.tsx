import React from 'react';
import { Button, type ButtonProps } from '@/components/ui/button';
import { cn } from '@/lib/utils';

interface AccessibleButtonProps extends ButtonProps {
  'aria-label'?: string;
  'aria-describedby'?: string;
  loading?: boolean;
  loadingText?: string;
  children?: React.ReactNode;
}

/**
 * Accessible button component with enhanced ARIA support
 */
export const AccessibleButton: React.FC<AccessibleButtonProps> = ({
  children,
  loading = false,
  loadingText = 'Loading...',
  disabled,
  className,
  ...props
}) => {
  return (
    <Button
      {...props}
      disabled={disabled || loading}
      aria-busy={loading}
      aria-disabled={disabled || loading}
      className={cn(
        'focus:ring-2 focus:ring-primary focus:ring-offset-2 focus:outline-none',
        className
      )}
    >
      {loading ? (
        <>
          <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-current mr-2" />
          <span className="sr-only">{loadingText}</span>
          {loadingText}
        </>
      ) : (
        children
      )}
    </Button>
  );
};

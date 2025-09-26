import React from 'react';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { cn, generateAccessibleId } from '@/lib/utils';
import { AlertCircle } from 'lucide-react';

interface AccessibleInputProps extends React.ComponentProps<typeof Input> {
  label: string;
  error?: string;
  description?: string;
  required?: boolean;
}

/**
 * Accessible input component with proper ARIA attributes
 */
export const AccessibleInput: React.FC<AccessibleInputProps> = ({
  label,
  error,
  description,
  required = false,
  className,
  id,
  ...props
}) => {
  const inputId = id || generateAccessibleId('input');
  const errorId = error ? `${inputId}-error` : undefined;
  const descriptionId = description ? `${inputId}-description` : undefined;

  return (
    <div className="space-y-2">
      <Label 
        htmlFor={inputId}
        className={cn(
          'text-sm font-medium text-foreground',
          required && "after:content-['*'] after:ml-0.5 after:text-red-500"
        )}
      >
        {label}
      </Label>
      
      {description && (
        <p 
          id={descriptionId}
          className="text-sm text-muted-foreground"
        >
          {description}
        </p>
      )}
      
      <Input
        {...props}
        id={inputId}
        required={required}
        aria-invalid={!!error}
        aria-describedby={cn(
          descriptionId,
          errorId
        )}
        className={cn(
          'transition-colors',
          error && 'border-red-500 focus:border-red-500',
          className
        )}
      />
      
      {error && (
        <div 
          id={errorId}
          className="flex items-center text-sm text-red-600 dark:text-red-400"
          role="alert"
          aria-live="polite"
        >
          <AlertCircle className="w-4 h-4 mr-2 flex-shrink-0" />
          {error}
        </div>
      )}
    </div>
  );
};

interface AccessibleFormProps extends React.FormHTMLAttributes<HTMLFormElement> {
  title?: string;
  description?: string;
}

/**
 * Accessible form wrapper with proper ARIA attributes
 */
export const AccessibleForm: React.FC<AccessibleFormProps> = ({
  title,
  description,
  children,
  className,
  ...props
}) => {
  const formId = generateAccessibleId('form');
  const titleId = title ? `${formId}-title` : undefined;
  const descriptionId = description ? `${formId}-description` : undefined;

  return (
    <form
      {...props}
      className={cn('space-y-6', className)}
      aria-labelledby={titleId}
      aria-describedby={descriptionId}
      noValidate // We handle validation ourselves
    >
      {title && (
        <h2 
          id={titleId}
          className="text-2xl font-light text-foreground"
        >
          {title}
        </h2>
      )}
      
      {description && (
        <p 
          id={descriptionId}
          className="text-muted-foreground font-light"
        >
          {description}
        </p>
      )}
      
      {children}
    </form>
  );
};

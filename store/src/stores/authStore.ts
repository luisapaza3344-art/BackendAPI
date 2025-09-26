import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { SecurityService } from '../services/cryptoService';

export interface User {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  role: 'user' | 'admin';
  avatar?: string;
  createdAt: string;
  lastLogin?: string;
}

interface AuthStore {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  
  // Actions
  login: (email: string, password: string) => Promise<void>;
  register: (userData: {
    email: string;
    password: string;
    firstName: string;
    lastName: string;
  }) => Promise<void>;
  logout: () => void;
  forgotPassword: (email: string) => Promise<void>;
  resetPassword: (token: string, password: string) => Promise<void>;
  updateProfile: (userData: Partial<User>) => Promise<void>;
  setUser: (user: User | null) => void;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  clearError: () => void;
}

/**
 * Mock API calls with enhanced security - replace with real API
 */

/**
 * Simulate login API call with rate limiting and validation
 * @param userEmail - User email address
 * @param userPassword - User password
 * @returns Promise with user data
 * @throws Error for invalid credentials or rate limiting
 */
const mockLogin = async (userEmail: string, userPassword: string): Promise<User> => {
  // Simulate API delay
  await new Promise(resolve => setTimeout(resolve, 1000));
  
  // Rate limiting check
  const rateLimitKey = `login_${userEmail.replace(/[^a-zA-Z0-9]/g, '_')}`;
  const rateLimitResult = SecurityService.checkAdvancedRateLimit(rateLimitKey, 5, 900000); // 5 attempts per 15 minutes
  if (!rateLimitResult.allowed) {
    throw new Error('Too many login attempts. Please try again later.');
  }
  
  // Sanitize inputs
  const sanitizedEmail = SecurityService.sanitizeInput(userEmail.toLowerCase().trim());
  const sanitizedPassword = SecurityService.sanitizeInput(userPassword);
  
  // Mock admin user
  if (sanitizedEmail === 'admin@minimal.gallery' && sanitizedPassword === 'admin123') {
    SecurityService.logSecurityEvent('login_success', { email: sanitizedEmail, role: 'admin' });
    return {
      id: '1',
      email: 'admin@minimal.gallery',
      firstName: 'Admin',
      lastName: 'User',
      role: 'admin',
      createdAt: '2024-01-01T00:00:00Z',
      lastLogin: new Date().toISOString()
    };
  }
  
  // Mock regular user
  if (sanitizedEmail === 'user@example.com' && sanitizedPassword === 'user123') {
    SecurityService.logSecurityEvent('login_success', { email: sanitizedEmail, role: 'user' });
    return {
      id: '2',
      email: 'user@example.com',
      firstName: 'John',
      lastName: 'Doe',
      role: 'user',
      createdAt: '2024-01-01T00:00:00Z',
      lastLogin: new Date().toISOString()
    };
  }
  
  SecurityService.logSecurityEvent('login_failed', { email: sanitizedEmail });
  throw new Error('Invalid email or password');
};

/**
 * Simulate registration API call with validation
 * @param userData - User registration data
 * @returns Promise with new user data
 */
const mockRegister = async (userData: {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
}): Promise<User> => {
  await new Promise(resolve => setTimeout(resolve, 1000));
  
  // Sanitize all inputs
  const sanitizedData = {
    email: SecurityService.sanitizeInput(userData.email.toLowerCase().trim()),
    firstName: SecurityService.sanitizeInput(userData.firstName.trim()),
    lastName: SecurityService.sanitizeInput(userData.lastName.trim()),
    password: SecurityService.sanitizeInput(userData.password)
  };
  
  SecurityService.logSecurityEvent('registration_success', { 
    email: sanitizedData.email,
    firstName: sanitizedData.firstName,
    lastName: sanitizedData.lastName
  });
  
  return {
    id: SecurityService.generateSecureId(16),
    email: sanitizedData.email,
    firstName: sanitizedData.firstName,
    lastName: sanitizedData.lastName,
    role: 'user',
    createdAt: new Date().toISOString()
  };
};

export const useAuthStore = create<AuthStore>()(
  persist(
    (set, get) => ({
      user: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,

      login: async (email: string, password: string) => {
        try {
          set({ isLoading: true, error: null });
          const user = await mockLogin(email, password);
          set({ 
            user, 
            isAuthenticated: true, 
            isLoading: false 
          });
        } catch (error) {
          set({ 
            error: error instanceof Error ? error.message : 'Login failed',
            isLoading: false 
          });
          throw error;
        }
      },

      register: async (userData) => {
        try {
          set({ isLoading: true, error: null });
          const user = await mockRegister(userData);
          set({ 
            user, 
            isAuthenticated: true, 
            isLoading: false 
          });
        } catch (error) {
          set({ 
            error: error instanceof Error ? error.message : 'Registration failed',
            isLoading: false 
          });
          throw error;
        }
      },

      logout: () => {
        set({ 
          user: null, 
          isAuthenticated: false, 
          error: null 
        });
      },

      forgotPassword: async (userEmail: string) => {
        try {
          set({ isLoading: true, error: null });
          await new Promise(resolve => setTimeout(resolve, 1000));
          // Mock success - in production, this would send an email
          SecurityService.logSecurityEvent('password_reset_requested', { 
            email: SecurityService.sanitizeInput(userEmail) 
          });
          set({ isLoading: false });
        } catch (error) {
          set({ 
            error: error instanceof Error ? error.message : 'Failed to send reset email',
            isLoading: false 
          });
          throw error;
        }
      },

      resetPassword: async (resetToken: string, userNewPassword: string) => {
        try {
          set({ isLoading: true, error: null });
          await new Promise(resolve => setTimeout(resolve, 1000));
          // Mock success - in production, this would validate token and update password
          SecurityService.logSecurityEvent('password_reset_completed', { 
            token: SecurityService.sanitizeInput(resetToken).substring(0, 8) + '...',
            passwordLength: userNewPassword.length
          });
          set({ isLoading: false });
        } catch (error) {
          set({ 
            error: error instanceof Error ? error.message : 'Failed to reset password',
            isLoading: false 
          });
          throw error;
        }
      },

      updateProfile: async (userData) => {
        try {
          set({ isLoading: true, error: null });
          await new Promise(resolve => setTimeout(resolve, 1000));
          const currentUser = get().user;
          if (currentUser) {
            const updatedUser = { ...currentUser, ...userData };
            set({ 
              user: updatedUser, 
              isLoading: false 
            });
          }
        } catch (error) {
          set({ 
            error: error instanceof Error ? error.message : 'Failed to update profile',
            isLoading: false 
          });
          throw error;
        }
      },

      setUser: (user) => {
        set({ user, isAuthenticated: !!user });
      },

      setLoading: (loading) => {
        set({ isLoading: loading });
      },

      setError: (error) => {
        set({ error });
      },

      clearError: () => {
        set({ error: null });
      }
    }),
    {
      name: 'auth-storage',
      partialize: (state) => ({ 
        user: state.user, 
        isAuthenticated: state.isAuthenticated 
      })
    }
  )
);

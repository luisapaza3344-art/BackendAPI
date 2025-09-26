import React, { Suspense, lazy, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, useNavigate, useLocation } from 'react-router-dom';
import { ErrorBoundary } from './components/ErrorBoundary';
import { Header } from './components/Header';
import { HeroSection } from './components/HeroSection';
import { CategoryNavigation } from './components/CategoryNavigation';
import { PromotionalBanner } from './components/PromotionalBanner';
import { FeaturedCollections } from './components/FeaturedCollections';
import { TrustSection } from './components/TrustSection';
import { DataProvider } from './components/DataProvider';
import { Footer } from './components/Footer';
import { Button } from './components/ui/button';
import { useThemeStore } from './stores/themeStore';
import { useAuthStore } from './stores/authStore';
import { AuthModal } from './components/auth/AuthModal';
import { SecurityUtils } from './utils/security';
import { initializeSecurityHardening } from './utils/securityHardening';

// Lazy load heavy components for better performance
const ProductsPage = lazy(() => import('./components/ProductsPage').then(module => ({ default: module.ProductsPage })));
const ProductDetail = lazy(() => import('./components/ProductDetail').then(module => ({ default: module.ProductDetail })));
const CollectionsPage = lazy(() => import('./components/CollectionsPage').then(module => ({ default: module.CollectionsPage })));
const CheckoutPage = lazy(() => import('./components/CheckoutPage').then(module => ({ default: module.CheckoutPage })));
const AboutPage = lazy(() => import('./components/AboutPage').then(module => ({ default: module.AboutPage })));
const UserAccount = lazy(() => import('./components/user/UserAccount').then(module => ({ default: module.UserAccount })));
const AdminDashboard = lazy(() => import('./components/admin/AdminDashboard').then(module => ({ default: module.AdminDashboard })));

/**
 * Loading component with accessibility features
 */
const LoadingSpinner: React.FC<{ message?: string }> = ({ message = 'Loading...' }) => (
  <div 
    className="min-h-screen bg-background flex items-center justify-center"
    role="status"
    aria-live="polite"
    aria-label={message}
  >
    <div className="text-center">
      <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto mb-4"></div>
      <p className="text-muted-foreground font-light">{message}</p>
    </div>
  </div>
);

/**
 * Protected route component for authentication
 */
interface ProtectedRouteProps {
  children: React.ReactNode;
  requiresAuth?: boolean;
  requiresAdmin?: boolean;
  redirectTo?: string;
}

const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ 
  children, 
  requiresAuth = false, 
  requiresAdmin = false,
  redirectTo = '/'
}) => {
  const { isAuthenticated, user } = useAuthStore();
  const navigate = useNavigate();

  useEffect(() => {
    if (requiresAuth && !isAuthenticated) {
      navigate(redirectTo);
      window.dispatchEvent(new CustomEvent('open-auth-modal'));
      return;
    }

    if (requiresAdmin && (!isAuthenticated || user?.role !== 'admin')) {
      navigate(redirectTo);
      if (!isAuthenticated) {
        window.dispatchEvent(new CustomEvent('open-auth-modal'));
      }
      return;
    }
  }, [isAuthenticated, user, requiresAuth, requiresAdmin, navigate, redirectTo]);

  if (requiresAuth && !isAuthenticated) {
    return <Navigate to={redirectTo} replace />;
  }

  if (requiresAdmin && (!isAuthenticated || user?.role !== 'admin')) {
    return <Navigate to={redirectTo} replace />;
  }

  return <>{children}</>;
};

/**
 * Home page component
 */
const HomePage: React.FC = () => {
  const navigate = useNavigate();
  
  const handleNavigate = (section: string) => {
    navigate(`/${section}`);
  };

  const handleProductClick = (productId: string) => {
    navigate(`/product/${productId}`);
  };

  return (
    <>
      <HeroSection onNavigate={handleNavigate} />
      <CategoryNavigation onNavigate={handleNavigate} />
      <PromotionalBanner onNavigate={handleNavigate} />
      <FeaturedCollections 
        onProductClick={handleProductClick}
        onNavigate={handleNavigate}
      />
      <TrustSection />
    </>
  );
};

/**
 * Main App component with React Router integration
 */
const AppContent: React.FC = () => {
  const { isDark } = useThemeStore();
  const { isAuthenticated } = useAuthStore();
  const [isAuthModalOpen, setIsAuthModalOpen] = React.useState(false);
  const location = useLocation();
  const navigate = useNavigate();

  // Initialize theme on app load
  useEffect(() => {
    if (isDark) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [isDark]);

  // Security: Initialize security hardening (only in production)
  useEffect(() => {
    try {
      // Only enable full security hardening in production
      if (import.meta.env?.NODE_ENV === 'production') {
        initializeSecurityHardening();
      } else {
        // Basic security in development
        console.log('Development mode - basic security enabled');
      }
      
      SecurityUtils.logSecurityEvent('application_initialized', {
        timestamp: new Date().toISOString(),
        userAgent: navigator.userAgent,
        url: window.location.href,
        route: location.pathname
      });
    } catch (error) {
      console.error('Security initialization failed:', error);
    }

    return () => {
      SecurityUtils.logSecurityEvent('application_destroyed', {
        timestamp: new Date().toISOString()
      });
    };
  }, []);

  // Handle authentication modal
  useEffect(() => {
    const handleAuthModalOpen = () => {
      setIsAuthModalOpen(true);
    };

    const handleCheckoutNavigation = () => {
      navigate('/checkout');
    };

    window.addEventListener('open-auth-modal', handleAuthModalOpen);
    window.addEventListener('navigate-to-checkout', handleCheckoutNavigation);
    
    return () => {
      window.removeEventListener('open-auth-modal', handleAuthModalOpen);
      window.removeEventListener('navigate-to-checkout', handleCheckoutNavigation);
    };
  }, [navigate]);

  // Redirect after successful login
  useEffect(() => {
    if (isAuthenticated && location.pathname === '/') {
      // Check if user was trying to access a protected route
      const intendedRoute = sessionStorage.getItem('intended-route');
      if (intendedRoute) {
        sessionStorage.removeItem('intended-route');
        navigate(intendedRoute);
      }
    }
  }, [isAuthenticated, location.pathname, navigate]);

  // Set page title based on route
  useEffect(() => {
    const routeTitles: Record<string, string> = {
      '/': 'Minimal Gallery - Curated Art Collection',
      '/products': 'Products - Minimal Gallery',
      '/collections': 'Collections - Minimal Gallery',
      '/about': 'About - Minimal Gallery',
      '/account': 'My Account - Minimal Gallery',
      '/admin': 'Admin Dashboard - Minimal Gallery',
      '/checkout': 'Checkout - Minimal Gallery'
    };

    const title = routeTitles[location.pathname] || 'Minimal Gallery';
    document.title = title;

    // Set meta description
    const metaDescription = document.querySelector('meta[name="description"]');
    if (metaDescription) {
      metaDescription.setAttribute('content', 'Discover exceptional contemporary art pieces. Curated collection of premium art prints, sculptures, and home decor.');
    }
  }, [location.pathname]);

  const handleNavigate = (section: string) => {
    navigate(`/${section}`);
  };

  const currentSection = location.pathname.slice(1) || 'home';

  return (
    <div className="min-h-screen bg-background text-foreground transition-colors duration-300">
      {/* Skip to main content for accessibility */}
      <a 
        href="#main-content" 
        className="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 bg-primary text-primary-foreground px-4 py-2 rounded-md z-50"
      >
        Skip to main content
      </a>

      <Header onNavigate={handleNavigate} currentSection={currentSection} />
      
      <main id="main-content" role="main">
        <Suspense fallback={<LoadingSpinner />}>
          <Routes>
            {/* Public Routes */}
            <Route path="/" element={<HomePage />} />
            
            <Route 
              path="/products" 
              element={
                <ProductsPage 
                  onProductClick={(productId: string) => navigate(`/product/${productId}`)} 
                />
              } 
            />
            
            <Route 
              path="/product/:productId" 
              element={
                <ProductDetail 
                  productId={location.pathname.split('/')[2] || ''}
                  onBack={() => navigate('/products')} 
                />
              } 
            />
            
            <Route 
              path="/collections" 
              element={<CollectionsPage onNavigate={handleNavigate} />} 
            />
            
            <Route 
              path="/about" 
              element={<AboutPage onNavigate={handleNavigate} />} 
            />

            {/* Protected Routes */}
            <Route 
              path="/account" 
              element={
                <ProtectedRoute requiresAuth>
                  <UserAccount onBack={() => navigate('/')} />
                </ProtectedRoute>
              } 
            />
            
            <Route 
              path="/checkout" 
              element={
                <ProtectedRoute requiresAuth>
                  <CheckoutPage onBack={() => navigate('/')} />
                </ProtectedRoute>
              } 
            />

            {/* Admin Routes */}
            <Route 
              path="/admin" 
              element={
                <ProtectedRoute requiresAdmin>
                  <AdminDashboard />
                </ProtectedRoute>
              } 
            />

            {/* Catch all route */}
            <Route 
              path="*" 
              element={
                <main className="pt-20 min-h-screen bg-background flex items-center justify-center">
                  <div className="text-center">
                    <h1 className="text-3xl font-light text-foreground mb-4">
                      Page Not Found
                    </h1>
                    <p className="text-muted-foreground mb-6">
                      The page you're looking for doesn't exist.
                    </p>
                    <Button 
                      onClick={() => navigate('/')}
                      className="bg-primary text-primary-foreground hover:bg-primary/90 font-light"
                    >
                      Go Home
                    </Button>
                  </div>
                </main>
              } 
            />
          </Routes>
        </Suspense>
      </main>

      {!location.pathname.startsWith('/admin') && <Footer onNavigate={handleNavigate} />}
      
      <AuthModal 
        isOpen={isAuthModalOpen} 
        onClose={() => setIsAuthModalOpen(false)} 
      />
    </div>
  );
};

/**
 * Root App component with Router and Error Boundary
 */
function App() {
  return (
    <ErrorBoundary>
      <Router>
        <DataProvider>
          <AppContent />
        </DataProvider>
      </Router>
    </ErrorBoundary>
  );
}

export default App;

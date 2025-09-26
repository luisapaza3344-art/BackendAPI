/**
 * Route types and interfaces for type-safe navigation
 */

export type RouteParams = {
  productId?: string;
  collectionId?: string;
  categoryId?: string;
};

export type AppRoute = 
  | 'home'
  | 'products'
  | 'collections'
  | 'about'
  | 'account'
  | 'admin'
  | 'checkout'
  | 'product-detail'
  | 'login'
  | 'register';

export interface NavigationState {
  currentRoute: AppRoute;
  previousRoute?: AppRoute;
  params?: RouteParams;
}

export interface RouteConfig {
  path: string;
  component: React.ComponentType<any>;
  requiresAuth?: boolean;
  requiresAdmin?: boolean;
  title?: string;
  description?: string;
}

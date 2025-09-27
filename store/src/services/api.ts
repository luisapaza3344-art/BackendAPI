// API Configuration and Services - Ultra Professional Backend Integration
// Route all API calls through the Enterprise API Gateway (port 9000) via /api prefix
const API_BASE_URL = (() => {
  const baseUrl = import.meta.env.VITE_API_GATEWAY_URL;
  if (!baseUrl) {
    console.error('❌ VITE_API_GATEWAY_URL environment variable is required for API calls');
    throw new Error('API Gateway URL is required for backend communication');
  }
  // Ensure /api suffix for proper routing
  return baseUrl.endsWith('/api') ? baseUrl : `${baseUrl}/api`;
})();

// API Response Types
export interface ApiCollection {
  id: string;
  title: string;
  subtitle: string;
  image: string;
  category: string;
  featured?: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface ApiProduct {
  id: string;
  name: string;
  price: number;
  image: string;
  images?: string[];
  category: string;
  description: string;
  sizes?: string[];
  colors?: string[];
  inStock: boolean;
  featured?: boolean;
  trending?: boolean;
  tags?: string[];
  createdAt: string;
  updatedAt: string;
}

export interface ApiCategory {
  id: string;
  name: string;
  displayName: string;
  image: string;
  description?: string;
  productCount: number;
}

/**
 * Enhanced API error interface with response body
 */
export interface ApiError extends Error {
  status?: number;
  responseBody?: any;
  code?: string;
}

/**
 * Generic API Client with enhanced error handling and timeouts
 */
class ApiClient {
  private baseUrl: string;
  private headers: Record<string, string>;
  private timeout: number;

  /**
   * Initialize API client
   * @param baseUrl - Base API URL from environment variables
   * @param timeout - Request timeout in milliseconds
   */
  constructor(baseUrl: string = API_BASE_URL, timeout: number = 30000) {
    this.baseUrl = baseUrl;
    this.timeout = timeout;
    this.headers = {
      'Content-Type': 'application/json',
      'X-API-Version': '1.0',
      'X-Client': 'minimal-gallery-web'
    };
  }

  /**
   * Make authenticated API request with timeout and error handling
   * @param endpoint - API endpoint
   * @param options - Fetch options
   * @returns Promise with typed response
   * @throws ApiError with detailed error information
   */
  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);
    
    try {
      const response = await fetch(url, {
        ...options,
        headers: {
          ...this.headers,
          ...options.headers,
        },
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        let responseBody;
        try {
          responseBody = await response.text();
        } catch {
          responseBody = 'Unable to read response body';
        }

        const error: ApiError = new Error(`API Error: ${response.status} ${response.statusText}`);
        error.status = response.status;
        error.responseBody = responseBody;
        
        // Add specific error codes
        if (response.status === 401) {
          error.code = 'UNAUTHORIZED';
        } else if (response.status === 403) {
          error.code = 'FORBIDDEN';
        } else if (response.status === 404) {
          error.code = 'NOT_FOUND';
        } else if (response.status >= 500) {
          error.code = 'SERVER_ERROR';
        }

        throw error;
      }

      return await response.json();
    } catch (error) {
      clearTimeout(timeoutId);
      
      if (error instanceof Error && error.name === 'AbortError') {
        const timeoutError: ApiError = new Error('Request timeout');
        timeoutError.code = 'TIMEOUT';
        throw timeoutError;
      }
      
      console.error(`API Request failed for ${endpoint}:`, {
        message: error instanceof Error ? error.message : 'Unknown error',
        endpoint,
        options
      });
      throw error;
    }
  }

  // Collections API
  async getCollections(): Promise<ApiCollection[]> {
    return this.request<ApiCollection[]>('/collections');
  }

  async getCollection(id: string): Promise<ApiCollection> {
    return this.request<ApiCollection>(`/collections/${id}`);
  }

  // Products API
  async getProducts(params?: {
    category?: string;
    featured?: boolean;
    trending?: boolean;
    search?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ products: ApiProduct[]; total: number }> {
    const searchParams = new URLSearchParams();
    
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) {
          searchParams.append(key, value.toString());
        }
      });
    }

    const endpoint = `/products${searchParams.toString() ? `?${searchParams.toString()}` : ''}`;
    return this.request<{ products: ApiProduct[]; total: number }>(endpoint);
  }

  async getProduct(id: string): Promise<ApiProduct> {
    return this.request<ApiProduct>(`/products/${id}`);
  }

  // Categories API
  async getCategories(): Promise<ApiCategory[]> {
    return this.request<ApiCategory[]>('/categories');
  }

  async getCategory(id: string): Promise<ApiCategory> {
    return this.request<ApiCategory>(`/categories/${id}`);
  }

  // Search API
  async search(query: string, filters?: {
    category?: string;
    priceMin?: number;
    priceMax?: number;
  }): Promise<{ products: ApiProduct[]; collections: ApiCollection[] }> {
    const searchParams = new URLSearchParams({ q: query });
    
    if (filters) {
      Object.entries(filters).forEach(([key, value]) => {
        if (value !== undefined) {
          searchParams.append(key, value.toString());
        }
      });
    }

    return this.request<{ products: ApiProduct[]; collections: ApiCollection[] }>(
      `/search?${searchParams.toString()}`
    );
  }
}

// Create singleton instance
export const apiClient = new ApiClient();

// Fallback data for development/offline mode
export const fallbackCollections: ApiCollection[] = [
  {
    id: 'bestsellers',
    title: 'BESTSELLERS',
    subtitle: 'Our most popular pieces that define contemporary art',
    image: 'https://c.animaapp.com/mf71q0fqV83AAg/img/ai_2.png',
    category: 'art-prints',
    featured: true,
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z'
  },
  {
    id: 'boundless-forms',
    title: 'BOUNDLESS FORMS',
    subtitle: 'Sculptural works that challenge traditional boundaries',
    image: 'https://c.animaapp.com/mf71q0fqV83AAg/img/ai_3.png',
    category: 'figures',
    featured: true,
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z'
  },
  {
    id: 'ethereal-layers',
    title: 'ETHEREAL LAYERS',
    subtitle: 'Abstract compositions with depth and movement',
    image: 'https://c.animaapp.com/mf71q0fqV83AAg/img/ai_4.png',
    category: 'art-prints',
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z'
  },
  {
    id: 'chains',
    title: 'CHAINS',
    subtitle: 'Connected forms exploring unity and separation',
    image: 'https://c.animaapp.com/mf71q0fqV83AAg/img/ai_5.png',
    category: 'home-decor',
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z'
  }
];

export const fallbackProducts: ApiProduct[] = [
  {
    id: '1',
    name: 'Abstract Geometric Print',
    price: 89.99,
    image: 'https://c.animaapp.com/mf71q0fqV83AAg/img/ai_2.png',
    images: ['https://c.animaapp.com/mf71q0fqV83AAg/img/ai_2.png'],
    category: 'art-prints',
    description: 'A stunning abstract geometric print that adds modern sophistication to any space.',
    sizes: ['Small', 'Medium', 'Large'],
    colors: ['Black', 'White', 'Blue'],
    inStock: true,
    featured: true,
    tags: ['abstract', 'geometric', 'modern'],
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z'
  },
  {
    id: '2',
    name: 'Limited Edition Figure',
    price: 149.99,
    image: 'https://c.animaapp.com/mf71q0fqV83AAg/img/ai_3.png',
    images: ['https://c.animaapp.com/mf71q0fqV83AAg/img/ai_3.png'],
    category: 'figures',
    description: 'Collectible figure from our exclusive limited edition series.',
    inStock: true,
    trending: true,
    tags: ['collectible', 'limited-edition', 'figure'],
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z'
  },
  {
    id: '3',
    name: 'Minimalist Art Detail',
    price: 69.99,
    image: 'https://c.animaapp.com/mf71q0fqV83AAg/img/ai_4.png',
    images: ['https://c.animaapp.com/mf71q0fqV83AAg/img/ai_4.png'],
    category: 'art-prints',
    description: 'Clean minimalist design perfect for contemporary interiors.',
    sizes: ['Small', 'Medium', 'Large'],
    colors: ['Black', 'White'],
    inStock: true,
    tags: ['minimalist', 'contemporary', 'clean'],
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z'
  },
  {
    id: '4',
    name: 'Home Decor Collection',
    price: 199.99,
    image: 'https://c.animaapp.com/mf71q0fqV83AAg/img/ai_5.png',
    images: ['https://c.animaapp.com/mf71q0fqV83AAg/img/ai_5.png'],
    category: 'home-decor',
    description: 'Complete home decor set for modern living spaces.',
    inStock: true,
    featured: true,
    tags: ['home-decor', 'modern', 'collection'],
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z'
  },
  {
    id: '5',
    name: 'Contemporary Wall Art',
    price: 129.99,
    image: 'https://c.animaapp.com/mf71q0fqV83AAg/img/ai_2.png',
    images: ['https://c.animaapp.com/mf71q0fqV83AAg/img/ai_2.png'],
    category: 'art-prints',
    description: 'Bold contemporary piece that makes a statement.',
    sizes: ['Medium', 'Large', 'Extra Large'],
    colors: ['Black', 'White', 'Red'],
    inStock: true,
    trending: true,
    tags: ['contemporary', 'wall-art', 'bold'],
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z'
  },
  {
    id: '6',
    name: 'Designer Figure Set',
    price: 299.99,
    image: 'https://c.animaapp.com/mf71q0fqV83AAg/img/ai_3.png',
    images: ['https://c.animaapp.com/mf71q0fqV83AAg/img/ai_3.png'],
    category: 'figures',
    description: 'Premium designer figure set for collectors.',
    inStock: true,
    tags: ['designer', 'premium', 'collector'],
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z'
  }
];

export const fallbackCategories: ApiCategory[] = [
  {
    id: 'all',
    name: 'all',
    displayName: 'All Products',
    image: '',
    productCount: 0
  },
  {
    id: 'art-prints',
    name: 'art-prints',
    displayName: 'Prints',
    image: 'https://c.animaapp.com/mf71q0fqV83AAg/img/ai_2.png',
    description: 'Premium quality prints and wall art',
    productCount: 3
  },
  {
    id: 'figures',
    name: 'figures',
    displayName: 'Sculptures',
    image: 'https://c.animaapp.com/mf71q0fqV83AAg/img/ai_3.png',
    description: 'Collectible figures and sculptures',
    productCount: 2
  },
  {
    id: 'home-decor',
    name: 'home-decor',
    displayName: 'Objects',
    image: 'https://c.animaapp.com/mf71q0fqV83AAg/img/ai_5.png',
    description: 'Home decor and decorative objects',
    productCount: 1
  }
];

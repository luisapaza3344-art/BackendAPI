import { create } from 'zustand';
import { ApiProduct, fallbackProducts } from '@/services/api';

// Convert API product to internal product format
export interface Product extends ApiProduct {}

interface ProductStore {
  products: Product[];
  filteredProducts: Product[];
  selectedCategory: string;
  priceRange: [number, number];
  selectedSizes: string[];
  selectedColors: string[];
  searchQuery: string;
  loading: boolean;
  error: string | null;
  lastUpdated: Date | null;
  
  // Actions
  setProducts: (products: Product[]) => void;
  setSelectedCategory: (category: string) => void;
  setPriceRange: (range: [number, number]) => void;
  setSelectedSizes: (sizes: string[]) => void;
  setSelectedColors: (colors: string[]) => void;
  setSearchQuery: (query: string) => void;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  applyFilters: () => void;
  getProductById: (id: string) => Product | undefined;
  updateProduct: (product: Product) => void;
  addProduct: (product: Product) => void;
  removeProduct: (id: string) => void;
  refreshProducts: () => void;
}

export const useProductStore = create<ProductStore>((set, get) => ({
  products: fallbackProducts,
  filteredProducts: fallbackProducts,
  selectedCategory: 'all',
  priceRange: [0, 1000],
  selectedSizes: [],
  selectedColors: [],
  searchQuery: '',
  loading: false,
  error: null,
  lastUpdated: null,
  
  setProducts: (products) => {
    set({ 
      products, 
      filteredProducts: products,
      lastUpdated: new Date(),
      error: null 
    });
    get().applyFilters();
  },
  
  setSelectedCategory: (category) => {
    set({ selectedCategory: category });
    get().applyFilters();
  },
  
  setPriceRange: (range) => {
    set({ priceRange: range });
    get().applyFilters();
  },
  
  setSelectedSizes: (sizes) => {
    set({ selectedSizes: sizes });
    get().applyFilters();
  },
  
  setSelectedColors: (colors) => {
    set({ selectedColors: colors });
    get().applyFilters();
  },
  
  setSearchQuery: (query) => {
    set({ searchQuery: query });
    get().applyFilters();
  },

  setLoading: (loading) => {
    set({ loading });
  },

  setError: (error) => {
    set({ error });
  },
  
  applyFilters: () => {
    const { products, selectedCategory, priceRange, selectedSizes, selectedColors, searchQuery } = get();
    
    let filtered = products.filter(product => {
      // Category filter
      if (selectedCategory !== 'all' && product.category !== selectedCategory) {
        return false;
      }
      
      // Price filter
      if (product.price < priceRange[0] || product.price > priceRange[1]) {
        return false;
      }
      
      // Size filter
      if (selectedSizes.length > 0 && product.sizes) {
        if (!selectedSizes.some(size => product.sizes?.includes(size))) {
          return false;
        }
      }
      
      // Color filter
      if (selectedColors.length > 0 && product.colors) {
        if (!selectedColors.some(color => product.colors?.includes(color))) {
          return false;
        }
      }
      
      // Search filter
      if (searchQuery) {
        const searchLower = searchQuery.toLowerCase();
        const matchesName = product.name.toLowerCase().includes(searchLower);
        const matchesDescription = product.description.toLowerCase().includes(searchLower);
        const matchesTags = product.tags?.some(tag => tag.toLowerCase().includes(searchLower));
        
        if (!matchesName && !matchesDescription && !matchesTags) {
          return false;
        }
      }
      
      return true;
    });
    
    set({ filteredProducts: filtered });
  },
  
  getProductById: (id) => {
    return get().products.find(product => product.id === id);
  },

  updateProduct: (updatedProduct) => {
    const { products } = get();
    const updatedProducts = products.map(product => 
      product.id === updatedProduct.id ? updatedProduct : product
    );
    set({ 
      products: updatedProducts,
      lastUpdated: new Date()
    });
    get().applyFilters();
  },

  addProduct: (newProduct) => {
    const { products } = get();
    set({ 
      products: [...products, newProduct],
      lastUpdated: new Date()
    });
    get().applyFilters();
  },

  removeProduct: (id) => {
    const { products } = get();
    const filteredProducts = products.filter(product => product.id !== id);
    set({ 
      products: filteredProducts,
      lastUpdated: new Date()
    });
    get().applyFilters();
  },

  refreshProducts: () => {
    // This will be called by components to trigger a refresh
    set({ lastUpdated: new Date() });
  }
}));

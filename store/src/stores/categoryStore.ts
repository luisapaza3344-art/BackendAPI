import { create } from 'zustand';
import { ApiCategory, fallbackCategories } from '@/services/api';

// Convert API category to internal category format
export interface Category extends ApiCategory {
  id: string;
  displayName: string;
}

interface CategoryStore {
  categories: Category[];
  loading: boolean;
  error: string | null;
  lastUpdated: Date | null;
  
  // Actions
  setCategories: (categories: Category[]) => void;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  getCategoryById: (id: string) => Category | undefined;
  getCategoryDisplayName: (id: string) => string;
  updateCategory: (category: Category) => void;
  addCategory: (category: Category) => void;
  removeCategory: (id: string) => void;
  refreshCategories: () => void;
}

export const useCategoryStore = create<CategoryStore>((set, get) => ({
  categories: fallbackCategories,
  loading: false,
  error: null,
  lastUpdated: null,
  
  setCategories: (categories) => {
    set({ 
      categories, 
      lastUpdated: new Date(),
      error: null 
    });
  },

  setLoading: (loading) => {
    set({ loading });
  },

  setError: (error) => {
    set({ error });
  },
  
  getCategoryById: (id) => {
    return get().categories.find(category => category.id === id);
  },

  getCategoryDisplayName: (id) => {
    const category = get().getCategoryById(id);
    return category?.displayName || id;
  },

  updateCategory: (updatedCategory) => {
    const { categories } = get();
    const updatedCategories = categories.map(category => 
      category.id === updatedCategory.id ? updatedCategory : category
    );
    set({ 
      categories: updatedCategories,
      lastUpdated: new Date()
    });
  },

  addCategory: (newCategory) => {
    const { categories } = get();
    set({ 
      categories: [...categories, newCategory],
      lastUpdated: new Date()
    });
  },

  removeCategory: (id) => {
    const { categories } = get();
    const filteredCategories = categories.filter(category => category.id !== id);
    set({ 
      categories: filteredCategories,
      lastUpdated: new Date()
    });
  },

  refreshCategories: () => {
    set({ lastUpdated: new Date() });
  }
}));

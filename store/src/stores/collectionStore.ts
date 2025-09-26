import { create } from 'zustand';
import { ApiCollection, fallbackCollections } from '@/services/api';

// Convert API collection to internal collection format
export interface Collection extends ApiCollection {
  id: string;
  category: string;
}

interface CollectionStore {
  collections: Collection[];
  loading: boolean;
  error: string | null;
  lastUpdated: Date | null;
  
  // Actions
  setCollections: (collections: Collection[]) => void;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  getCollectionById: (id: string) => Collection | undefined;
  getFeaturedCollections: () => Collection[];
  getCollectionsByCategory: (category: string) => Collection[];
  updateCollection: (collection: Collection) => void;
  addCollection: (collection: Collection) => void;
  removeCollection: (id: string) => void;
  refreshCollections: () => void;
}

export const useCollectionStore = create<CollectionStore>((set, get) => ({
  collections: fallbackCollections,
  loading: false,
  error: null,
  lastUpdated: null,
  
  setCollections: (collections) => {
    set({ 
      collections, 
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
  
  getCollectionById: (id) => {
    return get().collections.find(collection => collection.id === id);
  },

  getFeaturedCollections: () => {
    return get().collections.filter(collection => collection.featured);
  },

  getCollectionsByCategory: (category) => {
    if (category === 'all') return get().collections;
    return get().collections.filter(collection => collection.category === category);
  },

  updateCollection: (updatedCollection) => {
    const { collections } = get();
    const updatedCollections = collections.map(collection => 
      collection.id === updatedCollection.id ? updatedCollection : collection
    );
    set({ 
      collections: updatedCollections,
      lastUpdated: new Date()
    });
  },

  addCollection: (newCollection) => {
    const { collections } = get();
    set({ 
      collections: [...collections, newCollection],
      lastUpdated: new Date()
    });
  },

  removeCollection: (id) => {
    const { collections } = get();
    const filteredCollections = collections.filter(collection => collection.id !== id);
    set({ 
      collections: filteredCollections,
      lastUpdated: new Date()
    });
  },

  refreshCollections: () => {
    set({ lastUpdated: new Date() });
  }
}));

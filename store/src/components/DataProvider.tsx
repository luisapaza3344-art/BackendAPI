import React, { useEffect } from 'react';
import { useProductStore } from '@/stores/productStore';
import { useCollectionStore } from '@/stores/collectionStore';
import { useCategoryStore } from '@/stores/categoryStore';
import { useProducts, useCollections, useCategories, useRealTimeUpdates, usePolling } from '@/hooks/useApi';

interface DataProviderProps {
  children: React.ReactNode;
}

export const DataProvider: React.FC<DataProviderProps> = ({ children }) => {
  const productStore = useProductStore();
  const collectionStore = useCollectionStore();
  const categoryStore = useCategoryStore();

  // Fetch initial data
  const { data: productsData, loading: productsLoading, error: productsError, refetch: refetchProducts } = useProducts();
  const { data: collectionsData, loading: collectionsLoading, error: collectionsError, refetch: refetchCollections } = useCollections();
  const { data: categoriesData, loading: categoriesLoading, error: categoriesError, refetch: refetchCategories } = useCategories();

  // Real-time updates
  useRealTimeUpdates();

  // Update stores when data changes
  useEffect(() => {
    if (productsData) {
      productStore.setProducts(productsData.products);
    }
    productStore.setLoading(productsLoading);
    productStore.setError(productsError);
  }, [productsData, productsLoading, productsError]);

  useEffect(() => {
    if (collectionsData) {
      collectionStore.setCollections(collectionsData);
    }
    collectionStore.setLoading(collectionsLoading);
    collectionStore.setError(collectionsError);
  }, [collectionsData, collectionsLoading, collectionsError]);

  useEffect(() => {
    if (categoriesData) {
      categoryStore.setCategories(categoriesData);
    }
    categoryStore.setLoading(categoriesLoading);
    categoryStore.setError(categoriesError);
  }, [categoriesData, categoriesLoading, categoriesError]);

  // Polling fallback for real-time updates
  usePolling(() => {
    refetchProducts();
    refetchCollections();
    refetchCategories();
  }, 60000); // Poll every minute as fallback

  // Global error handling
  useEffect(() => {
    const handleGlobalError = (event: ErrorEvent) => {
      console.error('Global error:', event.error);
    };

    window.addEventListener('error', handleGlobalError);
    
    return () => {
      window.removeEventListener('error', handleGlobalError);
    };
  }, []);

  return <>{children}</>;
};

import { useState, useEffect, useCallback } from 'react';
import { apiClient, ApiCollection, ApiProduct, ApiCategory } from '@/services/api';

// Generic API hook
export function useApi<T>(
  apiCall: () => Promise<T>,
  dependencies: any[] = []
) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const result = await apiCall();
      setData(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
      console.error('API Error:', err);
    } finally {
      setLoading(false);
    }
  }, dependencies);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const refetch = useCallback(() => {
    fetchData();
  }, [fetchData]);

  return { data, loading, error, refetch };
}

// Collections hooks
export function useCollections() {
  return useApi(() => apiClient.getCollections());
}

export function useCollection(id: string) {
  return useApi(() => apiClient.getCollection(id), [id]);
}

// Products hooks
export function useProducts(params?: {
  category?: string;
  featured?: boolean;
  trending?: boolean;
  search?: string;
  limit?: number;
  offset?: number;
}) {
  return useApi(() => apiClient.getProducts(params), [
    params?.category,
    params?.featured,
    params?.trending,
    params?.search,
    params?.limit,
    params?.offset
  ]);
}

export function useProduct(id: string) {
  return useApi(() => apiClient.getProduct(id), [id]);
}

// Categories hooks
export function useCategories() {
  return useApi(() => apiClient.getCategories());
}

export function useCategory(id: string) {
  return useApi(() => apiClient.getCategory(id), [id]);
}

// Search hook
export function useSearch(query: string, filters?: {
  category?: string;
  priceMin?: number;
  priceMax?: number;
}) {
  return useApi(
    () => apiClient.search(query, filters),
    [query, filters?.category, filters?.priceMin, filters?.priceMax]
  );
}

// Real-time updates hook
export function useRealTimeUpdates() {
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date());

  useEffect(() => {
    // WebSocket connection for real-time updates
    const wsUrl = import.meta.env.VITE_WS_URL || 'wss://85a7dab0-f42c-425c-b5f9-606630150d16-00-3lj5tee1xmhhc.janeway.replit.dev:9000';
    
    try {
      const ws = new WebSocket(wsUrl);

      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        
        if (data.type === 'update') {
          setLastUpdate(new Date());
          
          // Dispatch custom events for different update types
          if (data.entity === 'products') {
            window.dispatchEvent(new CustomEvent('products-updated', { detail: data }));
          } else if (data.entity === 'collections') {
            window.dispatchEvent(new CustomEvent('collections-updated', { detail: data }));
          } else if (data.entity === 'categories') {
            window.dispatchEvent(new CustomEvent('categories-updated', { detail: data }));
          }
        }
      };

      ws.onerror = (error) => {
        console.warn('WebSocket connection failed:', error);
      };

      return () => {
        ws.close();
      };
    } catch (error) {
      console.warn('WebSocket not available:', error);
    }
  }, []);

  return { lastUpdate };
}

// Polling hook for fallback when WebSocket is not available
export function usePolling(callback: () => void, interval: number = 30000) {
  useEffect(() => {
    const intervalId = setInterval(callback, interval);
    return () => clearInterval(intervalId);
  }, [callback, interval]);
}

import React, { useEffect } from 'react';
import { motion } from 'framer-motion';
import { useProductStore } from '@/stores/productStore';
import { useCategoryStore } from '@/stores/categoryStore';
import { useCategories, useRealTimeUpdates } from '@/hooks/useApi';

interface Category {
  id: string;
  displayName: string;
  image: string;
  productCount: number;
  description?: string;
}

interface CategoryNavigationProps {
  onNavigate: (section: string) => void;
}

export const CategoryNavigation: React.FC<CategoryNavigationProps> = ({ onNavigate }) => {
  const { setSelectedCategory } = useProductStore();
  const { 
    categories, 
    setCategories, 
    setLoading, 
    setError,
    addCategory,
    updateCategory,
    removeCategory
  } = useCategoryStore();
  
  // Fetch categories from API
  const { data: apiCategories, loading, error, refetch } = useCategories();
  
  // Real-time updates
  useRealTimeUpdates();

  // Update store when API data changes
  useEffect(() => {
    if (apiCategories) {
      setCategories(apiCategories);
    }
    setLoading(loading);
    setError(error);
  }, [apiCategories, loading, error, setCategories, setLoading, setError]);

  // Listen for real-time category updates
  useEffect(() => {
    const handleCategoriesUpdate = (event: CustomEvent) => {
      const { action, data } = event.detail;
      
      switch (action) {
        case 'create':
          addCategory(data);
          break;
        case 'update':
          updateCategory(data);
          break;
        case 'delete':
          removeCategory(data.id);
          break;
        case 'refresh':
          refetch();
          break;
        default:
          refetch();
      }
    };

    window.addEventListener('categories-updated', handleCategoriesUpdate as EventListener);
    
    return () => {
      window.removeEventListener('categories-updated', handleCategoriesUpdate as EventListener);
    };
  }, [addCategory, updateCategory, removeCategory, refetch]);

  const handleCategoryClick = (categoryId: string) => {
    setSelectedCategory(categoryId);
    onNavigate('products');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  // Filter out 'all' category for display and only show categories with images
  const displayCategories = categories.filter(category => 
    category.id !== 'all' && category.image && category.productCount > 0
  );

  if (loading && displayCategories.length === 0) {
    return (
      <section className="py-24 lg:py-32 bg-white">
        <div className="max-w-7xl mx-auto px-6 lg:px-12">
          <div className="flex items-center justify-center min-h-[200px]">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-gray-900"></div>
          </div>
        </div>
      </section>
    );
  }

  if (displayCategories.length === 0) {
    return null; // Don't render if no categories to display
  }

  return (
    <section className="py-24 lg:py-32 bg-white">
      <div className="max-w-7xl mx-auto px-6 lg:px-12">
        <div className="text-center mb-20">
          <h2 className="text-4xl lg:text-5xl font-light text-gray-900 mb-6">
            Collections
          </h2>
          <p className="text-lg text-gray-600 font-light max-w-2xl mx-auto leading-relaxed">
            Explore our carefully curated selections, each piece chosen for its unique character and artistic excellence.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-12">
          {displayCategories.map((category: Category, index: number) => (
            <motion.div
              key={category.id}
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: index * 0.1 }}
              className="group cursor-pointer"
              onClick={() => handleCategoryClick(category.id)}
            >
              <div className="space-y-6">
                <div className="aspect-[4/5] overflow-hidden bg-gray-100">
                  <img
                    src={category.image}
                    alt={category.displayName}
                    className="w-full h-full object-cover transition-transform duration-700 group-hover:scale-105"
                    loading="lazy"
                    onError={(e) => {
                      // Fallback image on error
                      e.currentTarget.src = 'https://via.placeholder.com/400x500/f3f4f6/9ca3af?text=' + encodeURIComponent(category.displayName);
                    }}
                  />
                </div>
                
                <div className="space-y-2">
                  <h3 className="text-2xl font-light text-gray-900 group-hover:text-gray-600 transition-colors">
                    {category.displayName}
                  </h3>
                  <p className="text-sm text-gray-500 font-light tracking-wide">
                    {category.productCount} piece{category.productCount !== 1 ? 's' : ''}
                  </p>
                  {category.description && (
                    <p className="text-xs text-gray-400 font-light">
                      {category.description}
                    </p>
                  )}
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
};

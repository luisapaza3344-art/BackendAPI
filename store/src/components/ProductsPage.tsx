import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { useProductStore, Product } from '@/stores/productStore';
import { useCategoryStore } from '@/stores/categoryStore';
import { useCartStore } from '@/stores/cartStore';
import { useProducts, useRealTimeUpdates } from '@/hooks/useApi';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Button } from '@/components/ui/button';
import { ShoppingCart, Filter, RefreshCw } from 'lucide-react';

interface ProductsPageProps {
  onProductClick: (productId: string) => void;
}

const sortOptions = [
  { value: 'name-asc', label: 'Name A-Z' },
  { value: 'name-desc', label: 'Name Z-A' },
  { value: 'price-asc', label: 'Price Low to High' },
  { value: 'price-desc', label: 'Price High to Low' },
  { value: 'created-desc', label: 'Newest First' },
  { value: 'featured', label: 'Featured First' }
];

export const ProductsPage: React.FC<ProductsPageProps> = ({ onProductClick }) => {
  const { 
    filteredProducts, 
    selectedCategory, 
    setSelectedCategory,
    setProducts,
    setLoading,
    setError,
    loading,
    error,
    addProduct,
    updateProduct,
    removeProduct
  } = useProductStore();
  
  const { categories, getCategoryDisplayName } = useCategoryStore();
  const { addItem } = useCartStore();
  const [sortBy, setSortBy] = useState('name-asc');
  const [showFilters, setShowFilters] = useState(false);

  // Fetch products from API
  const { 
    data: apiProductsData, 
    loading: apiLoading, 
    error: apiError, 
    refetch 
  } = useProducts({
    category: selectedCategory === 'all' ? undefined : selectedCategory
  });
  
  // Real-time updates
  useRealTimeUpdates();

  // Update store when API data changes
  useEffect(() => {
    if (apiProductsData) {
      setProducts(apiProductsData.products);
    }
    setLoading(apiLoading);
    setError(apiError);
  }, [apiProductsData, apiLoading, apiError, setProducts, setLoading, setError]);

  // Listen for real-time product updates
  useEffect(() => {
    const handleProductsUpdate = (event: CustomEvent) => {
      const { action, data } = event.detail;
      
      switch (action) {
        case 'create':
          addProduct(data);
          break;
        case 'update':
          updateProduct(data);
          break;
        case 'delete':
          removeProduct(data.id);
          break;
        case 'refresh':
          refetch();
          break;
        default:
          refetch();
      }
    };

    window.addEventListener('products-updated', handleProductsUpdate as EventListener);
    
    return () => {
      window.removeEventListener('products-updated', handleProductsUpdate as EventListener);
    };
  }, [addProduct, updateProduct, removeProduct, refetch]);

  const handleAddToCart = (e: React.MouseEvent, product: Product) => {
    e.stopPropagation();
    addItem({
      id: product.id,
      name: product.name,
      price: product.price,
      image: product.image
    });
  };

  const handleProductClick = (productId: string) => {
    onProductClick(productId);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  // Sort products
  const sortedProducts = [...filteredProducts].sort((a, b) => {
    switch (sortBy) {
      case 'name-asc':
        return a.name.localeCompare(b.name);
      case 'name-desc':
        return b.name.localeCompare(a.name);
      case 'price-asc':
        return a.price - b.price;
      case 'price-desc':
        return b.price - a.price;
      case 'created-desc':
        return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
      case 'featured':
        return (b.featured ? 1 : 0) - (a.featured ? 1 : 0);
      default:
        return 0;
    }
  });

  if (loading && filteredProducts.length === 0) {
    return (
      <main className="pt-20 min-h-screen bg-white">
        <div className="max-w-7xl mx-auto px-6 lg:px-12 py-16">
          <div className="flex items-center justify-center min-h-[400px]">
            <div className="text-center">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-gray-900 mx-auto mb-4"></div>
              <p className="text-gray-600 font-light">Loading products...</p>
            </div>
          </div>
        </div>
      </main>
    );
  }

  if (error && filteredProducts.length === 0) {
    return (
      <main className="pt-20 min-h-screen bg-white">
        <div className="max-w-7xl mx-auto px-6 lg:px-12 py-16">
          <div className="flex items-center justify-center min-h-[400px]">
            <div className="text-center">
              <p className="text-red-600 mb-4">Error loading products: {error}</p>
              <button
                onClick={() => refetch()}
                className="bg-gray-900 text-white px-6 py-2 rounded font-light hover:bg-gray-800 transition-colors flex items-center gap-2 mx-auto"
              >
                <RefreshCw className="w-4 h-4" />
                Retry
              </button>
            </div>
          </div>
        </div>
      </main>
    );
  }

  return (
    <main className="pt-20 min-h-screen bg-white">
      <div className="max-w-7xl mx-auto px-6 lg:px-12 py-16">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
          className="mb-16"
        >
          <div className="text-center mb-12">
            <h1 className="text-5xl lg:text-6xl font-light text-gray-900 mb-8 tracking-wider">
              PRODUCTS
            </h1>
            
            {/* Category Filter */}
            <div className="flex justify-center items-center space-x-8 mb-8 flex-wrap gap-4">
              {categories.map((category) => (
                <button
                  key={category.id}
                  onClick={() => setSelectedCategory(category.id)}
                  className={`text-sm font-light tracking-widest transition-colors ${
                    selectedCategory === category.id 
                      ? 'text-gray-900 border-b border-gray-900 pb-1' 
                      : 'text-gray-400 hover:text-gray-600'
                  }`}
                >
                  {getCategoryDisplayName(category.id).toUpperCase()}
                </button>
              ))}
            </div>
          </div>

          {/* Controls */}
          <div className="flex justify-between items-center flex-wrap gap-4">
            <div className="flex items-center space-x-4">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setShowFilters(!showFilters)}
                className="text-xs font-light tracking-wide text-gray-500 hover:text-gray-900 hover:bg-transparent p-0 h-auto"
              >
                <Filter className="w-3 h-3 mr-2" />
                Filters
              </Button>
              
              {loading && (
                <div className="flex items-center space-x-2 text-xs text-gray-500">
                  <div className="animate-spin rounded-full h-3 w-3 border-b border-gray-500"></div>
                  <span>Updating...</span>
                </div>
              )}
            </div>

            <div className="flex items-center space-x-6">
              <span className="text-xs text-gray-500 font-light tracking-wide">
                Showing {sortedProducts.length} of {filteredProducts.length} products
              </span>
              
              <div className="flex items-center space-x-3">
                <span className="text-xs text-gray-500 font-light tracking-wide">
                  Sort by:
                </span>
                <Select value={sortBy} onValueChange={setSortBy}>
                  <SelectTrigger className="w-40 h-8 text-xs border-gray-200 bg-white text-gray-900 focus:border-gray-300 focus:ring-0">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-white text-gray-900 border-gray-200">
                    {sortOptions.map(option => (
                      <SelectItem key={option.value} value={option.value} className="text-xs">
                        {option.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
          </div>
        </motion.div>

        {/* Products Grid */}
        {sortedProducts.length === 0 ? (
          <div className="text-center py-24">
            <p className="text-lg text-gray-500 font-light">
              No products found matching your criteria
            </p>
            {selectedCategory !== 'all' && (
              <button
                onClick={() => setSelectedCategory('all')}
                className="mt-4 text-sm text-gray-400 hover:text-gray-600 underline"
              >
                View all products
              </button>
            )}
          </div>
        ) : (
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-x-8 gap-y-16">
            {sortedProducts.map((product, index) => (
              <motion.div
                key={product.id}
                initial={{ opacity: 0, y: 30 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: index * 0.05 }}
                className="group cursor-pointer"
                onClick={() => handleProductClick(product.id)}
              >
                <div className="space-y-4">
                  {/* Product Image */}
                  <div className="relative aspect-square overflow-hidden bg-gray-50">
                    <img
                      src={product.image}
                      alt={product.name}
                      className="w-full h-full object-cover transition-transform duration-500 group-hover:scale-105"
                      loading="lazy"
                      onError={(e) => {
                        // Fallback image on error
                        e.currentTarget.src = 'https://via.placeholder.com/400x400/f3f4f6/9ca3af?text=Product';
                      }}
                    />
                    
                    {/* Badges */}
                    <div className="absolute top-3 left-3 flex flex-col gap-2">
                      {product.featured && (
                        <span className="bg-black/20 backdrop-blur-sm text-white text-xs px-2 py-1 rounded">
                          Featured
                        </span>
                      )}
                      {product.trending && (
                        <span className="bg-green-500/20 backdrop-blur-sm text-white text-xs px-2 py-1 rounded">
                          Trending
                        </span>
                      )}
                    </div>
                    
                    {/* Add to Cart Button - Only visible on hover */}
                    <div className="absolute top-3 right-3 opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                      <button
                        onClick={(e) => handleAddToCart(e, product)}
                        className="w-8 h-8 bg-white/90 backdrop-blur-sm rounded-full flex items-center justify-center text-gray-900 hover:bg-white transition-colors shadow-sm"
                        disabled={!product.inStock}
                      >
                        <ShoppingCart className="w-3 h-3" />
                      </button>
                    </div>

                    {/* Out of Stock Overlay */}
                    {!product.inStock && (
                      <div className="absolute inset-0 bg-white/80 flex items-center justify-center">
                        <span className="text-xs text-gray-500 font-light tracking-wide">
                          SOLD OUT
                        </span>
                      </div>
                    )}
                  </div>
                  
                  {/* Product Info */}
                  <div className="space-y-1 text-center">
                    <h3 className="text-xs font-light text-gray-900 tracking-wide uppercase">
                      {product.name}
                    </h3>
                    <p className="text-xs text-gray-500 font-light">
                      ${product.price.toFixed(2)}
                    </p>
                    {product.tags && product.tags.length > 0 && (
                      <div className="flex justify-center gap-1 mt-2">
                        {product.tags.slice(0, 2).map((tag) => (
                          <span key={tag} className="text-xs text-gray-400 bg-gray-100 px-2 py-1 rounded">
                            {tag}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        )}
      </div>
    </main>
  );
};

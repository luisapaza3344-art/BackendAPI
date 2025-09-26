import React from 'react';
import { motion } from 'framer-motion';
import { useProductStore, Product } from '@/stores/productStore';
import { useCartStore } from '@/stores/cartStore';
import { ShoppingCart } from 'lucide-react';

interface ProductGridProps {
  onProductClick: (productId: string) => void;
}

export const ProductGrid: React.FC<ProductGridProps> = ({ onProductClick }) => {
  const { filteredProducts } = useProductStore();
  const { addItem } = useCartStore();

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

  if (filteredProducts.length === 0) {
    return (
      <div className="flex-1 flex items-center justify-center py-24">
        <div className="text-center">
          <p className="text-lg text-gray-500 font-light">
            No pieces found matching your criteria
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1">
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-12">
        {filteredProducts.map((product, index) => (
          <motion.div
            key={product.id}
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: index * 0.1 }}
            className="group cursor-pointer"
            onClick={() => handleProductClick(product.id)}
          >
            <div className="space-y-4">
              <div className="relative aspect-[4/5] overflow-hidden bg-gray-100">
                <img
                  src={product.image}
                  alt={product.name}
                  className="w-full h-full object-cover transition-transform duration-700 group-hover:scale-105"
                  loading="lazy"
                />
                
                {/* Add to Cart Button */}
                <div className="absolute top-4 right-4 opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                  <button
                    onClick={(e) => handleAddToCart(e, product)}
                    className="w-10 h-10 bg-white/90 backdrop-blur-sm rounded-full flex items-center justify-center text-gray-900 hover:bg-white transition-colors"
                  >
                    <ShoppingCart className="w-4 h-4" />
                  </button>
                </div>
              </div>
              
              <div className="space-y-2">
                <h3 className="text-lg font-light text-gray-900 group-hover:text-gray-600 transition-colors">
                  {product.name}
                </h3>
                
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-500 font-light">
                    ${product.price.toFixed(2)}
                  </span>
                  
                  {!product.inStock && (
                    <span className="text-xs text-gray-400 font-light">
                      Sold Out
                    </span>
                  )}
                </div>
              </div>
            </div>
          </motion.div>
        ))}
      </div>
    </div>
  );
};

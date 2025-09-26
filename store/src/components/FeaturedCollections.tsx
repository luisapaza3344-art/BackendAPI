import React from 'react';
import { motion } from 'framer-motion';
import { Button } from '@/components/ui/button';
import { useProductStore } from '@/stores/productStore';
import { useCartStore } from '@/stores/cartStore';
import { ShoppingCart } from 'lucide-react';

interface Product {
  id: string;
  name: string;
  price: number;
  image: string;
  featured?: boolean;
}

interface FeaturedCollectionsProps {
  onProductClick: (productId: string) => void;
  onNavigate: (section: string) => void;
}

export const FeaturedCollections: React.FC<FeaturedCollectionsProps> = ({ 
  onProductClick, 
  onNavigate 
}) => {
  const { products } = useProductStore();
  const { addItem } = useCartStore();
  
  const featuredProducts = products.filter((p: any) => p.featured).slice(0, 3);

  const handleAddToCart = (e: React.MouseEvent, product: any) => {
    e.stopPropagation();
    addItem({
      id: product.id,
      name: product.name,
      price: product.price,
      image: product.image
    });
  };

  return (
    <section className="py-24 lg:py-32 bg-white">
      <div className="max-w-7xl mx-auto px-6 lg:px-12">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="flex items-end justify-between mb-16"
        >
          <div>
            <h2 className="text-4xl lg:text-5xl font-light text-gray-900 mb-4">
              Featured Works
            </h2>
            <p className="text-lg text-gray-600 font-light max-w-md leading-relaxed">
              A selection of our most celebrated pieces, chosen for their exceptional artistry.
            </p>
          </div>
          <Button
            variant="outline"
            onClick={() => onNavigate('products')}
            className="hidden md:block border-gray-200 bg-white text-gray-900 hover:bg-gray-50 font-light"
          >
            View All
          </Button>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-12">
          {featuredProducts.map((product: any, index: number) => (
            <motion.div
              key={product.id}
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: index * 0.1 }}
              className="group cursor-pointer"
              onClick={() => onProductClick(product.id)}
            >
              <div className="space-y-6">
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
                  <h3 className="text-xl font-light text-gray-900 group-hover:text-gray-600 transition-colors">
                    {product.name}
                  </h3>
                  <p className="text-sm text-gray-500 font-light">
                    ${product.price.toFixed(2)}
                  </p>
                </div>
              </div>
            </motion.div>
          ))}
        </div>

        <div className="text-center mt-12 md:hidden">
          <Button
            variant="outline"
            onClick={() => onNavigate('products')}
            className="border-gray-200 bg-white text-gray-900 hover:bg-gray-50 font-light"
          >
            View All Works
          </Button>
        </div>
      </div>
    </section>
  );
};

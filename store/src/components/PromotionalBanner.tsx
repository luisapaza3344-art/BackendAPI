import React from 'react';
import { Button } from '@/components/ui/button';
import { motion } from 'framer-motion';

interface PromotionalBannerProps {
  onNavigate: (section: string) => void;
}

export const PromotionalBanner: React.FC<PromotionalBannerProps> = ({ onNavigate }) => {
  return (
    <section className="py-24 lg:py-32 bg-gray-50">
      <div className="max-w-7xl mx-auto px-6 lg:px-12">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
          className="text-center max-w-3xl mx-auto"
        >
          <h2 className="text-4xl lg:text-6xl font-light text-gray-900 mb-8 leading-tight">
            Limited Edition
            <br />
            <span className="italic">Exhibition</span>
          </h2>
          
          <p className="text-lg text-gray-600 font-light mb-12 max-w-2xl mx-auto leading-relaxed">
            Discover our exclusive collection featuring works from emerging contemporary artists. 
            Each piece tells a unique story of modern artistic expression.
          </p>
          
          <div className="flex flex-col sm:flex-row gap-6 justify-center">
            <Button
              onClick={() => onNavigate('products')}
              className="bg-gray-900 text-white hover:bg-gray-800 px-8 py-3 text-sm font-light tracking-wide"
            >
              View Exhibition
            </Button>
            <button className="text-sm text-gray-500 font-light tracking-wide hover:text-gray-900 transition-colors">
              Learn More
            </button>
          </div>
        </motion.div>
      </div>
    </section>
  );
};

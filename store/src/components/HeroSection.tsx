import React from 'react';
import { Button } from '@/components/ui/button';
import { motion } from 'framer-motion';

interface HeroSectionProps {
  onNavigate: (section: string) => void;
}

export const HeroSection: React.FC<HeroSectionProps> = ({ onNavigate }) => {
  return (
    <section className="relative min-h-screen flex items-center justify-center bg-background">
      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-6 lg:px-12 py-32">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 items-center">
          {/* Left Content */}
          <motion.div
            initial={{ opacity: 0, x: -30 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.8, delay: 0.2 }}
            className="space-y-8"
          >
            <div className="space-y-6">
              <h1 className="text-5xl lg:text-7xl font-light text-foreground leading-tight">
                Curated
                <br />
                <span className="italic">Art</span>
                <br />
                Collection
              </h1>
              
              <p className="text-lg text-muted-foreground font-light leading-relaxed max-w-md">
                Discover exceptional pieces that transform spaces and inspire minds. 
                Each work carefully selected for its artistic merit and timeless appeal.
              </p>
            </div>
            
            <div className="flex items-center space-x-8">
              <Button
                onClick={() => onNavigate('products')}
                className="bg-primary text-primary-foreground hover:bg-primary/90 px-8 py-3 text-sm font-light tracking-wide transition-colors"
              >
                Explore Collection
              </Button>
              
              <button className="text-sm text-muted-foreground font-light tracking-wide hover:text-foreground transition-colors">
                Learn More
              </button>
            </div>
          </motion.div>

          {/* Right Content - Featured Image */}
          <motion.div
            initial={{ opacity: 0, x: 30 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.8, delay: 0.4 }}
            className="relative"
          >
            <div className="aspect-[4/5] overflow-hidden bg-muted">
              <img
                src="https://c.animaapp.com/mf71q0fqV83AAg/img/ai_2.png"
                alt="Featured artwork"
                className="w-full h-full object-cover"
              />
            </div>
            
            {/* Image Caption */}
            <div className="mt-6 space-y-2">
              <p className="text-sm text-foreground font-light">Abstract Composition #1</p>
              <p className="text-xs text-muted-foreground font-light tracking-wide">Limited Edition Print</p>
            </div>
          </motion.div>
        </div>
      </div>

      {/* Scroll Indicator */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.8, delay: 1 }}
        className="absolute bottom-8 left-1/2 transform -translate-x-1/2"
      >
        <div className="w-px h-16 bg-border"></div>
      </motion.div>
    </section>
  );
};

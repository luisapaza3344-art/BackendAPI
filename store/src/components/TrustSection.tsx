import React from 'react';
import { motion } from 'framer-motion';
import { Shield, Truck, Award, RefreshCw } from 'lucide-react';

const trustFeatures = [
  {
    icon: Award,
    title: 'Authenticity',
    description: 'Every piece is verified and comes with a certificate of authenticity'
  },
  {
    icon: Truck,
    title: 'Worldwide Shipping',
    description: 'Secure delivery to your door, anywhere in the world'
  },
  {
    icon: Shield,
    title: 'Secure Payment',
    description: 'Your transactions are protected with bank-level security'
  },
  {
    icon: RefreshCw,
    title: '30-Day Returns',
    description: 'Not completely satisfied? Return within 30 days'
  }
];

export const TrustSection: React.FC = () => {
  return (
    <section className="py-24 lg:py-32 bg-gray-50">
      <div className="max-w-7xl mx-auto px-6 lg:px-12">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="text-center mb-20"
        >
          <h2 className="text-4xl lg:text-5xl font-light text-gray-900 mb-6">
            Our Promise
          </h2>
          <p className="text-lg text-gray-600 font-light max-w-2xl mx-auto leading-relaxed">
            We are committed to providing an exceptional experience from discovery to delivery.
          </p>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-12">
          {trustFeatures.map((feature, index) => {
            const IconComponent = feature.icon;
            return (
              <motion.div
                key={feature.title}
                initial={{ opacity: 0, y: 30 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, delay: index * 0.1 }}
                className="text-center"
              >
                <div className="w-12 h-12 mx-auto mb-6 flex items-center justify-center">
                  <IconComponent className="w-6 h-6 text-gray-900" />
                </div>
                <h3 className="text-lg font-light text-gray-900 mb-4">
                  {feature.title}
                </h3>
                <p className="text-gray-600 font-light leading-relaxed">
                  {feature.description}
                </p>
              </motion.div>
            );
          })}
        </div>
      </div>
    </section>
  );
};

import React, { useEffect } from 'react';
import { motion } from 'framer-motion';
import { useProductStore } from '@/stores/productStore';
import { useCollectionStore } from '@/stores/collectionStore';
import { useCollections, useRealTimeUpdates } from '@/hooks/useApi';

interface Collection {
  id: string;
  title: string;
  subtitle: string;
  image: string;
  category: string;
  featured?: boolean;
}

interface CollectionsPageProps {
  onNavigate: (section: string) => void;
}

export const CollectionsPage: React.FC<CollectionsPageProps> = ({ onNavigate }) => {
  const { setSelectedCategory } = useProductStore();
  const { 
    collections, 
    setCollections, 
    setLoading, 
    setError,
    addCollection,
    updateCollection,
    removeCollection
  } = useCollectionStore();
  
  // Fetch collections from API
  const { data: apiCollections, loading, error, refetch } = useCollections();
  
  // Real-time updates
  useRealTimeUpdates();

  // Update store when API data changes
  useEffect(() => {
    if (apiCollections) {
      setCollections(apiCollections);
    }
    setLoading(loading);
    setError(error);
  }, [apiCollections, loading, error, setCollections, setLoading, setError]);

  // Listen for real-time collection updates
  useEffect(() => {
    const handleCollectionsUpdate = (event: CustomEvent) => {
      const { action, data } = event.detail;
      
      switch (action) {
        case 'create':
          addCollection(data);
          break;
        case 'update':
          updateCollection(data);
          break;
        case 'delete':
          removeCollection(data.id);
          break;
        case 'refresh':
          refetch();
          break;
        default:
          refetch();
      }
    };

    window.addEventListener('collections-updated', handleCollectionsUpdate as EventListener);
    
    return () => {
      window.removeEventListener('collections-updated', handleCollectionsUpdate as EventListener);
    };
  }, [addCollection, updateCollection, removeCollection, refetch]);

  const handleCollectionClick = (category: string) => {
    setSelectedCategory(category);
    onNavigate('products');
  };

  if (loading && collections.length === 0) {
    return (
      <main className="pt-20 min-h-screen bg-white">
        <div className="max-w-7xl mx-auto px-6 lg:px-12 py-16">
          <div className="flex items-center justify-center min-h-[400px]">
            <div className="text-center">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-gray-900 mx-auto mb-4"></div>
              <p className="text-gray-600 font-light">Loading collections...</p>
            </div>
          </div>
        </div>
      </main>
    );
  }

  if (error && collections.length === 0) {
    return (
      <main className="pt-20 min-h-screen bg-white">
        <div className="max-w-7xl mx-auto px-6 lg:px-12 py-16">
          <div className="flex items-center justify-center min-h-[400px]">
            <div className="text-center">
              <p className="text-red-600 mb-4">Error loading collections: {error}</p>
              <button
                onClick={() => refetch()}
                className="bg-gray-900 text-white px-6 py-2 rounded font-light hover:bg-gray-800 transition-colors"
              >
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
          <h1 className="text-5xl lg:text-7xl font-light text-gray-900 mb-6">
            COLLECTIONS
          </h1>
          {collections.length > 0 && (
            <p className="text-lg text-gray-600 font-light">
              {collections.length} collection{collections.length !== 1 ? 's' : ''} available
            </p>
          )}
        </motion.div>

        {/* Collections Grid */}
        {collections.length > 0 ? (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            {collections.map((collection: Collection, index: number) => (
              <motion.div
                key={collection.id}
                initial={{ opacity: 0, y: 30 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, delay: index * 0.1 }}
                className="group cursor-pointer relative overflow-hidden bg-gray-100"
                onClick={() => handleCollectionClick(collection.category)}
                style={{ aspectRatio: '4/3' }}
              >
                {/* Background Image */}
                <img
                  src={collection.image}
                  alt={collection.title}
                  className="absolute inset-0 w-full h-full object-cover transition-transform duration-700 group-hover:scale-105"
                  onError={(e) => {
                    // Fallback image on error
                    e.currentTarget.src = 'https://via.placeholder.com/800x600/f3f4f6/9ca3af?text=Collection';
                  }}
                />
                
                {/* Overlay */}
                <div className="absolute inset-0 bg-black/20 group-hover:bg-black/30 transition-colors duration-300" />
                
                {/* Content */}
                <div className="absolute inset-0 flex flex-col justify-center items-center text-center p-8">
                  <h2 className="text-3xl lg:text-4xl font-light text-white mb-4 tracking-wider">
                    {collection.title}
                  </h2>
                  <p className="text-lg text-white/90 font-light max-w-md leading-relaxed">
                    {collection.subtitle}
                  </p>
                  {collection.featured && (
                    <div className="absolute top-4 right-4">
                      <span className="bg-white/20 backdrop-blur-sm text-white text-xs px-2 py-1 rounded">
                        Featured
                      </span>
                    </div>
                  )}
                </div>
                
                {/* Hover Effect */}
                <div className="absolute inset-0 border-2 border-white/0 group-hover:border-white/20 transition-colors duration-300" />
              </motion.div>
            ))}
          </div>
        ) : (
          <div className="text-center py-24">
            <p className="text-lg text-gray-500 font-light">
              No collections available at the moment.
            </p>
          </div>
        )}

        {/* Bottom Text */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.4 }}
          className="mt-20 text-center max-w-3xl mx-auto"
        >
          <p className="text-lg text-gray-600 font-light leading-relaxed">
            Each collection represents a unique artistic vision, carefully curated to showcase 
            the diversity and depth of contemporary art. Explore these distinct narratives 
            and discover pieces that resonate with your aesthetic sensibility.
          </p>
        </motion.div>
      </div>
    </main>
  );
};

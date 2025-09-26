import React from 'react';
import { Button } from '@/components/ui/button';
import { Slider } from '@/components/ui/slider';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useProductStore } from '@/stores/productStore';
import { X } from 'lucide-react';

interface ProductFiltersProps {
  isMobile?: boolean;
  onClose?: () => void;
}

const categories = [
  { id: 'all', name: 'All' },
  { id: 'art-prints', name: 'Prints' },
  { id: 'figures', name: 'Sculptures' },
  { id: 'home-decor', name: 'Objects' }
];

export const ProductFilters: React.FC<ProductFiltersProps> = ({ isMobile, onClose }) => {
  const {
    selectedCategory,
    priceRange,
    setSelectedCategory,
    setPriceRange
  } = useProductStore();

  const clearFilters = () => {
    setSelectedCategory('all');
    setPriceRange([0, 500]);
  };

  const FilterContent = () => (
    <div className="space-y-8">
      {isMobile && (
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-light text-gray-900">
            Filter
          </h3>
          <Button
            variant="ghost"
            size="sm"
            onClick={onClose}
            className="p-0 h-auto bg-transparent text-gray-500 hover:text-gray-900 hover:bg-transparent"
          >
            <X className="w-4 h-4" />
          </Button>
        </div>
      )}

      {/* Category Filter */}
      <div className="space-y-4">
        <h4 className="text-sm font-light text-gray-900 tracking-wide">Category</h4>
        <Select value={selectedCategory} onValueChange={setSelectedCategory}>
          <SelectTrigger className="border-gray-200 bg-white text-gray-900 focus:border-gray-300 focus:ring-0">
            <SelectValue />
          </SelectTrigger>
          <SelectContent className="bg-white text-gray-900 border-gray-200">
            {categories.map(category => (
              <SelectItem key={category.id} value={category.id}>
                {category.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Price Range */}
      <div className="space-y-4">
        <h4 className="text-sm font-light text-gray-900 tracking-wide">
          Price Range
        </h4>
        <div className="space-y-3">
          <Slider
            value={priceRange}
            onValueChange={(value) => setPriceRange(value as [number, number])}
            max={500}
            min={0}
            step={10}
            className="w-full"
          />
          <div className="flex justify-between text-xs text-gray-500 font-light">
            <span>${priceRange[0]}</span>
            <span>${priceRange[1]}</span>
          </div>
        </div>
      </div>

      {/* Clear Filters */}
      <Button
        variant="outline"
        onClick={clearFilters}
        className="w-full border-gray-200 bg-white text-gray-900 hover:bg-gray-50 font-light"
      >
        Clear Filters
      </Button>
    </div>
  );

  if (isMobile) {
    return (
      <div className="p-6 bg-white border-b border-gray-100">
        <FilterContent />
      </div>
    );
  }

  return (
    <div className="w-64 bg-white border border-gray-100 p-6 h-fit sticky top-24">
      <h3 className="text-lg font-light text-gray-900 mb-8">
        Filter
      </h3>
      <FilterContent />
    </div>
  );
};

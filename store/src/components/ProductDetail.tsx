import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Separator } from '@/components/ui/separator';
import { useProductStore } from '@/stores/productStore';
import { useCartStore } from '@/stores/cartStore';
import { ArrowLeft, ShoppingCart, Heart, Share2, Star, Minus, Plus } from 'lucide-react';

interface ProductDetailProps {
  productId: string;
  onBack: () => void;
}

export const ProductDetail: React.FC<ProductDetailProps> = ({ productId, onBack }) => {
  const { getProductById } = useProductStore();
  const { addItem } = useCartStore();
  const [selectedSize, setSelectedSize] = useState<string>('');
  const [selectedColor, setSelectedColor] = useState<string>('');
  const [quantity, setQuantity] = useState(1);
  
  const product = getProductById(productId);

  if (!product) {
    return (
      <div className="container mx-auto px-4 py-16 text-center">
        <h2 className="text-2xl font-headings font-bold text-foreground mb-4">
          Product not found
        </h2>
        <Button onClick={onBack} className="bg-primary text-primary-foreground hover:bg-primary/90">
          Go Back
        </Button>
      </div>
    );
  }

  const handleAddToCart = () => {
    for (let i = 0; i < quantity; i++) {
      addItem({
        id: product.id,
        name: product.name,
        price: product.price,
        image: product.image,
        size: selectedSize || undefined,
        color: selectedColor || undefined
      });
    }
  };

  return (
    <div className="container mx-auto px-4 py-8">
      {/* Back Button */}
      <Button
        variant="ghost"
        onClick={onBack}
        className="mb-6 bg-transparent text-foreground hover:bg-muted hover:text-foreground"
      >
        <ArrowLeft className="w-4 h-4 mr-2" />
        Back to Products
      </Button>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-12">
        {/* Product Image */}
        <motion.div
          initial={{ opacity: 0, x: -30 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.6 }}
          className="space-y-4"
        >
          <div className="aspect-square overflow-hidden rounded-lg bg-card border border-border">
            <img
              src={product.image}
              alt={product.name}
              className="w-full h-full object-cover"
            />
          </div>
        </motion.div>

        {/* Product Info */}
        <motion.div
          initial={{ opacity: 0, x: 30 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.6, delay: 0.2 }}
          className="space-y-6"
        >
          {/* Badges */}
          <div className="flex gap-2">
            {product.featured && (
              <Badge className="bg-accent text-accent-foreground font-labels font-medium">
                Featured
              </Badge>
            )}
            {product.trending && (
              <Badge className="bg-success text-success-foreground font-labels font-medium">
                Trending
              </Badge>
            )}
          </div>

          {/* Title and Rating */}
          <div>
            <h1 className="text-3xl lg:text-4xl font-headings font-bold text-foreground mb-4">
              {product.name}
            </h1>
            <div className="flex items-center gap-2 mb-4">
              <div className="flex items-center gap-1">
                {[...Array(5)].map((_, i) => (
                  <Star
                    key={i}
                    className={`w-5 h-5 ${
                      i < 4 ? 'fill-yellow-400 text-yellow-400' : 'text-gray-300'
                    }`}
                  />
                ))}
              </div>
              <span className="text-sm text-muted-foreground font-sans">(4.8) • 124 reviews</span>
            </div>
          </div>

          {/* Price */}
          <div className="text-3xl font-labels font-bold text-foreground">
            ${product.price.toFixed(2)}
          </div>

          <Separator className="bg-border" />

          {/* Options */}
          <div className="space-y-4">
            {product.sizes && product.sizes.length > 0 && (
              <div>
                <label className="text-sm font-labels font-medium text-foreground mb-2 block">
                  Size
                </label>
                <Select value={selectedSize} onValueChange={setSelectedSize}>
                  <SelectTrigger className="bg-background text-foreground border-border">
                    <SelectValue placeholder="Select size" />
                  </SelectTrigger>
                  <SelectContent className="bg-background text-foreground border-border">
                    {product.sizes.map(size => (
                      <SelectItem key={size} value={size}>
                        {size}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}

            {product.colors && product.colors.length > 0 && (
              <div>
                <label className="text-sm font-labels font-medium text-foreground mb-2 block">
                  Color
                </label>
                <Select value={selectedColor} onValueChange={setSelectedColor}>
                  <SelectTrigger className="bg-background text-foreground border-border">
                    <SelectValue placeholder="Select color" />
                  </SelectTrigger>
                  <SelectContent className="bg-background text-foreground border-border">
                    {product.colors.map(color => (
                      <SelectItem key={color} value={color}>
                        {color}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}

            {/* Quantity */}
            <div>
              <label className="text-sm font-labels font-medium text-foreground mb-2 block">
                Quantity
              </label>
              <div className="flex items-center gap-3">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setQuantity(Math.max(1, quantity - 1))}
                  className="bg-background text-foreground border-border hover:bg-muted hover:text-foreground"
                >
                  <Minus className="w-4 h-4" />
                </Button>
                <span className="text-lg font-labels font-medium text-foreground w-12 text-center">
                  {quantity}
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setQuantity(quantity + 1)}
                  className="bg-background text-foreground border-border hover:bg-muted hover:text-foreground"
                >
                  <Plus className="w-4 h-4" />
                </Button>
              </div>
            </div>
          </div>

          <Separator className="bg-border" />

          {/* Actions */}
          <div className="space-y-4">
            <div className="flex gap-4">
              <Button
                size="lg"
                onClick={handleAddToCart}
                disabled={!product.inStock}
                className="flex-1 bg-accent text-accent-foreground hover:bg-accent/90 font-labels font-medium"
              >
                <ShoppingCart className="w-5 h-5 mr-2" />
                Add to Cart
              </Button>
              <Button
                variant="outline"
                size="lg"
                className="bg-background text-foreground border-border hover:bg-muted hover:text-foreground"
              >
                <Heart className="w-5 h-5" />
              </Button>
              <Button
                variant="outline"
                size="lg"
                className="bg-background text-foreground border-border hover:bg-muted hover:text-foreground"
              >
                <Share2 className="w-5 h-5" />
              </Button>
            </div>

            {!product.inStock && (
              <Badge variant="outline" className="text-destructive border-destructive">
                Out of Stock
              </Badge>
            )}
          </div>
        </motion.div>
      </div>

      {/* Product Details Tabs */}
      <motion.div
        initial={{ opacity: 0, y: 30 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, delay: 0.4 }}
        className="mt-16"
      >
        <Tabs defaultValue="description" className="w-full">
          <TabsList className="grid w-full grid-cols-2 bg-muted">
            <TabsTrigger value="description" className="font-labels font-medium">
              Description
            </TabsTrigger>
            <TabsTrigger value="specifications" className="font-labels font-medium">
              Specifications
            </TabsTrigger>
          </TabsList>
          
          <TabsContent value="description" className="mt-6">
            <div className="prose max-w-none">
              <p className="text-foreground font-sans leading-relaxed">
                {product.description}
              </p>
              <p className="text-foreground font-sans leading-relaxed mt-4">
                This premium piece is carefully crafted with attention to detail and quality. 
                Perfect for collectors and art enthusiasts who appreciate fine craftsmanship 
                and unique design elements.
              </p>
            </div>
          </TabsContent>
          
          <TabsContent value="specifications" className="mt-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <h4 className="font-labels font-semibold text-foreground mb-3">Product Details</h4>
                <dl className="space-y-2">
                  <div className="flex justify-between">
                    <dt className="text-muted-foreground font-sans">Category:</dt>
                    <dd className="text-foreground font-sans capitalize">{product.category.replace('-', ' ')}</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-muted-foreground font-sans">SKU:</dt>
                    <dd className="text-foreground font-sans">{product.id.toUpperCase()}</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-muted-foreground font-sans">Availability:</dt>
                    <dd className="text-foreground font-sans">{product.inStock ? 'In Stock' : 'Out of Stock'}</dd>
                  </div>
                </dl>
              </div>
              
              {(product.sizes || product.colors) && (
                <div>
                  <h4 className="font-labels font-semibold text-foreground mb-3">Available Options</h4>
                  <dl className="space-y-2">
                    {product.sizes && (
                      <div className="flex justify-between">
                        <dt className="text-muted-foreground font-sans">Sizes:</dt>
                        <dd className="text-foreground font-sans">{product.sizes.join(', ')}</dd>
                      </div>
                    )}
                    {product.colors && (
                      <div className="flex justify-between">
                        <dt className="text-muted-foreground font-sans">Colors:</dt>
                        <dd className="text-foreground font-sans">{product.colors.join(', ')}</dd>
                      </div>
                    )}
                  </dl>
                </div>
              )}
            </div>
          </TabsContent>
        </Tabs>
      </motion.div>
    </div>
  );
};

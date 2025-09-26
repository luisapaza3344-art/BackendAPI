import React from 'react';
import { X, Plus, Minus, ShoppingBag } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Separator } from '@/components/ui/separator';
import { useCartStore } from '@/stores/cartStore';
import { motion, AnimatePresence } from 'framer-motion';

interface CartItem {
  id: string;
  name: string;
  price: number;
  image: string;
  quantity: number;
  size?: string;
  color?: string;
}

export const CartPanel: React.FC = () => {
  const { items, isOpen, toggleCart, updateQuantity, removeItem, getTotalPrice, clearCart } = useCartStore();
  
  const totalPrice = getTotalPrice();

  return (
    <Dialog open={isOpen} onOpenChange={toggleCart}>
      <DialogContent className="sm:max-w-md bg-background text-foreground border-border">
        <DialogHeader>
          <DialogTitle className="text-xl font-headings font-semibold text-foreground flex items-center gap-2">
            <ShoppingBag className="w-5 h-5" />
            Shopping Cart ({items.length})
          </DialogTitle>
        </DialogHeader>
        
        <div className="max-h-96 overflow-y-auto">
          <AnimatePresence>
            {items.length === 0 ? (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="text-center py-8"
              >
                <ShoppingBag className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
                <p className="text-muted-foreground font-labels">Your cart is empty</p>
              </motion.div>
            ) : (
              <div className="space-y-4">
                {items.map((item: CartItem) => (
                  <motion.div
                    key={item.id}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -20 }}
                    className="flex items-center space-x-4 p-3 bg-muted/30 rounded-lg"
                  >
                    <img
                      src={item.image}
                      alt={item.name}
                      className="w-16 h-16 object-cover rounded-md"
                    />
                    <div className="flex-1 min-w-0">
                      <h4 className="text-sm font-labels font-medium text-foreground truncate">
                        {item.name}
                      </h4>
                      <p className="text-sm text-muted-foreground">
                        ${item.price.toFixed(2)}
                      </p>
                      {item.size && (
                        <p className="text-xs text-muted-foreground">Size: {item.size}</p>
                      )}
                      {item.color && (
                        <p className="text-xs text-muted-foreground">Color: {item.color}</p>
                      )}
                    </div>
                    <div className="flex items-center space-x-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => updateQuantity(item.id, item.quantity - 1)}
                        className="w-8 h-8 p-0 bg-background text-foreground border-border hover:bg-muted hover:text-foreground"
                      >
                        <Minus className="w-3 h-3" />
                      </Button>
                      <span className="text-sm font-labels font-medium text-foreground w-8 text-center">
                        {item.quantity}
                      </span>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => updateQuantity(item.id, item.quantity + 1)}
                        className="w-8 h-8 p-0 bg-background text-foreground border-border hover:bg-muted hover:text-foreground"
                      >
                        <Plus className="w-3 h-3" />
                      </Button>
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => removeItem(item.id)}
                      className="w-8 h-8 p-0 bg-transparent text-muted-foreground hover:bg-destructive/10 hover:text-destructive"
                    >
                      <X className="w-4 h-4" />
                    </Button>
                  </motion.div>
                ))}
              </div>
            )}
          </AnimatePresence>
        </div>

        {items.length > 0 && (
          <>
            <Separator className="bg-border" />
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <span className="text-lg font-headings font-semibold text-foreground">
                  Total: ${totalPrice.toFixed(2)}
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={clearCart}
                  className="bg-background text-muted-foreground border-border hover:bg-destructive/10 hover:text-destructive hover:border-destructive/20"
                >
                  Clear Cart
                </Button>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <Button
                  variant="outline"
                  onClick={toggleCart}
                  className="bg-background text-foreground border-border hover:bg-muted hover:text-foreground"
                >
                  Continue Shopping
                </Button>
                <Button
                  onClick={() => {
                    toggleCart();
                    // This will be handled by the parent component
                    window.dispatchEvent(new CustomEvent('navigate-to-checkout'));
                  }}
                  className="bg-accent text-accent-foreground hover:bg-accent/90"
                >
                  Checkout
                </Button>
              </div>
            </div>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
};

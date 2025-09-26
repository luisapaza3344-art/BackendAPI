import { create } from 'zustand';

export interface CartItem {
  id: string;
  name: string;
  price: number;
  image: string;
  quantity: number;
  size?: string;
  color?: string;
}

interface CartStore {
  items: CartItem[];
  isOpen: boolean;
  addItem: (item: Omit<CartItem, 'quantity'>) => void;
  removeItem: (id: string) => void;
  updateQuantity: (id: string, quantity: number) => void;
  clearCart: () => void;
  toggleCart: () => void;
  getTotalItems: () => number;
  getTotalPrice: () => number;
}

export const useCartStore = create<CartStore>((set, get) => ({
  items: [],
  isOpen: false,
  
  addItem: (item) => {
    const existingItem = get().items.find(i => 
      i.id === item.id && 
      i.size === item.size && 
      i.color === item.color
    );
    if (existingItem) {
      set(state => ({
        items: state.items.map(i => 
          i.id === item.id && i.size === item.size && i.color === item.color
            ? { ...i, quantity: i.quantity + 1 }
            : i
        )
      }));
    } else {
      set(state => ({
        items: [...state.items, { ...item, quantity: 1 }]
      }));
    }
  },
  
  removeItem: (id) => {
    set(state => ({
      items: state.items.filter(item => item.id !== id)
    }));
  },
  
  updateQuantity: (id, quantity) => {
    if (quantity <= 0) {
      get().removeItem(id);
      return;
    }
    set(state => ({
      items: state.items.map(item => 
        item.id === id ? { ...item, quantity } : item
      )
    }));
  },
  
  clearCart: () => {
    set({ items: [] });
  },
  
  toggleCart: () => {
    set(state => ({ isOpen: !state.isOpen }));
  },
  
  getTotalItems: () => {
    return get().items.reduce((total, item) => total + item.quantity, 0);
  },
  
  getTotalPrice: () => {
    return get().items.reduce((total, item) => total + (item.price * item.quantity), 0);
  }
}));

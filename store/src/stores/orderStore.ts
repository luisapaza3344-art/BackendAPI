import { create } from 'zustand';

export interface OrderItem {
  id: string;
  name: string;
  price: number;
  quantity: number;
  image: string;
  size?: string;
  color?: string;
}

export interface Order {
  id: string;
  userId: string;
  userEmail: string;
  items: OrderItem[];
  subtotal: number;
  tax: number;
  shipping: number;
  total: number;
  status: 'pending' | 'processing' | 'shipped' | 'delivered' | 'cancelled';
  paymentStatus: 'pending' | 'paid' | 'failed' | 'refunded';
  paymentMethod: string;
  paymentId?: string;
  trackingNumber?: string;
  shippingAddress: {
    firstName: string;
    lastName: string;
    address: string;
    city: string;
    state: string;
    zipCode: string;
    country: string;
  };
  notes?: string;
  createdAt: string;
  updatedAt: string;
}

interface OrderStore {
  orders: Order[];
  loading: boolean;
  error: string | null;
  
  // Actions
  setOrders: (orders: Order[]) => void;
  addOrder: (order: Order) => void;
  updateOrder: (orderId: string, updates: Partial<Order>) => void;
  updateOrderStatus: (orderId: string, status: Order['status']) => void;
  updatePaymentStatus: (orderId: string, paymentStatus: Order['paymentStatus']) => void;
  updateTrackingNumber: (orderId: string, trackingNumber: string) => void;
  addOrderNotes: (orderId: string, notes: string) => void;
  getOrderById: (orderId: string) => Order | undefined;
  getOrdersByUser: (userId: string) => Order[];
  getOrdersByStatus: (status: Order['status']) => Order[];
  getOrdersByPaymentStatus: (paymentStatus: Order['paymentStatus']) => Order[];
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
}

// Mock orders data
const mockOrders: Order[] = [
  {
    id: 'order-1',
    userId: '2',
    userEmail: 'user@example.com',
    items: [
      {
        id: '1',
        name: 'Abstract Geometric Print',
        price: 89.99,
        quantity: 1,
        image: 'https://c.animaapp.com/mf71q0fqV83AAg/img/ai_2.png',
        size: 'Medium'
      }
    ],
    subtotal: 89.99,
    tax: 7.20,
    shipping: 15.00,
    total: 112.19,
    status: 'processing',
    paymentStatus: 'paid',
    paymentMethod: 'Credit Card',
    paymentId: 'pi_1234567890',
    trackingNumber: 'WNG12345678ABCD',
    shippingAddress: {
      firstName: 'John',
      lastName: 'Doe',
      address: '123 Main St',
      city: 'New York',
      state: 'NY',
      zipCode: '10001',
      country: 'US'
    },
    createdAt: '2024-01-15T10:30:00Z',
    updatedAt: '2024-01-15T10:30:00Z'
  },
  {
    id: 'order-2',
    userId: '3',
    userEmail: 'jane@example.com',
    items: [
      {
        id: '2',
        name: 'Limited Edition Figure',
        price: 149.99,
        quantity: 2,
        image: 'https://c.animaapp.com/mf71q0fqV83AAg/img/ai_3.png'
      }
    ],
    subtotal: 299.98,
    tax: 24.00,
    shipping: 0,
    total: 323.98,
    status: 'shipped',
    paymentStatus: 'paid',
    paymentMethod: 'PayPal',
    paymentId: 'PAYID-ABCDEFG',
    trackingNumber: 'WNG87654321EFGH',
    shippingAddress: {
      firstName: 'Jane',
      lastName: 'Smith',
      address: '456 Oak Ave',
      city: 'Los Angeles',
      state: 'CA',
      zipCode: '90210',
      country: 'US'
    },
    createdAt: '2024-01-14T14:20:00Z',
    updatedAt: '2024-01-16T09:15:00Z'
  }
];

export const useOrderStore = create<OrderStore>((set, get) => ({
  orders: mockOrders,
  loading: false,
  error: null,

  setOrders: (orders) => {
    set({ orders });
  },

  addOrder: (order) => {
    set(state => ({
      orders: [...state.orders, order]
    }));
  },

  updateOrder: (orderId, updates) => {
    set(state => ({
      orders: state.orders.map(order =>
        order.id === orderId
          ? { ...order, ...updates, updatedAt: new Date().toISOString() }
          : order
      )
    }));
  },

  updateOrderStatus: (orderId, status) => {
    get().updateOrder(orderId, { status });
  },

  updatePaymentStatus: (orderId, paymentStatus) => {
    get().updateOrder(orderId, { paymentStatus });
  },

  updateTrackingNumber: (orderId, trackingNumber) => {
    get().updateOrder(orderId, { trackingNumber });
  },

  addOrderNotes: (orderId, notes) => {
    get().updateOrder(orderId, { notes });
  },

  getOrderById: (orderId) => {
    return get().orders.find(order => order.id === orderId);
  },

  getOrdersByUser: (userId) => {
    return get().orders.filter(order => order.userId === userId);
  },

  getOrdersByStatus: (status) => {
    return get().orders.filter(order => order.status === status);
  },

  getOrdersByPaymentStatus: (paymentStatus) => {
    return get().orders.filter(order => order.paymentStatus === paymentStatus);
  },

  setLoading: (loading) => {
    set({ loading });
  },

  setError: (error) => {
    set({ error });
  }
}));

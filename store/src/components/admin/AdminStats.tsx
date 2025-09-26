import React from 'react';
import { motion } from 'framer-motion';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { useProductStore } from '@/stores/productStore';
import { useOrderStore } from '@/stores/orderStore';
import { 
  TrendingUp, 
  Package, 
  ShoppingCart,
  Star,
  AlertTriangle
} from 'lucide-react';

// Define types for products and orders
interface Product {
  id: string;
  name: string;
  image: string;
  inStock: boolean;
  featured?: boolean;
}

interface Order {
  id: string;
  userEmail: string;
  total: number;
  status: string;
  paymentStatus: string;
  createdAt: string;
}

export const AdminStats: React.FC = () => {
  const { products } = useProductStore();
  const { orders } = useOrderStore();

  const totalProducts = products.length;
  const inStockProducts = products.filter((p: any) => p.inStock).length;
  const outOfStockProducts = totalProducts - inStockProducts;
  const featuredProducts = products.filter((p: any) => p.featured).length;

  const totalOrders = orders.length;
  const paidOrders = orders.filter((o: any) => o.paymentStatus === 'paid').length;
  const pendingOrders = orders.filter((o: any) => o.status === 'pending').length;
  const totalRevenue = orders
    .filter((o: any) => o.paymentStatus === 'paid')
    .reduce((sum: number, order: any) => sum + order.total, 0);

  const recentOrders = orders
    .sort((a: any, b: any) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
    .slice(0, 5);

  const lowStockProducts = products.filter((p: any) => !p.inStock);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* Product Stats */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.1 }}
      >
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Package className="w-5 h-5" />
              <span>Product Overview</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="text-center p-4 bg-muted rounded-lg">
                <div className="text-2xl font-bold text-foreground">{totalProducts}</div>
                <div className="text-sm text-muted-foreground">Total Products</div>
              </div>
              <div className="text-center p-4 bg-muted rounded-lg">
                <div className="text-2xl font-bold text-green-600">{inStockProducts}</div>
                <div className="text-sm text-muted-foreground">In Stock</div>
              </div>
              <div className="text-center p-4 bg-muted rounded-lg">
                <div className="text-2xl font-bold text-red-600">{outOfStockProducts}</div>
                <div className="text-sm text-muted-foreground">Out of Stock</div>
              </div>
              <div className="text-center p-4 bg-muted rounded-lg">
                <div className="text-2xl font-bold text-yellow-600">{featuredProducts}</div>
                <div className="text-sm text-muted-foreground">Featured</div>
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Order Stats */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.2 }}
      >
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <ShoppingCart className="w-5 h-5" />
              <span>Order Overview</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="text-center p-4 bg-muted rounded-lg">
                <div className="text-2xl font-bold text-foreground">{totalOrders}</div>
                <div className="text-sm text-muted-foreground">Total Orders</div>
              </div>
              <div className="text-center p-4 bg-muted rounded-lg">
                <div className="text-2xl font-bold text-green-600">{paidOrders}</div>
                <div className="text-sm text-muted-foreground">Paid Orders</div>
              </div>
              <div className="text-center p-4 bg-muted rounded-lg">
                <div className="text-2xl font-bold text-yellow-600">{pendingOrders}</div>
                <div className="text-sm text-muted-foreground">Pending</div>
              </div>
              <div className="text-center p-4 bg-muted rounded-lg">
                <div className="text-2xl font-bold text-blue-600">${totalRevenue.toFixed(0)}</div>
                <div className="text-sm text-muted-foreground">Revenue</div>
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Recent Orders */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.3 }}
      >
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <TrendingUp className="w-5 h-5" />
              <span>Recent Orders</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {recentOrders.map((order: any) => (
                <div key={order.id} className="flex items-center justify-between p-3 bg-muted rounded-lg">
                  <div>
                    <p className="text-sm font-medium">#{order.id.slice(-6).toUpperCase()}</p>
                    <p className="text-xs text-muted-foreground">{order.userEmail}</p>
                  </div>
                  <div className="text-right">
                    <p className="text-sm font-medium">${order.total.toFixed(2)}</p>
                    <p className="text-xs text-muted-foreground capitalize">{order.status}</p>
                  </div>
                </div>
              ))}
              
              {recentOrders.length === 0 && (
                <p className="text-center text-muted-foreground py-4">No recent orders</p>
              )}
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Low Stock Alert */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.4 }}
      >
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <AlertTriangle className="w-5 h-5 text-yellow-600" />
              <span>Stock Alerts</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {lowStockProducts.length > 0 ? (
                lowStockProducts.map((product: any) => (
                  <div key={product.id} className="flex items-center justify-between p-3 bg-yellow-50 dark:bg-yellow-950 rounded-lg">
                    <div className="flex items-center space-x-3">
                      <img
                        src={product.image}
                        alt={product.name}
                        className="w-10 h-10 object-cover rounded"
                      />
                      <div>
                        <p className="text-sm font-medium">{product.name}</p>
                        <p className="text-xs text-muted-foreground">Out of stock</p>
                      </div>
                    </div>
                    <AlertTriangle className="w-4 h-4 text-yellow-600" />
                  </div>
                ))
              ) : (
                <div className="text-center py-4">
                  <Star className="w-8 h-8 text-green-600 mx-auto mb-2" />
                  <p className="text-sm text-muted-foreground">All products are in stock!</p>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
};

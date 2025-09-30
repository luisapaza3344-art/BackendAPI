import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  BarChart3, 
  Package, 
  DollarSign, 
  TrendingUp, 
  ShoppingCart,
  Layers,
  Grid,
  Plus,
  Edit,
  Save,
  X
} from 'lucide-react';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../ui/tabs';
import { Card } from '../ui/card';
import { useAuthStore } from '../../stores/authStore';
import { SEOHead } from '../SEOHead';

interface AdminStats {
  total_revenue: number;
  total_cost: number;
  total_profit: number;
  profit_margin_percent: number;
  total_products: number;
  products_with_stock: number;
  top_profitable_products: ProductProfitInfo[];
}

interface ProductProfitInfo {
  id: string;
  name: string;
  sku: string;
  cost_price: number;
  selling_price: number;
  profit: number;
  profit_margin_percent: number;
  total_stock: number;
}

interface Product {
  id: string;
  name: string;
  sku: string;
  cost_price: number;
  selling_price: number;
  short_description?: string;
  category?: string;
  status?: string;
}

export const AdminDashboard: React.FC = () => {
  const { user } = useAuthStore();
  const [activeTab, setActiveTab] = useState('dashboard');
  const [stats, setStats] = useState<AdminStats | null>(null);
  const [products, setProducts] = useState<Product[]>([]);
  const [loading, setLoading] = useState(false);
  const [editingProduct, setEditingProduct] = useState<string | null>(null);
  const [costPriceEdit, setCostPriceEdit] = useState<Record<string, string>>({});

  // Fetch admin statistics
  const fetchAdminStats = async () => {
    setLoading(true);
    try {
      // TODO: Replace with actual JWT token from authentication service
      // For now, send a placeholder Bearer token
      const response = await fetch('/api/admin/stats', {
        headers: {
          'Authorization': 'Bearer admin-placeholder-token'
        }
      });
      if (response.ok) {
        const data = await response.json();
        setStats(data);
      } else if (response.status === 401) {
        console.error('Unauthorized: Please log in as admin');
      }
    } catch (error) {
      console.error('Failed to fetch admin stats:', error);
    } finally {
      setLoading(false);
    }
  };

  // Fetch all products
  const fetchProducts = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/products');
      if (response.ok) {
        const data = await response.json();
        setProducts(data.products || []);
      }
    } catch (error) {
      console.error('Failed to fetch products:', error);
    } finally {
      setLoading(false);
    }
  };

  // Update product cost price
  const updateCostPrice = async (productId: string, newCostPrice: number) => {
    try {
      // TODO: Replace with actual JWT token from authentication service
      const response = await fetch(`/api/admin/products/${productId}/cost-price`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer admin-placeholder-token'
        },
        body: JSON.stringify({
          cost_price: newCostPrice
        })
      });

      if (response.ok) {
        // Refresh data
        await fetchProducts();
        await fetchAdminStats();
        setEditingProduct(null);
        setCostPriceEdit({});
      }
    } catch (error) {
      console.error('Failed to update cost price:', error);
    }
  };

  useEffect(() => {
    if (activeTab === 'dashboard') {
      fetchAdminStats();
    } else if (activeTab === 'products') {
      fetchProducts();
    }
  }, [activeTab]);

  const formatCurrency = (amount: number) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD'
    }).format(amount);
  };

  return (
    <>
      <SEOHead
        title="Admin Dashboard - Minimal Gallery"
        description="Admin dashboard for managing products, inventory, and profit analytics."
        keywords="admin, dashboard, products, inventory, profits"
      />
      <div className="min-h-screen bg-background py-12">
        <div className="container mx-auto px-4 max-w-7xl">
          {/* Header */}
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            className="mb-8"
          >
            <h1 className="text-4xl font-light text-foreground mb-2">
              Admin Dashboard
            </h1>
            <p className="text-muted-foreground">
              Welcome back, {user?.email || 'Admin'}
            </p>
          </motion.div>

          {/* Tabs */}
          <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
            <TabsList className="grid w-full grid-cols-4 bg-muted mb-8">
              <TabsTrigger value="dashboard" className="flex items-center gap-2">
                <BarChart3 className="w-4 h-4" />
                <span className="hidden sm:inline">Dashboard</span>
              </TabsTrigger>
              <TabsTrigger value="products" className="flex items-center gap-2">
                <Package className="w-4 h-4" />
                <span className="hidden sm:inline">Products</span>
              </TabsTrigger>
              <TabsTrigger value="collections" className="flex items-center gap-2">
                <Layers className="w-4 h-4" />
                <span className="hidden sm:inline">Collections</span>
              </TabsTrigger>
              <TabsTrigger value="categories" className="flex items-center gap-2">
                <Grid className="w-4 h-4" />
                <span className="hidden sm:inline">Categories</span>
              </TabsTrigger>
            </TabsList>

            {/* Dashboard Tab */}
            <TabsContent value="dashboard">
              {loading && (
                <div className="text-center py-12">
                  <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto"></div>
                </div>
              )}

              {!loading && stats && (
                <div className="space-y-6">
                  {/* Stats Cards */}
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                    <Card className="p-6">
                      <div className="flex items-center justify-between mb-4">
                        <DollarSign className="w-8 h-8 text-green-500" />
                        <div className="text-2xl font-bold text-foreground">
                          {formatCurrency(stats.total_revenue)}
                        </div>
                      </div>
                      <div className="text-sm text-muted-foreground">Total Revenue</div>
                    </Card>

                    <Card className="p-6">
                      <div className="flex items-center justify-between mb-4">
                        <ShoppingCart className="w-8 h-8 text-blue-500" />
                        <div className="text-2xl font-bold text-foreground">
                          {formatCurrency(stats.total_cost)}
                        </div>
                      </div>
                      <div className="text-sm text-muted-foreground">Total Cost</div>
                    </Card>

                    <Card className="p-6">
                      <div className="flex items-center justify-between mb-4">
                        <TrendingUp className="w-8 h-8 text-emerald-500" />
                        <div className="text-2xl font-bold text-foreground">
                          {formatCurrency(stats.total_profit)}
                        </div>
                      </div>
                      <div className="text-sm text-muted-foreground">Total Profit</div>
                    </Card>

                    <Card className="p-6">
                      <div className="flex items-center justify-between mb-4">
                        <Package className="w-8 h-8 text-purple-500" />
                        <div className="text-2xl font-bold text-foreground">
                          {stats.total_products}
                        </div>
                      </div>
                      <div className="text-sm text-muted-foreground">Total Products</div>
                    </Card>
                  </div>

                  {/* Profit Margin */}
                  <Card className="p-6">
                    <h3 className="text-xl font-semibold text-foreground mb-4">
                      Profit Margin
                    </h3>
                    <div className="flex items-center gap-4">
                      <div className="flex-1 bg-muted rounded-full h-4 overflow-hidden">
                        <div 
                          className="bg-gradient-to-r from-green-500 to-emerald-500 h-full transition-all duration-500"
                          style={{ width: `${Math.min(stats.profit_margin_percent, 100)}%` }}
                        />
                      </div>
                      <div className="text-2xl font-bold text-foreground">
                        {stats.profit_margin_percent.toFixed(1)}%
                      </div>
                    </div>
                  </Card>

                  {/* Top Profitable Products */}
                  <Card className="p-6">
                    <h3 className="text-xl font-semibold text-foreground mb-4">
                      Top Profitable Products
                    </h3>
                    <div className="space-y-3">
                      {stats.top_profitable_products.slice(0, 5).map((product) => (
                        <div 
                          key={product.id}
                          className="flex items-center justify-between p-3 bg-muted rounded-lg"
                        >
                          <div className="flex-1">
                            <div className="font-medium text-foreground">{product.name}</div>
                            <div className="text-sm text-muted-foreground">
                              SKU: {product.sku} • Stock: {product.total_stock}
                            </div>
                          </div>
                          <div className="text-right">
                            <div className="font-bold text-green-600">
                              {formatCurrency(product.profit)}
                            </div>
                            <div className="text-sm text-muted-foreground">
                              {product.profit_margin_percent.toFixed(1)}% margin
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </Card>
                </div>
              )}
            </TabsContent>

            {/* Products Tab */}
            <TabsContent value="products">
              <div className="space-y-6">
                <div className="flex items-center justify-between">
                  <h2 className="text-2xl font-semibold text-foreground">
                    Product Management
                  </h2>
                  <Button className="flex items-center gap-2">
                    <Plus className="w-4 h-4" />
                    Add Product
                  </Button>
                </div>

                {loading && (
                  <div className="text-center py-12">
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto"></div>
                  </div>
                )}

                {!loading && products.length > 0 && (
                  <div className="space-y-3">
                    {products.map((product) => (
                      <Card key={product.id} className="p-6">
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <h3 className="text-lg font-semibold text-foreground mb-2">
                              {product.name}
                            </h3>
                            <div className="text-sm text-muted-foreground mb-4">
                              SKU: {product.sku} • Category: {product.category || 'N/A'}
                            </div>
                            
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                              <div>
                                <Label className="text-xs text-muted-foreground">Cost Price</Label>
                                {editingProduct === product.id ? (
                                  <Input
                                    type="number"
                                    step="0.01"
                                    value={costPriceEdit[product.id] || product.cost_price}
                                    onChange={(e) => setCostPriceEdit({
                                      ...costPriceEdit,
                                      [product.id]: e.target.value
                                    })}
                                    className="mt-1"
                                  />
                                ) : (
                                  <div className="text-lg font-medium text-foreground">
                                    {formatCurrency(product.cost_price)}
                                  </div>
                                )}
                              </div>

                              <div>
                                <Label className="text-xs text-muted-foreground">Selling Price</Label>
                                <div className="text-lg font-medium text-foreground">
                                  {formatCurrency(product.selling_price)}
                                </div>
                              </div>

                              <div>
                                <Label className="text-xs text-muted-foreground">Profit</Label>
                                <div className="text-lg font-bold text-green-600">
                                  {formatCurrency(product.selling_price - product.cost_price)}
                                </div>
                              </div>
                            </div>
                          </div>

                          <div className="flex items-center gap-2 ml-4">
                            {editingProduct === product.id ? (
                              <>
                                <Button
                                  size="sm"
                                  onClick={() => updateCostPrice(
                                    product.id, 
                                    parseFloat(costPriceEdit[product.id] || String(product.cost_price))
                                  )}
                                  className="flex items-center gap-1"
                                >
                                  <Save className="w-4 h-4" />
                                  Save
                                </Button>
                                <Button
                                  size="sm"
                                  variant="outline"
                                  onClick={() => {
                                    setEditingProduct(null);
                                    setCostPriceEdit({});
                                  }}
                                  className="flex items-center gap-1"
                                >
                                  <X className="w-4 h-4" />
                                  Cancel
                                </Button>
                              </>
                            ) : (
                              <Button
                                size="sm"
                                variant="outline"
                                onClick={() => {
                                  setEditingProduct(product.id);
                                  setCostPriceEdit({
                                    ...costPriceEdit,
                                    [product.id]: String(product.cost_price)
                                  });
                                }}
                                className="flex items-center gap-1"
                              >
                                <Edit className="w-4 h-4" />
                                Edit Cost
                              </Button>
                            )}
                          </div>
                        </div>
                      </Card>
                    ))}
                  </div>
                )}
              </div>
            </TabsContent>

            {/* Collections Tab */}
            <TabsContent value="collections">
              <Card className="p-6">
                <h2 className="text-2xl font-semibold text-foreground mb-4">
                  Collection Management
                </h2>
                <p className="text-muted-foreground">
                  Collection management features coming soon...
                </p>
              </Card>
            </TabsContent>

            {/* Categories Tab */}
            <TabsContent value="categories">
              <Card className="p-6">
                <h2 className="text-2xl font-semibold text-foreground mb-4">
                  Category Management
                </h2>
                <p className="text-muted-foreground">
                  Category management features coming soon...
                </p>
              </Card>
            </TabsContent>
          </Tabs>
        </div>
      </div>
    </>
  );
};

export default AdminDashboard;

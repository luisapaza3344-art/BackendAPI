import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ProductManagement } from './ProductManagement';
import { CollectionManagement } from './CollectionManagement';
import { OrderManagement } from './OrderManagement';
import { AdminStats } from './AdminStats';
import { SEOHead } from '../SEOHead';
import { 
  Package, 
  ShoppingBag, 
  Users, 
  DollarSign,
  TrendingUp
} from 'lucide-react';

export const AdminDashboard: React.FC = () => {
  const [activeTab, setActiveTab] = useState('overview');

  const stats = [
    {
      title: 'Total Revenue',
      value: '$12,345',
      change: '+12.5%',
      icon: DollarSign,
      color: 'text-green-600'
    },
    {
      title: 'Orders',
      value: '156',
      change: '+8.2%',
      icon: ShoppingBag,
      color: 'text-blue-600'
    },
    {
      title: 'Products',
      value: '89',
      change: '+3.1%',
      icon: Package,
      color: 'text-purple-600'
    },
    {
      title: 'Customers',
      value: '1,234',
      change: '+15.3%',
      icon: Users,
      color: 'text-orange-600'
    }
  ];

  return (
    <>
      <SEOHead
        title="Admin Dashboard - Minimal Gallery"
        description="Admin dashboard for managing products, collections, and orders."
        keywords="admin, dashboard, management, products, orders"
      />
      <div className="min-h-screen bg-background p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="mb-8"
        >
          <h1 className="text-3xl font-light text-foreground mb-2">Admin Dashboard</h1>
          <p className="text-muted-foreground font-light">
            Manage your store, products, and orders
          </p>
        </motion.div>

        {/* Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList className="grid w-full grid-cols-4 bg-muted">
            <TabsTrigger value="overview" className="font-light">Overview</TabsTrigger>
            <TabsTrigger value="products" className="font-light">Products</TabsTrigger>
            <TabsTrigger value="collections" className="font-light">Collections</TabsTrigger>
            <TabsTrigger value="orders" className="font-light">Orders</TabsTrigger>
          </TabsList>

          {/* Overview Tab */}
          <TabsContent value="overview" className="space-y-6">
            {/* Stats Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              {stats.map((stat, index) => {
                const IconComponent = stat.icon;
                return (
                  <motion.div
                    key={stat.title}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.5, delay: index * 0.1 }}
                  >
                    <Card>
                      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium text-muted-foreground">
                          {stat.title}
                        </CardTitle>
                        <IconComponent className={`h-4 w-4 ${stat.color}`} />
                      </CardHeader>
                      <CardContent>
                        <div className="text-2xl font-bold text-foreground">{stat.value}</div>
                        <p className={`text-xs ${stat.color} flex items-center mt-1`}>
                          <TrendingUp className="w-3 h-3 mr-1" />
                          {stat.change} from last month
                        </p>
                      </CardContent>
                    </Card>
                  </motion.div>
                );
              })}
            </div>

            {/* Additional Stats */}
            <AdminStats />
          </TabsContent>

          {/* Products Tab */}
          <TabsContent value="products">
            <ProductManagement />
          </TabsContent>

          {/* Collections Tab */}
          <TabsContent value="collections">
            <CollectionManagement />
          </TabsContent>

          {/* Orders Tab */}
          <TabsContent value="orders">
            <OrderManagement />
          </TabsContent>
        </Tabs>
      </div>
    </div>
    </>
  );
};

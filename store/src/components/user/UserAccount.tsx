import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Separator } from '@/components/ui/separator';
import { useAuthStore } from '@/stores/authStore';
import { useOrderStore } from '@/stores/orderStore';
import { 
  User, 
  Package, 
  Truck, 
  CheckCircle, 
  Clock,
  MapPin,
  CreditCard,
  ArrowLeft,
  Copy,
  ExternalLink
} from 'lucide-react';

interface UserAccountProps {
  onBack: () => void;
}

const statusColors = {
  pending: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-950 dark:text-yellow-200',
  processing: 'bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-200',
  shipped: 'bg-purple-100 text-purple-800 dark:bg-purple-950 dark:text-purple-200',
  delivered: 'bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-200',
  cancelled: 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-200'
};

const paymentStatusColors = {
  pending: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-950 dark:text-yellow-200',
  paid: 'bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-200',
  failed: 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-200',
  refunded: 'bg-gray-100 text-gray-800 dark:bg-gray-950 dark:text-gray-200'
};

export const UserAccount: React.FC<UserAccountProps> = ({ onBack }) => {
  const { user, logout } = useAuthStore();
  const { getOrdersByUser } = useOrderStore();
  const [activeTab, setActiveTab] = useState('orders');

  if (!user) {
    return (
      <main className="pt-20 min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <h1 className="text-3xl font-light text-foreground mb-4">
            Please sign in to view your account
          </h1>
          <Button onClick={onBack} className="bg-primary text-primary-foreground hover:bg-primary/90">
            Go Back
          </Button>
        </div>
      </main>
    );
  }

  const userOrders = getOrdersByUser(user.id);

  const copyTrackingNumber = (trackingNumber: string) => {
    navigator.clipboard.writeText(trackingNumber);
    // You could add a toast notification here
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'pending': return <Clock className="w-4 h-4" />;
      case 'processing': return <Package className="w-4 h-4" />;
      case 'shipped': return <Truck className="w-4 h-4" />;
      case 'delivered': return <CheckCircle className="w-4 h-4" />;
      default: return <Package className="w-4 h-4" />;
    }
  };

  return (
    <main className="pt-20 min-h-screen bg-background">
      <div className="max-w-7xl mx-auto px-6 lg:px-12 py-8">
        {/* Back Button */}
        <Button
          variant="ghost"
          onClick={onBack}
          className="mb-6 p-0 h-auto bg-transparent text-muted-foreground hover:text-foreground hover:bg-transparent"
        >
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back
        </Button>

        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="mb-8"
        >
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-light text-foreground mb-2">My Account</h1>
              <p className="text-muted-foreground font-light">
                Welcome back, {user.firstName}
              </p>
            </div>
            <Button
              variant="outline"
              onClick={() => {
                logout();
                onBack();
              }}
              className="font-light"
            >
              Sign Out
            </Button>
          </div>
        </motion.div>

        {/* Account Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList className="grid w-full grid-cols-2 bg-muted max-w-md">
            <TabsTrigger value="orders" className="font-light">My Orders</TabsTrigger>
            <TabsTrigger value="profile" className="font-light">Profile</TabsTrigger>
          </TabsList>

          {/* Orders Tab */}
          <TabsContent value="orders" className="space-y-6">
            <div className="flex items-center justify-between">
              <h2 className="text-2xl font-light text-foreground">Order History</h2>
              <p className="text-sm text-muted-foreground">
                {userOrders.length} order{userOrders.length !== 1 ? 's' : ''}
              </p>
            </div>

            {userOrders.length === 0 ? (
              <Card className="p-12 text-center">
                <Package className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
                <h3 className="text-lg font-medium text-foreground mb-2">No orders yet</h3>
                <p className="text-muted-foreground mb-4">Start shopping to see your orders here</p>
                <Button onClick={() => onBack()}>
                  Browse Products
                </Button>
              </Card>
            ) : (
              <div className="space-y-4">
                {userOrders.map((order, index) => (
                  <motion.div
                    key={order.id}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.3, delay: index * 0.1 }}
                  >
                    <Card>
                      <CardHeader>
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-4">
                            <CardTitle className="text-lg font-medium">
                              Order #{order.id.slice(-6).toUpperCase()}
                            </CardTitle>
                            <Badge className={statusColors[order.status]}>
                              <div className="flex items-center space-x-1">
                                {getStatusIcon(order.status)}
                                <span className="capitalize">{order.status}</span>
                              </div>
                            </Badge>
                            <Badge className={paymentStatusColors[order.paymentStatus]}>
                              <span className="capitalize">{order.paymentStatus}</span>
                            </Badge>
                          </div>
                          <div className="text-right">
                            <p className="text-lg font-semibold">${order.total.toFixed(2)}</p>
                            <p className="text-sm text-muted-foreground">
                              {new Date(order.createdAt).toLocaleDateString()}
                            </p>
                          </div>
                        </div>
                      </CardHeader>
                      
                      <CardContent className="space-y-4">
                        {/* Order Items */}
                        <div className="space-y-3">
                          {order.items.map((item) => (
                            <div key={item.id} className="flex items-center space-x-4 p-3 bg-muted rounded-lg">
                              <img
                                src={item.image}
                                alt={item.name}
                                className="w-12 h-12 object-cover rounded"
                              />
                              <div className="flex-1">
                                <h4 className="text-sm font-medium">{item.name}</h4>
                                <p className="text-xs text-muted-foreground">
                                  Qty: {item.quantity} × ${item.price.toFixed(2)}
                                </p>
                                {item.size && <p className="text-xs text-muted-foreground">Size: {item.size}</p>}
                                {item.color && <p className="text-xs text-muted-foreground">Color: {item.color}</p>}
                              </div>
                              <div className="text-sm font-medium">
                                ${(item.price * item.quantity).toFixed(2)}
                              </div>
                            </div>
                          ))}
                        </div>

                        {/* Tracking Information */}
                        {order.status === 'shipped' && (
                          <div className="bg-blue-50 dark:bg-blue-950 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
                            <div className="flex items-center justify-between">
                              <div className="flex items-center space-x-2">
                                <Truck className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                                <span className="text-sm font-medium text-blue-900 dark:text-blue-100">
                                  Tracking Number
                                </span>
                              </div>
                              <div className="flex items-center space-x-2">
                                <code className="text-sm bg-blue-100 dark:bg-blue-900 px-2 py-1 rounded">
                                  WNG{order.id.slice(-8).toUpperCase()}
                                </code>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  onClick={() => copyTrackingNumber(`WNG${order.id.slice(-8).toUpperCase()}`)}
                                  className="p-1 h-auto"
                                >
                                  <Copy className="w-3 h-3" />
                                </Button>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  className="p-1 h-auto"
                                >
                                  <ExternalLink className="w-3 h-3" />
                                </Button>
                              </div>
                            </div>
                          </div>
                        )}

                        {/* Shipping Address */}
                        <div className="flex items-start space-x-2 text-sm">
                          <MapPin className="w-4 h-4 text-muted-foreground mt-0.5" />
                          <div>
                            <p className="font-medium">Shipping to:</p>
                            <p className="text-muted-foreground">
                              {order.shippingAddress.firstName} {order.shippingAddress.lastName}
                            </p>
                            <p className="text-muted-foreground">
                              {order.shippingAddress.address}, {order.shippingAddress.city}, {order.shippingAddress.state} {order.shippingAddress.zipCode}
                            </p>
                          </div>
                        </div>

                        {/* Payment Method */}
                        <div className="flex items-center space-x-2 text-sm">
                          <CreditCard className="w-4 h-4 text-muted-foreground" />
                          <span>Paid with {order.paymentMethod}</span>
                        </div>
                      </CardContent>
                    </Card>
                  </motion.div>
                ))}
              </div>
            )}
          </TabsContent>

          {/* Profile Tab */}
          <TabsContent value="profile" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <User className="w-5 h-5" />
                  <span>Profile Information</span>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">First Name</p>
                    <p className="text-foreground">{user.firstName}</p>
                  </div>
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">Last Name</p>
                    <p className="text-foreground">{user.lastName}</p>
                  </div>
                  <div className="col-span-2">
                    <p className="text-sm font-medium text-muted-foreground">Email</p>
                    <p className="text-foreground">{user.email}</p>
                  </div>
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">Role</p>
                    <Badge variant="outline" className="capitalize">
                      {user.role}
                    </Badge>
                  </div>
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">Member Since</p>
                    <p className="text-foreground">
                      {new Date(user.createdAt).toLocaleDateString()}
                    </p>
                  </div>
                </div>
                
                <Separator />
                
                <div className="flex justify-end">
                  <Button variant="outline" className="font-light">
                    Edit Profile
                  </Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </main>
  );
};

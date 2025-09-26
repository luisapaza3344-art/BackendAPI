import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Separator } from '@/components/ui/separator';
import { useOrderStore, Order } from '@/stores/orderStore';
import { SecurityService } from '@/services/cryptoService';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { 
  Package, 
  Eye, 
  Truck, 
  CheckCircle, 
  XCircle, 
  Clock,
  DollarSign,
  User,
  MapPin,
  Copy,
  Plus,
  FileText
} from 'lucide-react';

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

export const OrderManagement: React.FC = () => {
  const { 
    orders, 
    updateOrderStatus, 
    updatePaymentStatus, 
    updateTrackingNumber,
    addOrderNotes 
  } = useOrderStore();
  const [selectedOrder, setSelectedOrder] = useState<Order | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [paymentFilter, setPaymentFilter] = useState<string>('all');
  const [newTrackingNumber, setNewTrackingNumber] = useState<string>('');
  const [newNotes, setNewNotes] = useState<string>('');

  const filteredOrders = orders.filter(order => {
    if (statusFilter !== 'all' && order.status !== statusFilter) return false;
    if (paymentFilter !== 'all' && order.paymentStatus !== paymentFilter) return false;
    return true;
  });

  const handleStatusChange = (orderId: string, newStatus: Order['status']) => {
    updateOrderStatus(orderId, newStatus);
  };

  const handlePaymentStatusChange = (orderId: string, newPaymentStatus: Order['paymentStatus']) => {
    updatePaymentStatus(orderId, newPaymentStatus);
  };

  /**
   * Update tracking number for an order
   * @param orderId - Order ID to update
   */
  const handleTrackingNumberUpdate = (orderId: string) => {
    const sanitizedTracking = SecurityService.sanitizeInput(newTrackingNumber.trim());
    if (sanitizedTracking) {
      updateTrackingNumber(orderId, sanitizedTracking);
      setNewTrackingNumber('');
      
      // Log tracking update for audit
      SecurityService.logSecurityEvent('tracking_updated', {
        orderId,
        trackingNumber: sanitizedTracking
      });
    }
  };

  /**
   * Add notes to an order
   * @param orderId - Order ID to update
   */
  const handleNotesUpdate = (orderId: string) => {
    const sanitizedNotes = SecurityService.sanitizeInput(newNotes.trim());
    if (sanitizedNotes) {
      addOrderNotes(orderId, sanitizedNotes);
      setNewNotes('');
      
      // Log notes update for audit
      SecurityService.logSecurityEvent('order_notes_added', {
        orderId,
        notesLength: sanitizedNotes.length
      });
    }
  };

  /**
   * Generate secure tracking number
   */
  const generateTrackingNumber = () => {
    const tracking = SecurityService.generateTrackingNumber();
    setNewTrackingNumber(tracking);
  };

  /**
   * Copy text to clipboard with error handling
   * @param text - Text to copy
   */
  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      // You could add a toast notification here
    } catch (error) {
      console.warn('Failed to copy to clipboard:', error);
      // Fallback for older browsers
      const textArea = document.createElement('textarea');
      textArea.value = text;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand('copy');
      document.body.removeChild(textArea);
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'pending': return <Clock className="w-4 h-4" />;
      case 'processing': return <Package className="w-4 h-4" />;
      case 'shipped': return <Truck className="w-4 h-4" />;
      case 'delivered': return <CheckCircle className="w-4 h-4" />;
      case 'cancelled': return <XCircle className="w-4 h-4" />;
      default: return <Package className="w-4 h-4" />;
    }
  };

  const getPaymentIcon = (status: string) => {
    switch (status) {
      case 'paid': return <CheckCircle className="w-4 h-4" />;
      case 'failed': return <XCircle className="w-4 h-4" />;
      case 'refunded': return <DollarSign className="w-4 h-4" />;
      default: return <Clock className="w-4 h-4" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-light text-foreground">Order Management</h2>
          <p className="text-muted-foreground font-light">
            Track and manage customer orders
          </p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center space-x-4">
        <div className="flex items-center space-x-2">
          <Label className="text-sm font-light">Status:</Label>
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger className="w-40 bg-background border-border">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Status</SelectItem>
              <SelectItem value="pending">Pending</SelectItem>
              <SelectItem value="processing">Processing</SelectItem>
              <SelectItem value="shipped">Shipped</SelectItem>
              <SelectItem value="delivered">Delivered</SelectItem>
              <SelectItem value="cancelled">Cancelled</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <div className="flex items-center space-x-2">
          <Label className="text-sm font-light">Payment:</Label>
          <Select value={paymentFilter} onValueChange={setPaymentFilter}>
            <SelectTrigger className="w-40 bg-background border-border">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Payments</SelectItem>
              <SelectItem value="pending">Pending</SelectItem>
              <SelectItem value="paid">Paid</SelectItem>
              <SelectItem value="failed">Failed</SelectItem>
              <SelectItem value="refunded">Refunded</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <div className="text-sm text-muted-foreground">
          Showing {filteredOrders.length} of {orders.length} orders
        </div>
      </div>

      {/* Orders List */}
      <div className="space-y-4">
        {filteredOrders.map((order, index) => (
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
                      <div className="flex items-center space-x-1">
                        {getPaymentIcon(order.paymentStatus)}
                        <span className="capitalize">{order.paymentStatus}</span>
                      </div>
                    </Badge>
                  </div>
                  
                  <Dialog>
                    <DialogTrigger asChild>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setSelectedOrder(order)}
                      >
                        <Eye className="w-4 h-4 mr-2" />
                        View Details
                      </Button>
                    </DialogTrigger>
                    
                    <DialogContent className="sm:max-w-2xl bg-background text-foreground border-border max-h-[90vh] overflow-y-auto">
                      <DialogHeader>
                        <DialogTitle className="text-xl font-light">
                          Order Details - #{order.id.slice(-6).toUpperCase()}
                        </DialogTitle>
                      </DialogHeader>
                      
                      {selectedOrder && (
                        <div className="space-y-6">
                          {/* Order Info */}
                          <div className="grid grid-cols-2 gap-4">
                            <div>
                              <Label className="text-sm font-medium text-muted-foreground">Order Date</Label>
                              <p className="text-sm">{new Date(selectedOrder.createdAt).toLocaleDateString()}</p>
                            </div>
                            <div>
                              <Label className="text-sm font-medium text-muted-foreground">Customer</Label>
                              <p className="text-sm">{selectedOrder.userEmail}</p>
                            </div>
                            <div>
                              <Label className="text-sm font-medium text-muted-foreground">Payment Method</Label>
                              <p className="text-sm">{selectedOrder.paymentMethod}</p>
                            </div>
                            <div>
                              <Label className="text-sm font-medium text-muted-foreground">Payment ID</Label>
                              <div className="flex items-center space-x-2">
                                <code className="text-xs bg-muted px-2 py-1 rounded">
                                  {selectedOrder.paymentId || 'N/A'}
                                </code>
                                {selectedOrder.paymentId && (
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => copyToClipboard(selectedOrder.paymentId!)}
                                    className="p-1 h-auto"
                                  >
                                    <Copy className="w-3 h-3" />
                                  </Button>
                                )}
                              </div>
                            </div>
                          </div>

                          {/* Status Management */}
                          <div className="grid grid-cols-2 gap-4">
                            <div>
                              <Label className="text-sm font-medium text-muted-foreground">Order Status</Label>
                              <Select 
                                value={selectedOrder.status} 
                                onValueChange={(value) => handleStatusChange(selectedOrder.id, value as Order['status'])}
                              >
                                <SelectTrigger className="mt-1 bg-background border-border">
                                  <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                  <SelectItem value="pending">Pending</SelectItem>
                                  <SelectItem value="processing">Processing</SelectItem>
                                  <SelectItem value="shipped">Shipped</SelectItem>
                                  <SelectItem value="delivered">Delivered</SelectItem>
                                  <SelectItem value="cancelled">Cancelled</SelectItem>
                                </SelectContent>
                              </Select>
                            </div>
                            
                            <div>
                              <Label className="text-sm font-medium text-muted-foreground">Payment Status</Label>
                              <Select 
                                value={selectedOrder.paymentStatus} 
                                onValueChange={(value) => handlePaymentStatusChange(selectedOrder.id, value as Order['paymentStatus'])}
                              >
                                <SelectTrigger className="mt-1 bg-background border-border">
                                  <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                  <SelectItem value="pending">Pending</SelectItem>
                                  <SelectItem value="paid">Paid</SelectItem>
                                  <SelectItem value="failed">Failed</SelectItem>
                                  <SelectItem value="refunded">Refunded</SelectItem>
                                </SelectContent>
                              </Select>
                            </div>
                          </div>

                          <Separator />

                          {/* Tracking Number Management */}
                          <div>
                            <Label className="text-sm font-medium text-muted-foreground mb-3 block">Tracking Information</Label>
                            <div className="space-y-3">
                              {selectedOrder.trackingNumber ? (
                                <div className="flex items-center justify-between p-3 bg-green-50 dark:bg-green-950 border border-green-200 dark:border-green-800 rounded-lg">
                                  <div className="flex items-center space-x-2">
                                    <Truck className="w-4 h-4 text-green-600 dark:text-green-400" />
                                    <span className="text-sm font-medium">Tracking Number:</span>
                                    <code className="text-sm bg-green-100 dark:bg-green-900 px-2 py-1 rounded">
                                      {selectedOrder.trackingNumber}
                                    </code>
                                  </div>
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => copyToClipboard(selectedOrder.trackingNumber!)}
                                    className="p-1 h-auto"
                                  >
                                    <Copy className="w-3 h-3" />
                                  </Button>
                                </div>
                              ) : (
                                <div className="flex items-center space-x-2">
                                  <Input
                                    placeholder="Enter tracking number"
                                    value={newTrackingNumber}
                                    onChange={(e) => setNewTrackingNumber(e.target.value)}
                                    className="flex-1 bg-background border-border"
                                  />
                                  <Button
                                    variant="outline"
                                    size="sm"
                                    onClick={generateTrackingNumber}
                                    className="whitespace-nowrap"
                                  >
                                    Generate
                                  </Button>
                                  <Button
                                    size="sm"
                                    onClick={() => handleTrackingNumberUpdate(selectedOrder.id)}
                                    disabled={!newTrackingNumber.trim()}
                                    className="bg-primary text-primary-foreground hover:bg-primary/90"
                                  >
                                    <Plus className="w-4 h-4" />
                                  </Button>
                                </div>
                              )}
                            </div>
                          </div>

                          <Separator />

                          {/* Order Notes */}
                          <div>
                            <Label className="text-sm font-medium text-muted-foreground mb-3 block">Order Notes</Label>
                            <div className="space-y-3">
                              {selectedOrder.notes && (
                                <div className="p-3 bg-muted rounded-lg">
                                  <div className="flex items-start space-x-2">
                                    <FileText className="w-4 h-4 text-muted-foreground mt-0.5" />
                                    <p className="text-sm">{selectedOrder.notes}</p>
                                  </div>
                                </div>
                              )}
                              
                              <div className="flex items-start space-x-2">
                                <Textarea
                                  placeholder="Add notes about this order..."
                                  value={newNotes}
                                  onChange={(e) => setNewNotes(e.target.value)}
                                  className="flex-1 bg-background border-border"
                                  rows={2}
                                />
                                <Button
                                  size="sm"
                                  onClick={() => handleNotesUpdate(selectedOrder.id)}
                                  disabled={!newNotes.trim()}
                                  className="bg-primary text-primary-foreground hover:bg-primary/90 mt-1"
                                >
                                  <Plus className="w-4 h-4" />
                                </Button>
                              </div>
                            </div>
                          </div>

                          <Separator />

                          {/* Items */}
                          <div>
                            <Label className="text-sm font-medium text-muted-foreground mb-3 block">Order Items</Label>
                            <div className="space-y-3">
                              {selectedOrder.items.map((item) => (
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
                          </div>

                          <Separator />

                          {/* Shipping Address */}
                          <div>
                            <Label className="text-sm font-medium text-muted-foreground mb-3 block">Shipping Address</Label>
                            <div className="bg-muted p-4 rounded-lg">
                              <div className="flex items-start space-x-2">
                                <MapPin className="w-4 h-4 text-muted-foreground mt-0.5" />
                                <div className="text-sm">
                                  <p className="font-medium">
                                    {selectedOrder.shippingAddress.firstName} {selectedOrder.shippingAddress.lastName}
                                  </p>
                                  <p>{selectedOrder.shippingAddress.address}</p>
                                  <p>
                                    {selectedOrder.shippingAddress.city}, {selectedOrder.shippingAddress.state} {selectedOrder.shippingAddress.zipCode}
                                  </p>
                                  <p>{selectedOrder.shippingAddress.country}</p>
                                </div>
                              </div>
                            </div>
                          </div>

                          <Separator />

                          {/* Tracking Number Management */}
                          <div>
                            <Label className="text-sm font-medium text-muted-foreground mb-3 block">Tracking Information</Label>
                            <div className="space-y-3">
                              {selectedOrder.trackingNumber ? (
                                <div className="flex items-center justify-between p-3 bg-green-50 dark:bg-green-950 border border-green-200 dark:border-green-800 rounded-lg">
                                  <div className="flex items-center space-x-2">
                                    <Truck className="w-4 h-4 text-green-600 dark:text-green-400" />
                                    <span className="text-sm font-medium">Tracking:</span>
                                    <code className="text-sm bg-green-100 dark:bg-green-900 px-2 py-1 rounded">
                                      {selectedOrder.trackingNumber}
                                    </code>
                                  </div>
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => copyToClipboard(selectedOrder.trackingNumber!)}
                                    className="p-1 h-auto"
                                  >
                                    <Copy className="w-3 h-3" />
                                  </Button>
                                </div>
                              ) : (
                                <div className="flex items-center space-x-2">
                                  <Input
                                    placeholder="Enter tracking number"
                                    value={newTrackingNumber}
                                    onChange={(e) => setNewTrackingNumber(e.target.value)}
                                    className="flex-1 bg-background border-border"
                                  />
                                  <Button
                                    variant="outline"
                                    size="sm"
                                    onClick={generateTrackingNumber}
                                    className="whitespace-nowrap"
                                  >
                                    Generate
                                  </Button>
                                  <Button
                                    size="sm"
                                    onClick={() => handleTrackingNumberUpdate(selectedOrder.id)}
                                    disabled={!newTrackingNumber.trim()}
                                    className="bg-primary text-primary-foreground hover:bg-primary/90"
                                  >
                                    Add
                                  </Button>
                                </div>
                              )}
                            </div>
                          </div>

                          <Separator />

                          {/* Order Notes */}
                          <div>
                            <Label className="text-sm font-medium text-muted-foreground mb-3 block">Order Notes</Label>
                            <div className="space-y-3">
                              {selectedOrder.notes && (
                                <div className="p-3 bg-muted rounded-lg">
                                  <div className="flex items-start space-x-2">
                                    <FileText className="w-4 h-4 text-muted-foreground mt-0.5" />
                                    <p className="text-sm">{selectedOrder.notes}</p>
                                  </div>
                                </div>
                              )}
                              
                              <div className="flex items-start space-x-2">
                                <Textarea
                                  placeholder="Add notes about this order..."
                                  value={newNotes}
                                  onChange={(e) => setNewNotes(e.target.value)}
                                  className="flex-1 bg-background border-border"
                                  rows={2}
                                />
                                <Button
                                  size="sm"
                                  onClick={() => handleNotesUpdate(selectedOrder.id)}
                                  disabled={!newNotes.trim()}
                                  className="bg-primary text-primary-foreground hover:bg-primary/90 mt-1"
                                >
                                  Add
                                </Button>
                              </div>
                            </div>
                          </div>

                          <Separator />

                          {/* Order Total */}
                          <div className="space-y-2">
                            <div className="flex justify-between text-sm">
                              <span className="text-muted-foreground">Subtotal</span>
                              <span>${selectedOrder.subtotal.toFixed(2)}</span>
                            </div>
                            <div className="flex justify-between text-sm">
                              <span className="text-muted-foreground">Shipping</span>
                              <span>{selectedOrder.shipping === 0 ? 'Free' : `$${selectedOrder.shipping.toFixed(2)}`}</span>
                            </div>
                            <div className="flex justify-between text-sm">
                              <span className="text-muted-foreground">Tax</span>
                              <span>${selectedOrder.tax.toFixed(2)}</span>
                            </div>
                            <Separator />
                            <div className="flex justify-between text-lg font-semibold">
                              <span>Total</span>
                              <span>${selectedOrder.total.toFixed(2)}</span>
                            </div>
                          </div>
                        </div>
                      )}
                    </DialogContent>
                  </Dialog>
                </div>
              </CardHeader>
              
              <CardContent>
                <div className="space-y-3">
                  <div className="flex items-center justify-between text-sm">
                    <div className="flex items-center space-x-2">
                      <User className="w-4 h-4 text-muted-foreground" />
                      <span>{order.userEmail}</span>
                    </div>
                    <span className="font-semibold">${order.total.toFixed(2)}</span>
                  </div>
                  
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground">
                      {order.items.length} item{order.items.length !== 1 ? 's' : ''}
                    </span>
                    <span className="text-muted-foreground">
                      {new Date(order.createdAt).toLocaleDateString()}
                    </span>
                  </div>

                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      <span className="text-xs text-muted-foreground">Payment:</span>
                      <span className="text-xs">{order.paymentMethod}</span>
                    </div>
                    {order.paymentId && (
                      <div className="flex items-center space-x-2">
                        <span className="text-xs text-muted-foreground">Payment ID:</span>
                        <code className="text-xs bg-muted px-1 rounded">{order.paymentId.slice(0, 12)}...</code>
                      </div>
                    )}
                    {order.trackingNumber && (
                      <div className="flex items-center space-x-2">
                        <Truck className="w-3 h-3 text-muted-foreground" />
                        <span className="text-xs">{order.trackingNumber}</span>
                      </div>
                    )}
                  </div>

                  {/* Quick Actions */}
                  <div className="flex items-center space-x-2 pt-2">
                    <Select 
                      value={order.status} 
                      onValueChange={(value) => handleStatusChange(order.id, value as Order['status'])}
                    >
                      <SelectTrigger className="w-32 h-8 text-xs bg-background border-border">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="pending">Pending</SelectItem>
                        <SelectItem value="processing">Processing</SelectItem>
                        <SelectItem value="shipped">Shipped</SelectItem>
                        <SelectItem value="delivered">Delivered</SelectItem>
                        <SelectItem value="cancelled">Cancelled</SelectItem>
                      </SelectContent>
                    </Select>

                    <Select 
                      value={order.paymentStatus} 
                      onValueChange={(value) => handlePaymentStatusChange(order.id, value as Order['paymentStatus'])}
                    >
                      <SelectTrigger className="w-32 h-8 text-xs bg-background border-border">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="pending">Pending</SelectItem>
                        <SelectItem value="paid">Paid</SelectItem>
                        <SelectItem value="failed">Failed</SelectItem>
                        <SelectItem value="refunded">Refunded</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>

      {filteredOrders.length === 0 && (
        <Card className="p-12 text-center">
          <Package className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
          <h3 className="text-lg font-medium text-foreground mb-2">No orders found</h3>
          <p className="text-muted-foreground">
            {statusFilter !== 'all' || paymentFilter !== 'all' 
              ? 'Try adjusting your filters' 
              : 'Orders will appear here when customers make purchases'
            }
          </p>
        </Card>
      )}
    </div>
  );
};

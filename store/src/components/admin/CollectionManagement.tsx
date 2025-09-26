import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { useCollectionStore } from '@/stores/collectionStore';
import { Plus, Edit, Trash2, Image, AlertCircle } from 'lucide-react';

export const CollectionManagement: React.FC = () => {
  const { collections, addCollection, updateCollection, removeCollection } = useCollectionStore();
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [editingCollection, setEditingCollection] = useState<any>(null);
  const [formData, setFormData] = useState({
    title: '',
    subtitle: '',
    image: '',
    category: '',
    featured: false
  });

  const resetForm = () => {
    setFormData({
      title: '',
      subtitle: '',
      image: '',
      category: '',
      featured: false
    });
  };

  const handleEdit = (collection: any) => {
    setEditingCollection(collection);
    setFormData({
      title: collection.title,
      subtitle: collection.subtitle,
      image: collection.image,
      category: collection.category,
      featured: collection.featured || false
    });
    setIsAddModalOpen(true);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    const collectionData = {
      title: formData.title,
      subtitle: formData.subtitle,
      image: formData.image,
      category: formData.category,
      featured: formData.featured,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    if (editingCollection) {
      updateCollection({ ...editingCollection, ...collectionData });
    } else {
      addCollection({
        id: Date.now().toString(),
        ...collectionData
      });
    }

    setIsAddModalOpen(false);
    setEditingCollection(null);
    resetForm();
  };

  const handleDelete = (collectionId: string) => {
    if (confirm('Are you sure you want to delete this collection?')) {
      removeCollection(collectionId);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-light text-foreground">Collection Management</h2>
          <p className="text-muted-foreground font-light">
            Manage your product collections
          </p>
        </div>
        
        <Dialog open={isAddModalOpen} onOpenChange={setIsAddModalOpen}>
          <DialogTrigger asChild>
            <Button 
              onClick={() => {
                resetForm();
                setEditingCollection(null);
              }}
              className="bg-primary text-primary-foreground hover:bg-primary/90"
            >
              <Plus className="w-4 h-4 mr-2" />
              Add Collection
            </Button>
          </DialogTrigger>
          
          <DialogContent className="sm:max-w-lg bg-background text-foreground border-border">
            <DialogHeader>
              <DialogTitle className="text-xl font-light">
                {editingCollection ? 'Edit Collection' : 'Add New Collection'}
              </DialogTitle>
            </DialogHeader>
            
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <Label htmlFor="title">Collection Title</Label>
                <Input
                  id="title"
                  value={formData.title}
                  onChange={(e) => setFormData(prev => ({ ...prev, title: e.target.value }))}
                  required
                  className="bg-background border-border"
                  placeholder="COLLECTION NAME"
                />
              </div>

              <div>
                <Label htmlFor="subtitle">Subtitle</Label>
                <Textarea
                  id="subtitle"
                  value={formData.subtitle}
                  onChange={(e) => setFormData(prev => ({ ...prev, subtitle: e.target.value }))}
                  required
                  className="bg-background border-border"
                  rows={2}
                  placeholder="Brief description of the collection"
                />
              </div>

              <div>
                <Label htmlFor="image">Image URL</Label>
                <Input
                  id="image"
                  value={formData.image}
                  onChange={(e) => setFormData(prev => ({ ...prev,  image: e.target.value }))}
                  required
                  className="bg-background border-border"
                  placeholder="https://example.com/image.jpg"
                />
              </div>

              <div>
                <Label htmlFor="category">Category</Label>
                <Select value={formData.category} onValueChange={(value) => setFormData(prev => ({ ...prev, category: value }))}>
                  <SelectTrigger className="bg-background border-border">
                    <SelectValue placeholder="Select category" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="art-prints">Art Prints</SelectItem>
                    <SelectItem value="figures">Figures</SelectItem>
                    <SelectItem value="home-decor">Home Decor</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="featured"
                  checked={formData.featured}
                  onChange={(e) => setFormData(prev => ({ ...prev, featured: e.target.checked }))}
                  className="rounded border-border"
                />
                <Label htmlFor="featured" className="text-sm">Featured Collection</Label>
              </div>

              <div className="flex justify-end space-x-3 pt-4">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => {
                    setIsAddModalOpen(false);
                    setEditingCollection(null);
                    resetForm();
                  }}
                >
                  Cancel
                </Button>
                <Button type="submit" className="bg-primary text-primary-foreground hover:bg-primary/90">
                  {editingCollection ? 'Update Collection' : 'Add Collection'}
                </Button>
              </div>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      {/* Collections Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {collections.map((collection, index) => (
          <motion.div
            key={collection.id}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3, delay: index * 0.1 }}
          >
            <Card className="overflow-hidden">
              <div className="aspect-[4/3] overflow-hidden">
                <img
                  src={collection.image}
                  alt={collection.title}
                  className="w-full h-full object-cover"
                />
              </div>
              
              <CardHeader className="pb-2">
                <div className="flex items-start justify-between">
                  <CardTitle className="text-lg font-medium">
                    {collection.title}
                  </CardTitle>
                  <div className="flex space-x-1">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleEdit(collection)}
                      className="p-1 h-auto"
                    >
                      <Edit className="w-4 h-4" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleDelete(collection.id)}
                      className="p-1 h-auto text-red-600 hover:text-red-700"
                    >
                      <Trash2 className="w-4 h-4" />
                    </Button>
                  </div>
                </div>
              </CardHeader>
              
              <CardContent className="pt-0">
                <div className="space-y-2">
                  <p className="text-sm text-muted-foreground line-clamp-2">
                    {collection.subtitle}
                  </p>
                  
                  <div className="flex items-center justify-between">
                    <Badge variant="outline" className="text-xs capitalize">
                      {collection.category.replace('-', ' ')}
                    </Badge>
                    {collection.featured && (
                      <Badge className="text-xs">Featured</Badge>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>

      {collections.length === 0 && (
        <Card className="p-12 text-center">
          <Image className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
          <h3 className="text-lg font-medium text-foreground mb-2">No collections yet</h3>
          <p className="text-muted-foreground mb-4">Create your first collection to showcase your products</p>
          <Button onClick={() => setIsAddModalOpen(true)}>
            <Plus className="w-4 h-4 mr-2" />
            Add Collection
          </Button>
        </Card>
      )}
    </div>
  );
};

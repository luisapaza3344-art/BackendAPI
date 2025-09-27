import React from 'react';
import { Link } from 'react-router-dom';
import { ShoppingBag, User, Menu, X, Shield } from 'lucide-react';

interface HeaderProps {
  onNavigate: (section: string) => void;
  currentSection: string;
}

export const Header: React.FC<HeaderProps> = ({ onNavigate, currentSection }) => {
  const [isMenuOpen, setIsMenuOpen] = React.useState(false);

  const navigation = [
    { name: 'Home', id: 'home', href: '/' },
    { name: 'Products', id: 'products', href: '/products' },
    { name: 'Collections', id: 'collections', href: '/collections' },
    { name: 'About', id: 'about', href: '/about' },
    { name: 'Health Check', id: 'health', href: '/health' },
  ];

  return (
    <header className="bg-white shadow-sm border-b border-gray-200 sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          {/* Logo */}
          <Link to="/" className="flex items-center space-x-2">
            <Shield className="h-8 w-8 text-blue-600" />
            <span className="text-xl font-bold text-gray-900">Ultra Professional Gateway</span>
          </Link>

          {/* Desktop Navigation */}
          <nav className="hidden md:flex space-x-8">
            {navigation.map((item) => (
              <Link
                key={item.id}
                to={item.href}
                className={`px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                  currentSection === item.id || (currentSection === 'home' && item.id === 'home')
                    ? 'text-blue-600 bg-blue-50'
                    : 'text-gray-700 hover:text-blue-600 hover:bg-gray-50'
                }`}
                onClick={() => onNavigate(item.id)}
              >
                {item.name}
              </Link>
            ))}
          </nav>

          {/* Right side */}
          <div className="flex items-center space-x-4">
            <Link
              to="/account"
              className="p-2 text-gray-700 hover:text-blue-600 transition-colors"
            >
              <User className="h-5 w-5" />
            </Link>
            <Link
              to="/checkout"
              className="p-2 text-gray-700 hover:text-blue-600 transition-colors"
            >
              <ShoppingBag className="h-5 w-5" />
            </Link>

            {/* Mobile menu button */}
            <button
              className="md:hidden p-2 text-gray-700 hover:text-blue-600"
              onClick={() => setIsMenuOpen(!isMenuOpen)}
            >
              {isMenuOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
            </button>
          </div>
        </div>

        {/* Mobile Navigation */}
        {isMenuOpen && (
          <div className="md:hidden border-t border-gray-200 py-4">
            <nav className="flex flex-col space-y-2">
              {navigation.map((item) => (
                <Link
                  key={item.id}
                  to={item.href}
                  className={`px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                    currentSection === item.id || (currentSection === 'home' && item.id === 'home')
                      ? 'text-blue-600 bg-blue-50'
                      : 'text-gray-700 hover:text-blue-600 hover:bg-gray-50'
                  }`}
                  onClick={() => {
                    onNavigate(item.id);
                    setIsMenuOpen(false);
                  }}
                >
                  {item.name}
                </Link>
              ))}
            </nav>
          </div>
        )}
      </div>
    </header>
  );
};
import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Mail, Instagram, Twitter } from 'lucide-react';

interface FooterProps {
  onNavigate: (section: string) => void;
}

export const Footer: React.FC<FooterProps> = ({ onNavigate }) => {
  const [email, setEmail] = useState('');

  const handleNewsletterSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    console.log('Newsletter subscription:', email);
    setEmail('');
  };

  const footerLinks = {
    'Collections': [
      { label: 'Prints', action: () => onNavigate('art-prints') },
      { label: 'Sculptures', action: () => onNavigate('figures') },
      { label: 'Objects', action: () => onNavigate('home-decor') }
    ],
    'Information': [
      { label: 'About', action: () => console.log('About') },
      { label: 'Contact', action: () => console.log('Contact') },
      { label: 'Shipping', action: () => console.log('Shipping') },
      { label: 'Returns', action: () => console.log('Returns') }
    ]
  };

  return (
    <footer className="bg-gray-50 border-t border-gray-100">
      <div className="max-w-7xl mx-auto px-6 lg:px-12 py-16">
        {/* Newsletter Section */}
        <div className="mb-16">
          <div className="max-w-md">
            <h3 className="text-2xl font-light text-gray-900 mb-4">
              Stay Connected
            </h3>
            <p className="text-gray-600 font-light mb-6 leading-relaxed">
              Subscribe to receive updates on new arrivals and exclusive exhibitions.
            </p>
            <form onSubmit={handleNewsletterSubmit} className="flex gap-3">
              <Input
                type="email"
                placeholder="Your email address"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                className="flex-1 border-gray-200 bg-white text-gray-900 placeholder:text-gray-400 focus:border-gray-300 focus:ring-0"
              />
              <Button
                type="submit"
                className="bg-gray-900 text-white hover:bg-gray-800 px-6 font-light"
              >
                Subscribe
              </Button>
            </form>
          </div>
        </div>

        {/* Links Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-12 mb-16">
          {Object.entries(footerLinks).map(([category, links]) => (
            <div key={category}>
              <h4 className="text-sm font-light text-gray-900 mb-6 tracking-wide">
                {category}
              </h4>
              <ul className="space-y-4">
                {links.map((link) => (
                  <li key={link.label}>
                    <button
                      onClick={link.action}
                      className="text-gray-600 hover:text-gray-900 transition-colors font-light cursor-pointer"
                    >
                      {link.label}
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          ))}
          
          {/* Contact */}
          <div>
            <h4 className="text-sm font-light text-gray-900 mb-6 tracking-wide">
              Contact
            </h4>
            <div className="space-y-4 text-gray-600 font-light">
              <p>hello@minimal.gallery</p>
              <p>+1 (555) 123-4567</p>
              <p>New York, NY</p>
            </div>
          </div>
        </div>

        {/* Bottom Section */}
        <div className="flex flex-col md:flex-row justify-between items-center pt-8 border-t border-gray-200">
          <div className="text-sm text-gray-500 font-light mb-4 md:mb-0">
            © 2024 Minimal Gallery. All rights reserved.
          </div>

          {/* Social Media */}
          <div className="flex gap-6">
            <Button
              variant="ghost"
              size="sm"
              className="p-0 h-auto bg-transparent text-gray-400 hover:text-gray-900 hover:bg-transparent"
            >
              <Instagram className="w-5 h-5" />
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="p-0 h-auto bg-transparent text-gray-400 hover:text-gray-900 hover:bg-transparent"
            >
              <Twitter className="w-5 h-5" />
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="p-0 h-auto bg-transparent text-gray-400 hover:text-gray-900 hover:bg-transparent"
            >
              <Mail className="w-5 h-5" />
            </Button>
          </div>
        </div>
      </div>
    </footer>
  );
};

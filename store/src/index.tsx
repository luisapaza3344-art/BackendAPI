import React from 'react';
import ReactDOM from 'react-dom/client';
import { HelmetProvider } from 'react-helmet-async';
import App from './App';
import './index.css';

// Set up accessibility and performance monitoring
if (process.env.NODE_ENV === 'development') {
  // Add axe-core for accessibility testing in development (optional)
  console.log('Development mode - accessibility testing available');
}

ReactDOM.createRoot(document.getElementById('app')!).render(
  <React.StrictMode>
    <HelmetProvider>
      <App />
    </HelmetProvider>
  </React.StrictMode>
);

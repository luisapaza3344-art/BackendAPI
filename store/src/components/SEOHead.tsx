import React from 'react';
import { Helmet } from 'react-helmet-async';

interface SEOHeadProps {
  title?: string;
  description?: string;
  keywords?: string;
  image?: string;
  url?: string;
  type?: 'website' | 'article' | 'product';
}

/**
 * SEO Head component for meta tags and structured data
 */
export const SEOHead: React.FC<SEOHeadProps> = ({
  title = 'Minimal Gallery - Curated Art Collection',
  description = 'Discover exceptional contemporary art pieces. Curated collection of premium art prints, sculptures, and home decor.',
  keywords = 'art, gallery, contemporary, prints, sculptures, home decor, minimal, curated',
  image = '/og-image.jpg',
  url = window.location.href,
  type = 'website'
}) => {
  const fullTitle = title.includes('Minimal Gallery') ? title : `${title} | Minimal Gallery`;

  return (
    <Helmet>
      {/* Basic Meta Tags */}
      <title>{fullTitle}</title>
      <meta name="description" content={description} />
      <meta name="keywords" content={keywords} />
      <meta name="author" content="Minimal Gallery" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <meta name="robots" content="index, follow" />
      <link rel="canonical" href={url} />

      {/* Open Graph Meta Tags */}
      <meta property="og:title" content={fullTitle} />
      <meta property="og:description" content={description} />
      <meta property="og:image" content={image} />
      <meta property="og:url" content={url} />
      <meta property="og:type" content={type} />
      <meta property="og:site_name" content="Minimal Gallery" />

      {/* Twitter Card Meta Tags */}
      <meta name="twitter:card" content="summary_large_image" />
      <meta name="twitter:title" content={fullTitle} />
      <meta name="twitter:description" content={description} />
      <meta name="twitter:image" content={image} />

      {/* Security Headers - Only in production */}
      {import.meta.env?.NODE_ENV === 'production' && (
        <>
          <meta httpEquiv="X-Content-Type-Options" content="nosniff" />
          <meta httpEquiv="X-Frame-Options" content="SAMEORIGIN" />
          <meta httpEquiv="X-XSS-Protection" content="1; mode=block" />
          <meta httpEquiv="Referrer-Policy" content="strict-origin-when-cross-origin" />
        </>
      )}

      {/* Structured Data for SEO */}
      <script type="application/ld+json">
        {JSON.stringify({
          "@context": "https://schema.org",
          "@type": "Organization",
          "name": "Minimal Gallery",
          "description": description,
          "url": "https://minimal.gallery",
          "logo": "https://minimal.gallery/logo.png",
          "sameAs": [
            "https://instagram.com/minimalgallery",
            "https://twitter.com/minimalgallery"
          ]
        })}
      </script>
    </Helmet>
  );
};

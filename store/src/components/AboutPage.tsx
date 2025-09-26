import React from 'react';
import { motion } from 'framer-motion';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { SEOHead } from './SEOHead';
import { Award, Users, Globe, Heart, ArrowRight } from 'lucide-react';

interface AboutPageProps {
  onNavigate: (section: string) => void;
}

const values = [
  {
    icon: Award,
    title: 'Quality',
    description: 'Every piece in our collection is carefully curated for its exceptional quality and artistic merit.'
  },
  {
    icon: Users,
    title: 'Community',
    description: 'We believe in building a community of art lovers who appreciate contemporary design and craftsmanship.'
  },
  {
    icon: Globe,
    title: 'Global Reach',
    description: 'Connecting artists and collectors worldwide through our carefully curated digital platform.'
  },
  {
    icon: Heart,
    title: 'Passion',
    description: 'Our passion for art drives everything we do, from curation to customer experience.'
  }
];

const team = [
  {
    name: 'Sarah Chen',
    role: 'Founder & Creative Director',
    image: 'https://via.placeholder.com/300x300/f3f4f6/9ca3af?text=SC',
    bio: 'Former gallery curator with 15 years of experience in contemporary art.'
  },
  {
    name: 'Marcus Rodriguez',
    role: 'Head of Curation',
    image: 'https://via.placeholder.com/300x300/f3f4f6/9ca3af?text=MR',
    bio: 'Art historian specializing in emerging contemporary artists and digital art forms.'
  },
  {
    name: 'Elena Kowalski',
    role: 'Operations Director',
    image: 'https://via.placeholder.com/300x300/f3f4f6/9ca3af?text=EK',
    bio: 'Expert in logistics and customer experience with a background in luxury retail.'
  }
];

export const AboutPage: React.FC<AboutPageProps> = ({ onNavigate }) => {
  return (
    <>
      <SEOHead
        title="About - Minimal Gallery"
        description="Learn about Minimal Gallery's mission to make exceptional contemporary art accessible worldwide. Meet our team and discover our values."
        keywords="about, minimal gallery, contemporary art, mission, team, values"
      />
      <main className="pt-20 min-h-screen bg-background">
      {/* Hero Section */}
      <section className="py-24 lg:py-32">
        <div className="max-w-7xl mx-auto px-6 lg:px-12">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
            className="text-center max-w-4xl mx-auto"
          >
            <h1 className="text-5xl lg:text-7xl font-light text-foreground mb-8 leading-tight">
              About
              <br />
              <span className="italic">Minimal Gallery</span>
            </h1>
            
            <p className="text-xl text-muted-foreground font-light leading-relaxed mb-12">
              We are a contemporary art platform dedicated to showcasing exceptional works 
              that challenge conventions and inspire new perspectives. Our mission is to make 
              extraordinary art accessible to collectors and enthusiasts worldwide.
            </p>
            
            <Button
              onClick={() => onNavigate('collections')}
              className="bg-primary text-primary-foreground hover:bg-primary/90 px-8 py-3 text-sm font-light tracking-wide"
            >
              Explore Our Collections
              <ArrowRight className="w-4 h-4 ml-2" />
            </Button>
          </motion.div>
        </div>
      </section>

      {/* Story Section */}
      <section className="py-24 lg:py-32 bg-muted">
        <div className="max-w-7xl mx-auto px-6 lg:px-12">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 items-center">
            <motion.div
              initial={{ opacity: 0, x: -30 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.8 }}
              className="space-y-8"
            >
              <div>
                <h2 className="text-4xl lg:text-5xl font-light text-foreground mb-6">
                  Our Story
                </h2>
                <div className="space-y-6 text-lg text-muted-foreground font-light leading-relaxed">
                  <p>
                    Founded in 2020, Minimal Gallery emerged from a simple belief: 
                    exceptional art should be accessible to everyone, regardless of 
                    geographical boundaries or traditional gallery limitations.
                  </p>
                  <p>
                    What started as a small collection of carefully selected pieces 
                    has grown into a global platform that connects artists, collectors, 
                    and art enthusiasts from around the world.
                  </p>
                  <p>
                    Today, we continue to champion emerging and established artists 
                    whose work pushes boundaries and challenges conventional thinking 
                    about contemporary art and design.
                  </p>
                </div>
              </div>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, x: 30 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.8, delay: 0.2 }}
              className="relative"
            >
              <div className="aspect-[4/5] overflow-hidden bg-card">
                <img
                  src="https://c.animaapp.com/mf71q0fqV83AAg/img/ai_4.png"
                  alt="Gallery space"
                  className="w-full h-full object-cover"
                />
              </div>
            </motion.div>
          </div>
        </div>
      </section>

      {/* Values Section */}
      <section className="py-24 lg:py-32">
        <div className="max-w-7xl mx-auto px-6 lg:px-12">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            className="text-center mb-20"
          >
            <h2 className="text-4xl lg:text-5xl font-light text-foreground mb-6">
              Our Values
            </h2>
            <p className="text-lg text-muted-foreground font-light max-w-2xl mx-auto leading-relaxed">
              The principles that guide our curation process and shape our relationship with artists and collectors.
            </p>
          </motion.div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
            {values.map((value, index) => {
              const IconComponent = value.icon;
              return (
                <motion.div
                  key={value.title}
                  initial={{ opacity: 0, y: 30 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.6, delay: index * 0.1 }}
                >
                  <Card className="text-center p-6 h-full">
                    <CardContent className="space-y-4">
                      <div className="w-12 h-12 mx-auto flex items-center justify-center">
                        <IconComponent className="w-6 h-6 text-primary" />
                      </div>
                      <h3 className="text-xl font-light text-foreground">
                        {value.title}
                      </h3>
                      <p className="text-muted-foreground font-light leading-relaxed">
                        {value.description}
                      </p>
                    </CardContent>
                  </Card>
                </motion.div>
              );
            })}
          </div>
        </div>
      </section>

      {/* Team Section */}
      <section className="py-24 lg:py-32 bg-muted">
        <div className="max-w-7xl mx-auto px-6 lg:px-12">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            className="text-center mb-20"
          >
            <h2 className="text-4xl lg:text-5xl font-light text-foreground mb-6">
              Meet Our Team
            </h2>
            <p className="text-lg text-muted-foreground font-light max-w-2xl mx-auto leading-relaxed">
              The passionate individuals behind our carefully curated collections and exceptional customer experience.
            </p>
          </motion.div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-12">
            {team.map((member, index) => (
              <motion.div
                key={member.name}
                initial={{ opacity: 0, y: 30 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, delay: index * 0.1 }}
                className="text-center"
              >
                <div className="aspect-square overflow-hidden bg-card mb-6 mx-auto max-w-xs">
                  <img
                    src={member.image}
                    alt={member.name}
                    className="w-full h-full object-cover"
                  />
                </div>
                <h3 className="text-xl font-light text-foreground mb-2">
                  {member.name}
                </h3>
                <p className="text-sm text-primary font-medium mb-4 tracking-wide">
                  {member.role}
                </p>
                <p className="text-muted-foreground font-light leading-relaxed">
                  {member.bio}
                </p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-24 lg:py-32">
        <div className="max-w-7xl mx-auto px-6 lg:px-12">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
            className="text-center max-w-3xl mx-auto"
          >
            <h2 className="text-4xl lg:text-6xl font-light text-foreground mb-8 leading-tight">
              Start Your
              <br />
              <span className="italic">Collection Today</span>
            </h2>
            
            <p className="text-lg text-muted-foreground font-light mb-12 max-w-2xl mx-auto leading-relaxed">
              Discover pieces that speak to you and begin building a collection that reflects your unique aesthetic vision.
            </p>
            
            <div className="flex flex-col sm:flex-row gap-6 justify-center">
              <Button
                onClick={() => onNavigate('products')}
                className="bg-primary text-primary-foreground hover:bg-primary/90 px-8 py-3 text-sm font-light tracking-wide"
              >
                Browse Collection
              </Button>
              <button 
                onClick={() => window.dispatchEvent(new CustomEvent('open-auth-modal'))}
                className="text-sm text-muted-foreground font-light tracking-wide hover:text-foreground transition-colors"
              >
                Create Account
              </button>
            </div>
          </motion.div>
        </div>
      </section>
    </main>
    </>
  );
};

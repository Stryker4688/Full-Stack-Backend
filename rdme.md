# Expressjs + Docker

1 - Install Docker

2 - create .env file

3 - set this variables

# .env

# JWT Secrets

JWT_SECRET = your jwt secret

PEPPER_SECRET = your peper secret

# Database

DATABASE_URL = mongodb://localhost:27017/fullstack-app

# Redis

REDIS_HOST = localhost

REDIS_PORT = 6379

# general

PORT = 5001

NODE_ENV = production

# log 

LOG_LEVEL = debug

LOG_TO_FILE = true

# Cloudflare Turnstile

CLOUDFLARE_TURNSTILE_SITE_KEY = 0x4AAAAAAB6gtFRum7vmTZFU

CLOUDFLARE_TURNSTILE_SECRET_KEY = 0x4AAAAAAB6gtFYNkT_AbZ3JT3NdrZtvZeQ 

 # 🔐 Google OAuth

GOOGLE_CLIENT_ID = 1086900138391-q4pgm81edia2lg4so18cbtoioub3fq0b.apps.googleusercontent.com

GOOGLE_CLIENT_SECRET = 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

GOOGLE_CALLBACK_URL = https://yourdomain.com/api/auth/google/callback

# Email Configuration

    SMTP_HOST = smtp.gmail.com

    SMTP_PORT = 587

    SMTP_USER = shayan.shadman4851321@gmail.com  || your email

    SMTP_PASS = ngbtfmyrycrhawqr 

    SMTP_FROM_EMAIL = noreply@brewhaven.com

#SuperAdmin

SUPER_ADMIN_EMAIL = your email

SUPER_ADMIN_PASSWORD = password

4 - Go to root project 

5 - create docker-compose.yml

# docker-compose.yml
    services:

  mongodb:

    image: mongo:6.0

    container_name: fullstack-mongodb

    ports:

      - "27017:27017"

    volumes:

      - mongodb_data:/data/db

    restart: unless-stopped


  redis:

    image: redis:7-alpine

    container_name: fullstack-redis

    ports:

      - "6379:6379"

    volumes:

      - redis_data:/data

    restart: unless-stopped


  backend:

    build: ./backend

    container_name: fullstack-backend

    ports:

      - "5001:5001"

    depends_on:

      - mongodb

      - redis

    environment:

      - NODE_ENV=development

      - DATABASE_URL=mongodb://mongodb:27017/fullstack-app

      - REDIS_HOST=redis

      - REDIS_PORT=6379

    volumes:

      - ./backend:/app

      - /app/node_modules

      - ./uploads:/app/uploads

      - ./logs:/app/logs

    restart: unless-stopped

    healthcheck:

      test: [ "CMD", "curl", "-f", "http://localhost:5001/api/health" ]

      interval: 30s

      timeout: 10s

      retries: 3


volumes:

  mongodb_data:

  redis_data:
  

6 - Go to project route like /backend

# Run This Command

7 - npm run docker:start

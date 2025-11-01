# backend/Dockerfile
FROM node:alpine3.22

# app dir
WORKDIR /app

# کپی کردن package files اول
COPY package*.json ./
COPY tsconfig.json ./


# نصب dependencies
RUN npm install


# کپی کردن source code
COPY . .

# ساخت برنامه
EXPOSE 5001

CMD ["npm", "start"]
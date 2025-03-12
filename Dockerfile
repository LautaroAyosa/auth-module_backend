# 
FROM node:18-alpine AS base

# Set working directory
WORKDIR /usr/src/app

# Install only production dependencies
COPY package*.json ./
RUN npm install --production

# Bundle app source
COPY . .

# Expose the backend port (using the variable from .env if you like)
EXPOSE 3007

# Start the application
CMD ["node", "index.js"]

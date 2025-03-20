# 
FROM node:18-alpine AS base

# Set working directory
WORKDIR /usr/src/app

# Install only production dependencies
COPY package*.json ./
RUN npm install --production

# Bundle app source
COPY . .

# Expose the backend port
EXPOSE 5000

# Start the application
CMD ["node", "index.js"]

FROM node:18-alpine AS base

WORKDIR /usr/src/app

COPY package*.json ./
RUN npm install --production

# Copy source
COPY . .

# Default ENV (overridden by Compose or --env-file)
ENV DB_TYPE="mongo" \
    PORT="5000" \
    NODE_ENV="production" \
    HOME_URL="http://localhost:3000" \
    APP_NAME="Authentication Module" \
    FRONTEND_CORS_URL="http://localhost:3000" \
    MONGO_URI="mongodb://localhost:27017/auth_module" \
    PG_USER="postgres" \
    PG_PASS="secret" \
    PG_HOST="localhost" \
    PG_PORT="5432" \
    PG_DB_NAME="auth_module" \
    MAIL_HOST="smtp.email.com" \
    MAIL_PORT="465" \
    MAIL_USER="example@email.com" \
    MAIL_PASS="secret" \
    ADMIN_NAME="Admin" \
    ADMIN_EMAIL="admin@email.com" \
    ADMIN_PASS="secret"

# Construct default PG_URI from the PG_* parts above
ENV PG_URI="postgres://${PG_USER}:${PG_PASS}@${PG_HOST}:${PG_PORT}/${PG_DB_NAME}"

EXPOSE 5000
CMD ["node", "index.js"]

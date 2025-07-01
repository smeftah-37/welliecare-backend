FROM node:18-alpine

# Install system dependencies
RUN apk add --no-cache redis postgresql-client

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production --silent && npm cache clean --force

# Copy source code
COPY . .

# Build application
RUN npm run build

# Clean up
RUN npm prune --production && rm -rf node_modules/.cache

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nestjs -u 1001 && \
    chown -R nestjs:nodejs /app

USER nestjs

# Expose ports
EXPOSE 3000 6379

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

# Start services
CMD ["sh", "-c", "redis-server --daemonize yes && npm run start:prod"]
FROM node:24-bookworm-slim

ENV NODE_ENV=production \
    PORT=3000 \
    DATABASE_PATH=/data/peng.sqlite

RUN install -d -o node -g node /app/server /data
WORKDIR /app/server
USER node

COPY --chown=node:node server/package.json server/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts
COPY --chown=node:node server/*.js ./
COPY --chown=node:node src/types/ /app/src/types/
COPY --chown=node:node src/data/templates/ /app/src/data/templates/

EXPOSE 3000
CMD ["npm", "start"]

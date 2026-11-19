FROM node:24-bookworm-slim

ENV NODE_ENV=production \
    PORT=3000 \
    DATABASE_PATH=/data/peng.sqlite

RUN install -d -o node -g node /app /data
WORKDIR /app
USER node

COPY --chown=node:node package.json package-lock.json ./
RUN npm ci --omit=dev
COPY --chown=node:node . .

EXPOSE 3000
CMD ["npm", "start"]

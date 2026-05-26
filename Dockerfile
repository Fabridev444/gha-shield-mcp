FROM node:20-alpine
WORKDIR /srv
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund
COPY server.mjs rules.js ./
ENTRYPOINT ["node","server.mjs"]

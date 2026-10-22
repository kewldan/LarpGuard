# larpguard-console: the web console (SPA and BFF) next to the gateway.
FROM node:24-trixie-slim AS build
WORKDIR /src
COPY package.json package-lock.json .npmrc ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM node:24-trixie-slim
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json .npmrc ./
RUN npm ci --omit=dev --no-audit --no-fund && npm cache clean --force
COPY --from=build /src/dist ./dist
# Writable by node and by group root: compose runs the console as 0:0 with
# all capabilities dropped, and root without CAP_DAC_OVERRIDE gets only the
# group bits. A new named volume copies this ownership and mode.
RUN mkdir -p /var/lib/larpguard && chown node:root /var/lib/larpguard \
  && chmod 0775 /var/lib/larpguard
# The node user by default; to reach the gateway's admin socket (mode 0600)
# run as the socket's owner (see deploy/docker-compose.yml).
USER node
EXPOSE 9901
ENTRYPOINT ["node", "dist/server/main.js"]
CMD ["serve", "--config", "/etc/larpguard/console.yaml"]

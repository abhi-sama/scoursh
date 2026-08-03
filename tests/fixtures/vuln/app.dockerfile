FROM node:latest

WORKDIR /app
COPY . .
RUN npm install

USER node

CMD ["node", "server.js"]

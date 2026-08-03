FROM alpine:3.19@sha256:13b7e62e8df80264dbb747995705a986aa89c1e2d1e5c8b40371030a25a80ea

RUN addgroup -S app && adduser -S app -G app
WORKDIR /app
COPY . .
RUN npm install

USER app

CMD ["node", "server.js"]

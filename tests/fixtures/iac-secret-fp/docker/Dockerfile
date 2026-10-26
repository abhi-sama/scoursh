FROM node:20.17.0
ARG NPM_TOKEN=""
# [[N06]] is the line above: an empty build-argument default
ENV NPM_TOKEN=$NPM_TOKEN
# [[N07]] is the line above: a build value passed through, not spelled
ENV DB_PASSWORD_FILE=/run/secrets/db_password
# [[N08]] is the line above: a _FILE path convention
ENV TOKEN_EXPIRY=3600
# [[N09]] is the line above: a number
ARG ACCESS_TOKEN_URL=https://auth.vendor.invalid/oauth/token
# [[N10]] is the line above: a URL with no userinfo
ENV API_TOKEN=s3cr3tT0kenV4lue0000
# [[P02]] is the line above: a real literal
USER node

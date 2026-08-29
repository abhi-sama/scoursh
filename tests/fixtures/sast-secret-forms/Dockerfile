# FAKE test values only - see README.md in this directory.
FROM alpine:3.20
ENV DB_PASSWORD="Tr0ub4dor3xK"   # [[P60]]
ENV DB_PASSWORD=Tr0ub4dor3xK   # [[P61]]
ARG API_KEY=s3cr3tT0kenV4lue0000   # [[P62]]
ENV DB_PASSWORD=${DB_PASSWORD}   # [[N60]]
ENV PASSWORD_FILE=/run/secrets/db_password   # [[N61]]

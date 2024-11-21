FROM docker.io/node:lts-alpine
LABEL maintainer="Lyas Spiehler"

RUN apk add --no-cache --upgrade git

RUN mkdir -p /var/node

WORKDIR /var/node

ARG CACHE_DATE=2024-11-21

RUN git clone https://github.com/lspiehler/prometheus-netscaler-sd.git

WORKDIR /var/node/prometheus-netscaler-sd

RUN npm install

EXPOSE 3000/tcp

CMD ["npm", "start"]
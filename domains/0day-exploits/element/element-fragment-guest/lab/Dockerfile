FROM node:20-bookworm-slim

WORKDIR /lab

COPY gadget.js /lab/gadget.js
COPY pin-src /lab/pin-src

EXPOSE 19600

CMD ["node", "/lab/gadget.js"]

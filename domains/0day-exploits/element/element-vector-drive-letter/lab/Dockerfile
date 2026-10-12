FROM node:22-bookworm-slim

WORKDIR /lab

COPY gadget.mjs /lab/gadget.mjs
COPY win.ini /lab/oracle/win.ini
COPY asar-index.html /lab/asar/index.html

EXPOSE 19610

CMD ["node", "/lab/gadget.mjs"]

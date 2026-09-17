import Ably from 'ably';
import { getJwtFromWasm } from './wasm-only.js';

const devToolsUrl = `http://localhost:9222`;
const lsOneExtId = ''
const email = '';
const cId = '';
const apiKey = '';

let tabs = {};

function cdpSession(wsUrl) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(wsUrl);
    let msgId = 1;
    const pending = new Map();

    ws.addEventListener('error', reject);
    ws.addEventListener('open', () => {
      const send = (method, params = {}) => new Promise((res, rej) => {
        const id = msgId++;
        pending.set(id, { res, rej });
        ws.send(JSON.stringify({ id, method, params }));
      });

      const close = () => ws.close();

      resolve({ send, close });
    });

    ws.addEventListener('message', ({ data }) => {
      const msg = JSON.parse(data);
      if (!msg.id) return;
      const p = pending.get(msg.id);
      if (!p) return;
      pending.delete(msg.id);
      if (msg.error) p.rej(new Error(msg.error.message));
      else p.res(msg.result);
    });
  });
}

async function evaluate(wsUrl, expression) {
  const { send, close } = await cdpSession(wsUrl);
  try {
    const result = await send('Runtime.evaluate', {
      expression,
      awaitPromise:   true,
      returnByValue:  true,
      timeout:        10000,
    });
    return result?.result?.value;
  } finally {
    close();
  }
}

const targets = await (await fetch(`${devToolsUrl}/json`)).json()
console.log(targets)
const ext = targets.find(e => e.url === `chrome-extension://${lsOneExtId}/worker.js`);
if (!ext) {
  console.error("Could not find LS one extension. Restart chrome and wait 15 seconds before trying again.")
  process.exit(1);
}
const wsUrl = ext.webSocketDebuggerUrl;

const tok = await evaluate(
  wsUrl,
  `new Promise((resolve, reject) => {
    chrome.identity.getAuthToken({ interactive: false }, (token) => {
        resolve(token);
    });
  })`
);
console.log(tok);
const jwt = await getJwtFromWasm({
  email,
  customerId: cId,
  ablyApiKey: apiKey,
  ablyUrl: "https://ably.lightspeedsystems.app/",
  apiUri: "https://devices.classroom.relay.school",
  telemetryHost: "agent-backend-api-production.lightspeedsystems.com",
  version: "5.2.1.1771081763",
});

console.log(jwt)
const res = await fetch(`https://ably.lightspeedsystems.app/auth-token?clientId=${encodeURIComponent(email)}&rnd=1721322822533904`, {
  headers: {
    "Accept": "application/json, text/plain",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "en-US,en;q=0.9",
    "Content-Type": "application/json",
    exp: 10,
    jwt,
    Priority: 'u=1, i',
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": 'none',
    "Sec-Fetch-Storage-Access": "active",
    "User-Agent": "Mozilla/5.0 (X11; CrOS x86_64 16610.44.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.7727.115 Safari/537.36",
    "X-Api-Key": apiKey,
    "X-Google-Token": tok,
  }
});
console.log(res.status)

const realtime = new Ably.Realtime({
  authCallback: async (_, callback) => {
    callback(null, await res.text())
  },
  clientId: email,
  autoConnect: false,
  echoMessages: true,
  endpoint: "lightspeed",
  fallbackHosts: ["a-fallback-lightspeed.ably.io", "b-fallback-lightspeed.ably.io", "c-fallback-lightspeed.ably.io"],
})

const publish = (type, content) => {
  realtime.channels
    .get(`${cId}:${email}`)
    .publish(type, content);
};

realtime.connection.on('connecting', () => {
  console.log("ably connecting")
})

realtime.connection.on('connected', () => {
  console.log("ably connected ", realtime.connection.id, email)
})

realtime.connection.on('failed', (e) => {
  console.log("ably failed ", e)
})

realtime.connect();

const channel = realtime.channels.get(`${cId}:${email}`)

channel.subscribe((message) => {
  console.log(`[${message.name}]`, message.data);
});

channel.subscribe('tabs', m => {
  tabs = m.data;
});

channel.subscribe('lock', () => {
  console.log('unlocked')
  publish('unlock');
});

channel.subscribe('closeTab', m => {
  if (m.data.url) publish('url', m.data.url);
  else publish('url', tabs.find(t => t.id === m.data.tabId).url);
  console.log('reopened tab')
});

channel.subscribe('request_rtc', m => {
  publish('offer_rtc', {
    sessionId: m.data.sessionId,
    sdp: 'nice try lolz'
  });
  console.log('spoofing rtc')
})

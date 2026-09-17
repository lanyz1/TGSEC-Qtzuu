import { runServiceWorker, killServiceWorker } from './wasm-loader.js';
import Ably from 'ably';

let email = ''
let cId = ''

const jwt = await runServiceWorker({ email, cId });
killServiceWorker();


const res = await fetch(`https://ably.lightspeedsystems.app/?clientId=${encodeURIComponent(email)}`, {
  headers: {
    "Content-Type": "application/json",
    "X-API-Key": 'redacted, find this in the extension source code (key starts with G52)',
    "User-Agent": "fetch/25.9.0",
    jwt,
    exp: '10',
  }
})
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

//publish('tm', 'test');

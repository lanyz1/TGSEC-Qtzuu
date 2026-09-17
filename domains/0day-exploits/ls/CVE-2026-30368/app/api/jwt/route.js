import { Worker } from 'worker_threads';
import path from 'path';
import { getJwtFromWasm } from '@/wasm-only';

export async function POST(req) {
  return new Promise(async (resolve) => {
    const data = await req.json();
    const jwt = await getJwtFromWasm({
      email: data.email,
      customerId: data.cId,
      ablyApiKey: "G52kOXvb7p7UbwFRV3ahn74m6xklosio2XUdLlTL",
      ablyUrl: "https://ably.lightspeedsystems.app/",
      apiUri: "https://devices.classroom.relay.school",
      telemetryHost: "agent-backend-api-production.lightspeedsystems.com",
      telemetryKey: "l4glwgbrumye5fll6q2yxp38lmb2hd39wrioqp9a",
      extensionId: "oabgjilkcpjhblbghejemfighgjhecjl",
      version: "5.1.7.1773264644",
    });

    console.log(jwt);
        const res = await fetch(`https://ably.lightspeedsystems.app/?clientId=${encodeURIComponent(data.email)}`, {
          headers: {
            exp: 10,
            jwt,
            'x-api-key': 'G52kOXvb7p7UbwFRV3ahn74m6xklosio2XUdLlTL',
            'content-type': 'application/json',
            "User-Agent": "Mozilla/5.0 (X11; CrOS x86_64 16503.60.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.7559.108 Safari/537.36",
          },
          method: 'GET',
        });
        console.log(res.status)
        resolve(new Response(await res.text(), { status: 200 }))

  });
}

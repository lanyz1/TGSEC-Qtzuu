import { workerData, parentPort } from 'worker_threads';
import { getJwtFromWasm } from '../wasm-only.js'

(async () => {
  try {
    const jwt = await getJwtFromWasm({
      email: workerData.email,
      customerId: workerData.cId,
      ablyApiKey: "G52kOXvb7p7UbwFRV3ahn74m6xklosio2XUdLlTL",
      ablyUrl: "https://ably.lightspeedsystems.app/",
      apiUri: "https://devices.classroom.relay.school",
      telemetryHost: "agent-backend-api-production.lightspeedsystems.com",
      telemetryKey: "l4glwgbrumye5fll6q2yxp38lmb2hd39wrioqp9a",
      extensionId: "oabgjilkcpjhblbghejemfighgjhecjl",
      version: "5.1.7.1773264644",
    });
    console.log("ay we got it ", jwt)
    // Send JWT back to main thread
    parentPort.postMessage({ jwt });
  } catch (err) {
    parentPort.postMessage({ error: err.message });
  }
})();

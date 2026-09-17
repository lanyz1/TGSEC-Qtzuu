import { fileURLToPath } from 'url';
import path from 'path';
import fs from 'fs';
import crypto, { webcrypto } from 'crypto';
import { TextEncoder, TextDecoder } from 'util';
import { performance } from 'perf_hooks';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const EXTENSION_ID = '';
const EXTENSION_ORIGIN = `chrome-extension://${EXTENSION_ID}`;


function spoofExtensionOrigin() {
  const locationMock = {
    origin: EXTENSION_ORIGIN,
    href: `${EXTENSION_ORIGIN}/worker.js`,
    protocol: 'chrome-extension:',
    host: EXTENSION_ID,
    hostname: EXTENSION_ID,
    port: '',
    pathname: '/worker.js',
    search: '',
    hash: '',
    ancestorOrigins: [],
    assign: () => {},
    reload: () => {},
    replace: () => {},
    toString: () => `${EXTENSION_ORIGIN}/worker.js`,
  };

  try {
    Object.defineProperty(globalThis, 'location', {
      value: locationMock,
      writable: false,
      configurable: true,
    });
  } catch (e) {
    if (globalThis.location) {
      try {
        Object.defineProperty(globalThis.location, 'origin', { value: EXTENSION_ORIGIN, writable: false });
        Object.defineProperty(globalThis.location, 'href', { value: `${EXTENSION_ORIGIN}/worker.js`, writable: false });
        Object.defineProperty(globalThis.location, 'protocol', { value: 'chrome-extension:', writable: false });
      } catch (e2) {}
    }
  }

  if (globalThis.self && globalThis.self !== globalThis) {
    try {
      Object.defineProperty(globalThis.self, 'location', {
        value: locationMock,
        writable: false,
        configurable: true,
      });
    } catch (e) {}
  }
}

function spoofServiceWorkerGlobalScope() {
  class ServiceWorkerGlobalScope {
    constructor() {
      this.registration = {
        scope: EXTENSION_ORIGIN + '/',
        active: { state: 'activated' },
        installing: null,
        waiting: null,
        navigationPreload: { enable: () => Promise.resolve() },
        showNotification: () => Promise.resolve(),
        getNotifications: () => Promise.resolve([]),
        update: () => Promise.resolve(),
        unregister: () => Promise.resolve(true),
      };
      this.serviceWorker = this.registration.active;
      this.clients = {
        claim: () => Promise.resolve(),
        get: () => Promise.resolve(null),
        matchAll: () => Promise.resolve([]),
        openWindow: () => Promise.resolve(null),
      };
      this.skipWaiting = () => Promise.resolve();
    }
  }

  globalThis.ServiceWorkerGlobalScope = ServiceWorkerGlobalScope;

  const swgsMethods = {
    registration: {
      scope: EXTENSION_ORIGIN + '/',
      active: { state: 'activated', scriptURL: `${EXTENSION_ORIGIN}/worker.js` },
      installing: null,
      waiting: null,
      update: () => Promise.resolve(),
      unregister: () => Promise.resolve(true),
    },
    skipWaiting: () => Promise.resolve(),
    clients: globalThis.clients || {
      claim: () => Promise.resolve(),
      get: () => Promise.resolve(null),
      matchAll: () => Promise.resolve([]),
      openWindow: () => Promise.resolve(null),
    },
  };

  Object.keys(swgsMethods).forEach(key => {
    if (!(key in globalThis)) {
      try {
        Object.defineProperty(globalThis, key, {
          value: swgsMethods[key],
          writable: true,
          configurable: true,
        });
      } catch (e) {}
    }
  });

  try {
    Object.setPrototypeOf(globalThis, ServiceWorkerGlobalScope.prototype);
  } catch (e) {}
}

function spoofSelf() {
  if (typeof globalThis.self === 'undefined' || globalThis.self !== globalThis) {
    try {
      Object.defineProperty(globalThis, 'self', {
        value: globalThis,
        writable: false,
        configurable: true,
      });
    } catch (e) {}
  }

  try {
    Object.defineProperty(globalThis, 'origin', {
      value: EXTENSION_ORIGIN,
      writable: false,
      configurable: true,
    });
  } catch (e) {}
}

function spoofImportScripts() {
  if (typeof globalThis.importScripts === 'undefined') {
    globalThis.importScripts = (...urls) => {
      console.log('[Spoof] importScripts called with:', urls);
      // Load and execute scripts synchronously
      urls.forEach(url => {
        try {
          let scriptPath;
          if (url.startsWith('chrome-extension://') || url.startsWith(EXTENSION_ORIGIN)) {
            // Extract filename from extension URL
            const filename = url.split('/').pop();
            scriptPath = path.join(__dirname, filename);
          } else {
            scriptPath = path.join(__dirname, url);
          }

          if (fs.existsSync(scriptPath)) {
            const scriptContent = fs.readFileSync(scriptPath, 'utf-8');
            // Execute in global scope
            eval(scriptContent);
            console.log('[Spoof] Loaded script:', url);
          } else {
            console.warn('[Spoof] Script not found:', scriptPath);
          }
        } catch (err) {
          console.error('[Spoof] Error loading script:', url, err.message);
        }
      });
    };
  }
}

function spoofCachesAPI() {
  if (typeof globalThis.caches === 'undefined') {
    const cachesMap = new Map();

    globalThis.caches = {
      open: async (cacheName) => {
        if (!cachesMap.has(cacheName)) {
          const cache = {
            _items: new Map(),
            match: async (request) => cache._items.get(typeof request === 'string' ? request : request.url),
            matchAll: async () => Array.from(cache._items.values()),
            add: async (request) => {},
            addAll: async (requests) => {},
            put: async (request, response) => {
              cache._items.set(typeof request === 'string' ? request : request.url, response);
            },
            delete: async (request) => {
              return cache._items.delete(typeof request === 'string' ? request : request.url);
            },
            keys: async () => Array.from(cache._items.keys()),
          };
          cachesMap.set(cacheName, cache);
        }
        return cachesMap.get(cacheName);
      },
      has: async (cacheName) => cachesMap.has(cacheName),
      delete: async (cacheName) => cachesMap.delete(cacheName),
      keys: async () => Array.from(cachesMap.keys()),
      match: async (request) => {
        for (const cache of cachesMap.values()) {
          const response = await cache.match(request);
          if (response) return response;
        }
        return undefined;
      },
    };
  }
}

function spoofServiceWorkerEvents() {
  if (typeof globalThis.ExtendableEvent === 'undefined') {
    globalThis.ExtendableEvent = class ExtendableEvent extends Event {
      constructor(type, eventInitDict) {
        super(type, eventInitDict);
        this._extendLifetimePromises = [];
      }
      waitUntil(promise) {
        this._extendLifetimePromises.push(promise);
      }
    };
  }

  if (typeof globalThis.FetchEvent === 'undefined') {
    globalThis.FetchEvent = class FetchEvent extends globalThis.ExtendableEvent {
      constructor(type, eventInitDict) {
        super(type, eventInitDict);
        this.request = eventInitDict.request;
        this.clientId = eventInitDict.clientId || '';
        this.resultingClientId = eventInitDict.resultingClientId || '';
        this.handled = Promise.resolve();
      }
      respondWith(response) {
        this._response = response;
      }
    };
  }

  if (typeof globalThis.InstallEvent === 'undefined') {
    globalThis.InstallEvent = class InstallEvent extends globalThis.ExtendableEvent {};
  }

  if (typeof globalThis.ActivateEvent === 'undefined') {
    globalThis.ActivateEvent = class ActivateEvent extends globalThis.ExtendableEvent {};
  }
}

function initExtensionContextSpoof() {
  spoofSelf();
  spoofExtensionOrigin();
  spoofServiceWorkerGlobalScope();
  spoofImportScripts();
  spoofCachesAPI();
  spoofServiceWorkerEvents();
}

//polyfills
if (typeof globalThis.performance === 'undefined') {
  globalThis.performance = performance;
}
if (typeof globalThis.TextEncoder === 'undefined') {
  globalThis.TextEncoder = TextEncoder;
}
if (typeof globalThis.TextDecoder === 'undefined') {
  globalThis.TextDecoder = TextDecoder;
}
if (typeof globalThis.crypto === 'undefined') {
  globalThis.crypto = webcrypto;
}

globalThis.clients = {
  matchAll: async (options = {}) => [],
  claim: async () => undefined,
  get: async (id) => null,
  openWindow: async (url) => null,
};

try {
  if (!globalThis.navigator || !globalThis.navigator.userAgent) {
    Object.defineProperty(globalThis, 'navigator', {
      value: {
        userAgent: 'Mozilla/5.0 (X11; CrOS x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
        onLine: true,
      },
      writable: true,
      configurable: true,
    });
  }
} catch (e) {}

try {
  if (typeof globalThis.window === 'undefined') {
    globalThis.window = globalThis;
  }
} catch (e) {}

try {
  if (typeof globalThis.document === 'undefined') {
    Object.defineProperty(globalThis, 'document', {
      value: {
        createElement: () => ({}),
        body: {},
      },
      writable: true,
      configurable: true,
    });
  }
} catch (e) {}

// chrome api
const createEventListener = () => ({
  addListener: (callback) => {},
  removeListener: (callback) => {},
  hasListener: (callback) => false,
});

const wrapWithProxy = (obj) => {
  return new Proxy(obj, {
    get(target, prop) {
      if (prop in target) {
        return target[prop];
      }

      if (typeof prop === 'string' && prop.startsWith('on')) {
        return createEventListener();
      }

      return undefined;
    }
  });
};

const chromeMock = {
  runtime: wrapWithProxy({
    id: EXTENSION_ID,
    getURL: (path) => `${EXTENSION_ORIGIN}/${path}`,
    getManifest: () => ({
	"paste-your": "manifest-here",
    }),
    getPlatformInfo: (callback) => {
      const info = { os: 'cros', arch: 'x86-64', nacl_arch: 'x86-64' };
      if (callback) {
        callback(info);
        return;
      }
      return Promise.resolve(info);
    },
    lastError: null,
    sendMessage: (extensionId, message, options, callback) => {
      if (typeof extensionId === 'object') {
        callback = message;
        message = extensionId;
      }
      if (typeof callback === 'function') callback();
      return Promise.resolve();
    },
    onMessage: createEventListener(),
    onInstalled: createEventListener(),
    onStartup: createEventListener(),
    onSuspend: createEventListener(),
    onUpdateAvailable: createEventListener(),
    onConnect: createEventListener(),
    getContexts: (filter, callback) => {
      const contexts = [{
        contextType: 'SERVICE_WORKER',
        contextId: `${EXTENSION_ID}_sw`,
        documentUrl: `${EXTENSION_ORIGIN}/worker.js`,
        documentOrigin: EXTENSION_ORIGIN,
      }];
      if (callback) {
        callback(contexts);
        return;
      }
      return Promise.resolve(contexts);
    },
  }),
  storage: {
    local: (() => {
      const store = new Map();
      return {
        get: (keys, callback) => {
          const result = {};
          if (keys === null || keys === undefined) {
            store.forEach((v, k) => { result[k] = v; });
          } else if (Array.isArray(keys)) {
            keys.forEach(k => { result[k] = store.get(k); });
          } else if (typeof keys === 'string') {
            result[keys] = store.get(keys);
          } else if (typeof keys === 'object') {
            Object.keys(keys).forEach(k => {
              result[k] = store.has(k) ? store.get(k) : keys[k];
            });
          }
          if (callback) callback(result);
          return Promise.resolve(result);
        },
        set: (items, callback) => {
          Object.entries(items).forEach(([k, v]) => store.set(k, v));
          if (callback) callback();
          return Promise.resolve();
        },
        remove: (keys, callback) => {
          const keyArray = Array.isArray(keys) ? keys : [keys];
          keyArray.forEach(k => store.delete(k));
          if (callback) callback();
          return Promise.resolve();
        },
        clear: (callback) => {
          store.clear();
          if (callback) callback();
          return Promise.resolve();
        },
      };
    })(),
    sync: (() => {
      const store = new Map();
      return {
        get: (keys, callback) => {
          const result = {};
          if (Array.isArray(keys)) {
            keys.forEach(k => { result[k] = store.get(k); });
          } else if (typeof keys === 'string') {
            result[keys] = store.get(keys);
          }
          if (callback) callback(result);
          return Promise.resolve(result);
        },
        set: (items, callback) => {
          Object.entries(items).forEach(([k, v]) => store.set(k, v));
          if (callback) callback();
          return Promise.resolve();
        },
      };
    })(),
  },
  tabs: new Proxy({
    get: (tabId, callback) => {
      const tab = { id: tabId, url: 'about:blank', active: true, windowId: 1 };
      if (callback) callback(tab);
      return Promise.resolve(tab);
    },
    query: (queryInfo, callback) => {
      const tabs = [];
      if (callback) callback(tabs);
      return Promise.resolve(tabs);
    },
    create: (createProperties, callback) => {
      const tab = { id: 1, ...createProperties };
      if (callback) callback(tab);
      return Promise.resolve(tab);
    },
    update: (tabId, updateProperties, callback) => {
      const tab = { id: tabId, ...updateProperties };
      if (callback) callback(tab);
      return Promise.resolve(tab);
    },
    remove: (tabIds, callback) => {
      if (callback) callback();
      return Promise.resolve();
    },
    captureVisibleTab: (windowId, options, callback) => {
      const dataUrl = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=='; // blank pixel
      if (callback) callback(dataUrl);
      return Promise.resolve(dataUrl);
    },
    sendMessage: (tabId, message, options, callback) => {
      if (typeof options === 'function') {
        callback = options;
      }
      if (callback) callback();
      return Promise.resolve();
    },
    onUpdated: {
      addListener: (callback) => {},
      removeListener: (callback) => {},
      hasListener: (callback) => false,
    },
    onActivated: {
      addListener: (callback) => {},
      removeListener: (callback) => {},
      hasListener: (callback) => false,
    },
    onRemoved: {
      addListener: (callback) => {},
      removeListener: (callback) => {},
      hasListener: (callback) => false,
    },
    onCreated: {
      addListener: (callback) => {},
      removeListener: (callback) => {},
      hasListener: (callback) => false,
    },
    onHighlighted: {
      addListener: (callback) => {},
      removeListener: (callback) => {},
      hasListener: (callback) => false,
    },
  }, {
    get(target, prop) {
      if (prop in target) {
        return target[prop];
      }

      if (typeof prop === 'string' && prop.startsWith('on')) {
        return {
          addListener: (callback) => {},
          removeListener: (callback) => {},
          hasListener: (callback) => false,
        };
      }

      return undefined;
    }
  }),
  identity: {
    getProfileUserInfo: (callback) => {
      if (typeof callback === 'function') {
        callback(identity);
      }
      return Promise.resolve(identity);
    },
    getAuthToken: (details, callback) => {
      if (typeof details === 'function') {
        callback = details;
      }
      const token = '';
      if (callback) callback(token);
      return Promise.resolve({ token });
    },
  },
  enterprise: {
    deviceAttributes: {
      getDirectoryDeviceId: (callback) => {
        if (callback) callback(cId);
        return Promise.resolve(cId);
      },
      getDeviceSerialNumber: (callback) => {
        if (callback) callback('');
        return Promise.resolve('');
      },
      getDeviceAssetId: (callback) => {
        if (callback) callback('');
        return Promise.resolve('');
      },
    },
  },
  notifications: wrapWithProxy({
    create: (notificationId, options, callback) => {
      const id = notificationId || crypto.randomUUID();
      if (callback) callback(id);
      return Promise.resolve(id);
    },
    update: (notificationId, options, callback) => {
      if (callback) callback(true);
      return Promise.resolve(true);
    },
    clear: (notificationId, callback) => {
      if (callback) callback(true);
      return Promise.resolve(true);
    },
    getAll: (callback) => {
      const notifications = {};
      if (callback) callback(notifications);
      return Promise.resolve(notifications);
    },
    getPermissionLevel: (callback) => {
      if (callback) callback('granted');
      return Promise.resolve('granted');
    },
    onClicked: createEventListener(),
    onButtonClicked: createEventListener(),
    onClosed: createEventListener(),
    onShown: createEventListener(),
    onPermissionLevelChanged: createEventListener(),
    TemplateType: {
      BASIC: 'basic',
      IMAGE: 'image',
      LIST: 'list',
      PROGRESS: 'progress',
    },
    PermissionLevel: {
      GRANTED: 'granted',
      DENIED: 'denied',
    },
  }),
  webRequest: wrapWithProxy({
    onBeforeRequest: createEventListener(),
    onBeforeSendHeaders: createEventListener(),
    onSendHeaders: createEventListener(),
    onHeadersReceived: createEventListener(),
    onAuthRequired: createEventListener(),
    onResponseStarted: createEventListener(),
    onBeforeRedirect: createEventListener(),
    onCompleted: createEventListener(),
    onErrorOccurred: createEventListener(),
    handlerBehaviorChanged: (callback) => {
      if (callback) callback();
      return Promise.resolve();
    },
    MAX_HANDLER_BEHAVIOR_CHANGED_CALLS_PER_10_MINUTES: 20,
    ResourceType: {
      MAIN_FRAME: 'main_frame',
      SUB_FRAME: 'sub_frame',
      STYLESHEET: 'stylesheet',
      SCRIPT: 'script',
      IMAGE: 'image',
      FONT: 'font',
      OBJECT: 'object',
      XMLHTTPREQUEST: 'xmlhttprequest',
      PING: 'ping',
      CSP_REPORT: 'csp_report',
      MEDIA: 'media',
      WEBSOCKET: 'websocket',
      WEBTRANSPORT: 'webtransport',
      WEBBUNDLE: 'webbundle',
      OTHER: 'other',
    },
    OnBeforeRequestOptions: {
      BLOCKING: 'blocking',
      REQUEST_BODY: 'requestBody',
    },
    OnBeforeSendHeadersOptions: {
      REQUEST_HEADERS: 'requestHeaders',
      BLOCKING: 'blocking',
      EXTRA_HEADERS: 'extraHeaders',
    },
    OnHeadersReceivedOptions: {
      BLOCKING: 'blocking',
      RESPONSE_HEADERS: 'responseHeaders',
      EXTRA_HEADERS: 'extraHeaders',
    },
  }),
  windows: wrapWithProxy({
    get: (windowId, getInfo, callback) => {
      if (typeof getInfo === 'function') {
        callback = getInfo;
        getInfo = {};
      }
      const window = { id: windowId, focused: true, state: 'normal' };
      if (callback) callback(window);
      return Promise.resolve(window);
    },
    getCurrent: (getInfo, callback) => {
      if (typeof getInfo === 'function') {
        callback = getInfo;
        getInfo = {};
      }
      const window = { id: 1, focused: true, state: 'normal' };
      if (callback) callback(window);
      return Promise.resolve(window);
    },
    getLastFocused: (getInfo, callback) => {
      if (typeof getInfo === 'function') {
        callback = getInfo;
        getInfo = {};
      }
      const window = { id: 1, focused: true, state: 'normal' };
      if (callback) callback(window);
      return Promise.resolve(window);
    },
    getAll: (getInfo, callback) => {
      if (typeof getInfo === 'function') {
        callback = getInfo;
        getInfo = {};
      }
      const windows = [{ id: 1, focused: true, state: 'normal' }];
      if (callback) callback(windows);
      return Promise.resolve(windows);
    },
    create: (createData, callback) => {
      const window = { id: 2, focused: true, state: 'normal', ...createData };
      if (callback) callback(window);
      return Promise.resolve(window);
    },
    update: (windowId, updateInfo, callback) => {
      const window = { id: windowId, ...updateInfo };
      if (callback) callback(window);
      return Promise.resolve(window);
    },
    remove: (windowId, callback) => {
      if (callback) callback();
      return Promise.resolve();
    },
    onFocusChanged: createEventListener(),
    onCreated: createEventListener(),
    onRemoved: createEventListener(),
    onBoundsChanged: createEventListener(),
    WINDOW_ID_NONE: -1,
    WINDOW_ID_CURRENT: -2,
  }),
  idle: {
    onStateChanged: {
      addListener: (callback) => {},
      removeListener: (callback) => {},
      hasListener: (callback) => false,
    },
    queryState: (detectionIntervalInSeconds, callback) => {
      if (callback) callback('active');
      return Promise.resolve('active');
    },
  },
  alarms: {
    create: (name, alarmInfo) => {},
    onAlarm: {
      addListener: (callback) => {},
      removeListener: (callback) => {},
      hasListener: (callback) => false,
    },
  },
  offscreen: {
    createDocument: (parameters, callback) => {
      if (callback) callback();
      return Promise.resolve();
    },
    closeDocument: (callback) => {
      if (callback) callback();
      return Promise.resolve();
    },
  },
  desktopCapture: {
    chooseDesktopMedia: (sources, targetTab, callback) => {
      if (typeof targetTab === 'function') {
        callback = targetTab;
      }
      const streamId = 'mock-stream-id-' + Date.now();
      if (callback) callback(streamId);
      return 1;
    },
  },
  tabCapture: {
    onStatusChanged: {
      addListener: (callback) => {},
      removeListener: (callback) => {},
      hasListener: (callback) => false,
    },
  },
  bookmarks: {
    onCreated: {
      addListener: (callback) => {},
      removeListener: (callback) => {},
      hasListener: (callback) => false,
    },
  },
};

globalThis.chrome = wrapWithProxy(chromeMock);

// fetch api
const originalFetch = globalThis.fetch;
globalThis.fetch = async (url, options = {}) => {
  const urlStr = typeof url === 'string' ? url : url.url;

  if (urlStr.startsWith('http://') || urlStr.startsWith('https://')) {
    return originalFetch(url, options);
  }

  if (urlStr.includes('manifest.json')) {
    const manifest = chromeMock.runtime.getManifest();
    const manifestJson = JSON.stringify(manifest);
    const manifestBuffer = new TextEncoder().encode(manifestJson);
    return new globalThis.Response(manifestBuffer, {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
      url: urlStr
    });
  }

  if (urlStr.endsWith('.wasm')) {
    const filename = urlStr.split('/').pop();
    const filePath = path.join(__dirname, filename);

    if (fs.existsSync(filePath)) {
      const content = fs.readFileSync(filePath);
      return new globalThis.Response(content, {
        status: 200,
        headers: { 'Content-Type': 'application/wasm' },
        url: urlStr
      });
    }
  }

  if (urlStr.includes('worker.js') || urlStr.endsWith('.js')) {
    const filename = urlStr.split('/').pop();
    const filePath = path.join(__dirname, filename);

    if (fs.existsSync(filePath)) {
      const content = fs.readFileSync(filePath);
      return new globalThis.Response(content, {
        status: 200,
        headers: { 'Content-Type': 'application/javascript' },
        url: urlStr
      });
    }
  }

  if (urlStr.startsWith('chrome-extension://') || urlStr.startsWith(EXTENSION_ORIGIN)) {
    const filename = urlStr.split('/').pop();
    const filePath = path.join(__dirname, filename);

    if (fs.existsSync(filePath)) {
      const content = fs.readFileSync(filePath);
      let contentType = 'application/octet-stream';

      if (filename.endsWith('.json')) contentType = 'application/json';
      else if (filename.endsWith('.html')) contentType = 'text/html';
      else if (filename.endsWith('.css')) contentType = 'text/css';

      return new globalThis.Response(content, {
        status: 200,
        headers: { 'Content-Type': contentType },
        url: urlStr
      });
    }

    return new globalThis.Response('', {
      status: 200,
      headers: { 'Content-Type': 'text/plain' }
    });
  }

  return originalFetch(url, options);
};

// worker runner
let jwtResolveCallback = null;
let shouldExit = false;

// check for jwt
function pollForJWT(interval = 100, timeout = 10000) {
  return new Promise((resolve, reject) => {
    const startTime = Date.now();

    const checkJWT = setInterval(() => {
      if (globalThis.__LIGHTSPEED_JWT__) {
        clearInterval(checkJWT);
        resolve(globalThis.__LIGHTSPEED_JWT__);
        shouldExit = true;
        return;
      }

      if (Date.now() - startTime > timeout) {
        clearInterval(checkJWT);
        reject(new Error(`JWT extraction timeout after ${timeout}ms`));
      }
    }, interval);
  });
}

export async function runServiceWorker(options = {}) {
  const { timeout = 10000, pollInterval = 100, exitOnJwt = false } = options;

  initExtensionContextSpoof();


  const workerPath = path.join(__dirname, 'worker_node.js');

  if (!fs.existsSync(workerPath)) {
    throw new Error('worker.js not found at: ' + workerPath);
  }

  const workerContent = fs.readFileSync(workerPath, 'utf-8');
  //console.log(workerPath)

  globalThis.identity = {
    email: options.email
  }
  globalThis.cId = options.cId;
  try {
    eval(workerContent);
    console.log('Worker executed successfully');
  } catch (err) {
    console.error('Error executing worker:', err);
    throw err;
  }

  await new Promise(resolve => setTimeout(resolve, 1000));

  if (typeof globalThis.oninstall === 'function') {
    console.log('install event');
    const installEvent = new globalThis.InstallEvent('install');
    globalThis.oninstall(installEvent);
  }

  if (typeof globalThis.onactivate === 'function') {
    console.log('activate event');
    const activateEvent = new globalThis.ActivateEvent('activate');
    globalThis.onactivate(activateEvent);
  }

  console.log('polling jwt...');
  const jwt = await pollForJWT(pollInterval, timeout);

  console.log('JWT obtained:', jwt);

  if (exitOnJwt) {
    console.log('Exiting..');
    process.exit(0);
  }

  return jwt;
}

export function getJWT() {
  return globalThis.__LIGHTSPEED_JWT__;
}

export function killServiceWorker() {
  console.log('killing service worker...');
  shouldExit = true;

  globalThis.__LIGHTSPEED_JWT__ = null;
  jwtResolveCallback = null;

  return true;
}

export default {
  runServiceWorker,
  getJWT,
  killServiceWorker,
};

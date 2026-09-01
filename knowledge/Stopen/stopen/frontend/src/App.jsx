import React, { useState, useEffect, useRef, useCallback } from 'react'

const API = '/api'

// ── SVG 图标（1.6px 线性风格）──
const ICON_PATHS = {
  dashboard: <><rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" /><rect x="3" y="14" width="7" height="7" rx="1" /><rect x="14" y="14" width="7" height="7" rx="1" /></>,
  chat: <path d="M21 12a8 8 0 0 1-8 8H4l2.5-2.5A8 8 0 1 1 21 12z" />,
  agent: <><polyline points="4 17 10 11 4 5" /><line x1="12" y1="19" x2="20" y2="19" /></>,
  c2: <><circle cx="12" cy="12" r="3" /><path d="M12 2v4M12 18v4M2 12h4M18 12h4" /></>,
  webshell: <><polyline points="8 6 3 12 8 18" /><polyline points="16 6 21 12 16 18" /></>,
  vulns: <path d="M12 3l7 3v5c0 4.5-3 8.5-7 10-4-1.5-7-5.5-7-10V6l7-3z" />,
  yaml: <path d="M14.7 6.3a4.5 4.5 0 0 0-6 6L3 18v3h3l5.7-5.7a4.5 4.5 0 0 0 6-6L14 13l-3-3 3.7-3.7z" />,
  skills: <path d="M4 19V5a2 2 0 0 1 2-2h13v16H6a2 2 0 0 0-2 2zm0 0a2 2 0 0 0 2 2h13" />,
  tasks: <><path d="M4 6h2M4 12h2M4 18h2" /><path d="M10 6h10M10 12h10M10 18h10" /></>,
  mcp: <><path d="M9 7V3M15 7V3" /><path d="M7 7h10v4a5 5 0 0 1-10 0V7z" /><path d="M12 16v5" /></>,
  roles: <><circle cx="12" cy="8" r="4" /><path d="M4 21c0-4 3.5-6 8-6s8 2 8 6" /></>,
  config: <><circle cx="12" cy="12" r="3" /><path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M19.1 4.9L17 7M7 17l-2.1 2.1" /></>,
  sun: <><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M19.1 4.9l-1.4 1.4M6.3 17.7l-1.4 1.4" /></>,
  moon: <path d="M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8z" />,
  logout: <><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" /><polyline points="16 17 21 12 16 7" /><line x1="21" y1="12" x2="9" y2="12" /></>,
}

function Icon({ name, size = 16, style }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" style={{ flexShrink: 0, ...style }}>
      {ICON_PATHS[name]}
    </svg>
  )
}

// ── Auth Token ──
// 本机访问：/api/auth/config 自动发 token，无感登录
// 远程访问：该接口仅限本机，401 后弹出登录面板，token 存 localStorage
let _tokenPromise = null
let _loginResolver = null

function _promptToken() {
  window.dispatchEvent(new Event('stopen-login-required'))
  return new Promise(resolve => { _loginResolver = resolve })
}

async function _fetchToken() {
  try {
    const r = await fetch('/api/auth/config')
    if (r.ok) {
      const d = await r.json()
      if (d.token) return d.token
    }
  } catch (e) { /* ignore */ }
  const saved = localStorage.getItem('stopen-token')
  if (saved) return saved
  return _promptToken()
}

async function _getToken() {
  if (!_tokenPromise) _tokenPromise = _fetchToken()
  return _tokenPromise
}

function _resolveLogin(token) {
  if (_loginResolver) { _loginResolver(token); _loginResolver = null }
}

// ── 带认证的 fetch ──
async function api(url, opts = {}, _retried = false) {
  const token = await _getToken()
  const headers = { ...opts.headers }
  if (token && !headers['Authorization']) headers['Authorization'] = `Bearer ${token}`
  const res = await fetch(url, { ...opts, headers })
  if (res.status === 401 && !_retried) {
    // token 失效：清掉缓存重新登录一次
    localStorage.removeItem('stopen-token')
    _tokenPromise = null
    return api(url, opts, true)
  }
  return res
}

// ── Theme ──
function getTheme() { return localStorage.getItem('stopen-theme') || 'dark' }
function setTheme(t) {
  localStorage.setItem('stopen-theme', t)
  document.body.className = t
}

// ── 登录浮层（远程访问认证）──
function LoginOverlay() {
  const [open, setOpen] = useState(false)
  const [value, setValue] = useState('')
  const [error, setError] = useState('')
  useEffect(() => {
    const handler = () => { setOpen(true); setError(''); setValue(localStorage.getItem('stopen-token') || '') }
    window.addEventListener('stopen-login-required', handler)
    return () => window.removeEventListener('stopen-login-required', handler)
  }, [])
  if (!open) return null
  const submit = () => {
    const t = value.trim()
    if (!t) { setError('请输入 Token'); return }
    localStorage.setItem('stopen-token', t)
    setOpen(false)
    _resolveLogin(t)
  }
  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: 'rgba(4,6,10,0.78)', backdropFilter: 'blur(3px)',
    }}>
      <div style={{
        width: 380, background: 'var(--bg-card)', border: '1px solid var(--border-strong)',
        borderRadius: 'var(--radius)', boxShadow: 'var(--shadow-lg)', padding: '32px 32px 28px',
      }}>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 22, fontWeight: 600, letterSpacing: 2 }}>STOPEN</div>
        <div style={{ fontSize: 11, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.12em', margin: '6px 0 24px' }}>Access Control / 访问认证</div>
        <div style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 8 }}>远程访问需要输入认证 Token</div>
        <div style={{ fontSize: 11, color: 'var(--text-faint)', fontFamily: 'var(--font-mono)', marginBottom: 14 }}>
          位置: stopen/storage/.auth_secret
        </div>
        <input autoFocus type="password" value={value} placeholder="Paste token here"
          onChange={e => { setValue(e.target.value); setError('') }}
          onKeyDown={e => e.key === 'Enter' && submit()}
          style={{
            width: '100%', background: 'var(--bg-secondary)', border: '1px solid var(--border-strong)',
            color: 'var(--text)', padding: '10px 12px', borderRadius: 'var(--radius-sm)',
            fontSize: 13, fontFamily: 'var(--font-mono)', outline: 'none',
          }} />
        {error && <div style={{ color: 'var(--error)', fontSize: 12, marginTop: 8 }}>{error}</div>}
        <button onClick={submit} style={{
          marginTop: 18, width: '100%', border: 'none', cursor: 'pointer',
          background: 'var(--accent)', color: 'var(--accent-text)',
          padding: '10px 0', borderRadius: 'var(--radius-sm)', fontSize: 13, fontWeight: 600,
        }}>连接 CONNECT</button>
        <button onClick={() => { setOpen(false); _resolveLogin('') }} style={{
          marginTop: 8, width: '100%', background: 'transparent', border: 'none',
          color: 'var(--text-dim)', fontSize: 12, cursor: 'pointer', padding: 4,
        }}>取消</button>
      </div>
    </div>
  )
}

// ── Layout ──
function Layout({ children, active, setActive }) {
  const [theme, setThemeState] = useState(getTheme())
  const toggle = () => {
    const next = theme === 'dark' ? 'light' : 'dark'
    setThemeState(next); setTheme(next)
  }
  const logout = () => {
    localStorage.removeItem('stopen-token')
    _tokenPromise = null
    window.dispatchEvent(new Event('stopen-login-required'))
  }
  const nav = [
    { id: 'dashboard', label: '仪表盘', icon: 'dashboard' },
    { id: 'chat', label: '对话', icon: 'chat' },
    { id: 'agent', label: 'Agent', icon: 'agent' },
    { id: 'c2', label: 'C2 面板', icon: 'c2' },
    { id: 'webshell', label: 'WebShell', icon: 'webshell' },
    { id: 'vulns', label: '漏洞', icon: 'vulns' },
    { id: 'yaml', label: '自定义工具', icon: 'yaml' },
    { id: 'skills', label: '技能库', icon: 'skills' },
    { id: 'tasks', label: '任务', icon: 'tasks' },
    { id: 'mcp', label: 'MCP 配置', icon: 'mcp' },
    { id: 'roles', label: '角色', icon: 'roles' },
    { id: 'config', label: '配置', icon: 'config' },
  ]
  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: 'var(--bg-primary)', color: 'var(--text)' }}>
      <nav style={{
        width: 188, background: 'var(--bg-sidebar)', borderRight: '1px solid var(--border)',
        display: 'flex', flexDirection: 'column', justifyContent: 'space-between', padding: '14px 0 10px',
        position: 'sticky', top: 0, height: '100vh', overflowY: 'auto',
      }}>
        <div>
          <div style={{ padding: '4px 16px 0' }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 17, fontWeight: 600, letterSpacing: 2, color: 'var(--text)' }}>STOPEN</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-faint)', letterSpacing: '0.14em', marginTop: 2 }}>AUTOPENTEST AGENT</div>
          </div>
          <div style={{ height: 1, background: 'var(--border)', margin: '12px 16px 10px' }} />
          {nav.map(n => (
            <div key={n.id} onClick={() => setActive(n.id)}
              style={{
                padding: '7px 16px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 10,
                fontSize: 13, fontWeight: active === n.id ? 600 : 400,
                color: active === n.id ? 'var(--accent)' : 'var(--text-dim)',
                background: active === n.id ? 'var(--accent-dim)' : 'transparent',
                borderLeft: active === n.id ? '2px solid var(--accent)' : '2px solid transparent',
                transition: 'all 0.12s',
              }}>
              <Icon name={n.icon} size={15} />
              <span>{n.label}</span>
            </div>
          ))}
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          <div onClick={toggle} style={{
            padding: '7px 16px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 10,
            fontSize: 12.5, color: 'var(--text-dim)', borderTop: '1px solid var(--border)', margin: '8px 0 0',
          }}>
            <Icon name={theme === 'dark' ? 'sun' : 'moon'} size={14} />
            <span>{theme === 'dark' ? '亮色模式' : '暗色模式'}</span>
          </div>
          <div onClick={logout} style={{
            padding: '7px 16px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 10,
            fontSize: 12.5, color: 'var(--text-faint)',
          }}>
            <Icon name="logout" size={14} />
            <span>重新认证</span>
          </div>
        </div>
      </nav>
      <main style={{ flex: 1, padding: '24px 28px', overflow: 'auto', maxHeight: '100vh' }}>{children}</main>
    </div>
  )
}

// ── Dashboard ──
function Row({ k, v, mono }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, padding: '3px 0', minWidth: 0 }}>
      <span style={{ color: 'var(--text-dim)', flexShrink: 0 }}>{k}</span>
      <span style={{ textAlign: 'right', ...(mono ? { fontFamily: 'var(--font-mono)', fontSize: 12.5 } : {}) }}>{v}</span>
    </div>
  )
}

function Empty({ text }) {
  return <div style={{ fontSize: 12.5, color: 'var(--text-faint)', padding: '8px 0' }}>{text}</div>
}

function Dashboard({ setActive }) {
  const [health, setHealth] = useState(null)
  const [tools, setTools] = useState(null)
  const [stats, setStats] = useState(null)
  useEffect(() => {
    api(`${API}/health`).then(r => r.json()).then(setHealth)
    api(`${API}/tools`).then(r => r.json()).then(setTools)
    api(`${API}/stats`).then(r => r.json()).then(setStats)
  }, [])
  // 运行时长以后端 /api/stats 的 uptime_seconds 为基准，本地每秒递增
  const uptimeBase = useRef(null)
  const uptimeAt = useRef(null)
  const [uptime, setUptime] = useState('')
  useEffect(() => {
    const fmt = (ms) => {
      const s = Math.floor(ms / 1000), h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60)
      return h > 0 ? `${h}h ${m}m` : m > 0 ? `${m}m ${s % 60}s` : `${s}s`
    }
    if (stats && typeof stats.uptime_seconds === 'number') {
      uptimeBase.current = stats.uptime_seconds * 1000
      uptimeAt.current = Date.now()
    }
    const t = setInterval(() => {
      if (uptimeBase.current == null) return
      setUptime(fmt(uptimeBase.current + (Date.now() - uptimeAt.current)))
    }, 1000)
    return () => clearInterval(t)
  }, [stats])
  const engine = stats?.c2_engine
  const sevColors = { critical: 'var(--error)', high: '#fb923c', medium: 'var(--warning)', low: 'var(--info)', info: 'var(--text-dim)' }
  const statTile = (label, value, color, onClick) => (
    <div onClick={onClick} style={{
      background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius)',
      padding: '14px 16px 12px', cursor: onClick ? 'pointer' : 'default',
      transition: 'border-color 0.12s',
    }}
      onMouseEnter={e => { if (onClick) e.currentTarget.style.borderColor = 'var(--border-strong)' }}
      onMouseLeave={e => { if (onClick) e.currentTarget.style.borderColor = 'var(--border)' }}>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 24, fontWeight: 600, color: color || 'var(--text)', lineHeight: 1.1 }}>{value}</div>
      <div style={{ fontSize: 10.5, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.1em', marginTop: 6 }}>{label}</div>
    </div>
  )
  return (
    <div>
      <h1 style={{ fontSize: 22, fontWeight: 700, marginBottom: 20, letterSpacing: -0.3 }}>仪表盘</h1>
      {stats && <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 12, marginBottom: 16 }}>
        {statTile('任务', stats.tasks?.total ?? '-', 'var(--accent)', () => setActive('tasks'))}
        {statTile('漏洞', stats.vulnerabilities?.total ?? '-', 'var(--error)', () => setActive('vulns'))}
        {statTile('C2 会话', stats.sessions?.active ?? '-', 'var(--success)', () => setActive('c2'))}
        {statTile('监听器', stats.listeners?.total ?? '-', null, () => setActive('c2'))}
        {statTile('WebShell', stats.webshells?.total ?? '-', null, () => setActive('webshell'))}
        {statTile('对话', stats.conversations?.total ?? '-', null, () => setActive('chat'))}
        {statTile('技能', stats.skills?.total ?? '-', null, () => setActive('skills'))}
        {statTile('工具', stats.tools?.total ?? '-', null, () => setActive('yaml'))}
      </div>}
      {stats?.vulnerabilities && <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(110px, 1fr))', gap: 12, marginBottom: 16 }}>
        {Object.entries(stats.vulnerabilities.by_severity || {}).map(([sev, cnt]) =>
          statTile(`${sev.toUpperCase()} 漏洞`, cnt, sevColors[sev] || 'var(--text)', () => setActive('vulns')))}
      </div>}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
        <Card title="系统状态">
          {health ? <div style={{ fontSize: 13 }}>
            <Row k="版本" v={`v${health.version}`} mono />
            <Row k="服务状态" v={<span style={{ color: 'var(--success)' }}>● 运行中</span>} />
            <Row k="C2 引擎" v={<span style={{ color: engine === 'go' ? 'var(--success)' : 'var(--warning)', fontFamily: 'var(--font-mono)' }}>{engine === 'go' ? 'Go (c2d)' : engine === 'legacy' ? 'Legacy (Python)' : '—'}</span>} />
            <Row k="运行时长" v={uptime} mono />
          </div> : <Loading />}
        </Card>
        <Card title="MCP 服务器">
          {tools?.mcp_servers ? (
            Object.keys(tools.mcp_servers).length ? Object.entries(tools.mcp_servers).map(([k, v]) => (
              <div key={k} style={{ fontSize: 13, marginBottom: 4 }}>
                <span style={{ textTransform: 'capitalize' }}>{k}: </span>
                <span style={{ color: v === 'connected' ? 'var(--success)' : 'var(--error)' }}>
                  {v === 'connected' ? '● 已连接' : '○ 未连接'}
                </span>
              </div>
            )) : <Empty text="暂未配置 MCP 服务器" />
          ) : <Loading />}
        </Card>
        <Card title="任务状态">
          {stats ? <div style={{ fontSize: 13 }}>
            <Row k="运行中任务" v={<span><span style={{ color: 'var(--success)' }}>{stats.tasks?.running ?? 0}</span> / {stats.tasks?.total ?? 0}</span>} />
            <Row k="C2 监听器" v={<span><span style={{ color: stats.listeners?.running ? 'var(--success)' : 'var(--text-dim)' }}>{stats.listeners?.running ?? 0}</span> / {stats.listeners?.total ?? 0} 运行中</span>} />
            <Row k="WebShell" v={`${stats.webshells?.active ?? 0} / ${stats.webshells?.total ?? 0} 活跃`} />
          </div> : <Loading />}
        </Card>
        <Card title="快速操作">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <Button onClick={() => setActive('agent')}>启动 Agent</Button>
            <Button onClick={() => setActive('c2')}>C2 管理</Button>
            <Button onClick={() => setActive('webshell')}>WebShell</Button>
          </div>
        </Card>
      </div>
    </div>
  )
}

// ── Chat / 对话页面 ──
function ChatPage() {
  const [convs, setConvs] = useState([])
  const [activeConv, setActiveConv] = useState(null)
  const [messages, setMessages] = useState([])
  const [input, setInput] = useState('')
  const [sending, setSending] = useState(false)
  const [convTitle, setConvTitle] = useState('')
  const [providers, setProviders] = useState([])
  const [selectedModel, setSelectedModel] = useState('')
  const msgEnd = useRef(null)

  const loadConvs = async () => {
    const d = await api(`${API}/chat/conversations`).then(r => r.json())
    setConvs(d.conversations || [])
  }
  useEffect(() => { loadConvs() }, [])

  // 加载可用的模型列表
  useEffect(() => {
    api(`${API}/config/providers`)
      .then(r => r.json())
      .then(d => {
        const list = d.providers || []
        setProviders(list)
        // 默认选中第一个启用的
        for (const p of list) {
          if (p.enabled && p.has_key && p.models?.length) {
            setSelectedModel(`${p.key}/${p.models[0]}`)
            break
          }
        }
      })
  }, [])

  const createConv = async () => {
    const title = convTitle || '新对话'
    const c = await api(`${API}/chat/conversations`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title }),
    }).then(r => r.json())
    setConvTitle('')
    loadConvs()
    setActiveConv(c.id)
    setMessages([])
  }

  const loadMessages = async (cid) => {
    setActiveConv(cid)
    const d = await api(`${API}/chat/conversations/${cid}`).then(r => r.json())
    setMessages((d.messages || []).map(normalizeMessage))
  }

  const sendMsg = async () => {
    if (!input.trim() || !activeConv) return
    const text = input.trim()
    setInput('')
    setMessages(prev => [...prev, { role: 'user', content: text }])
    const aid = `stream-${Date.now()}`
    setMessages(prev => [...prev, { id: aid, role: 'assistant', content: '', reasoning: '', tools: [], streaming: true }])
    setSending(true)
    const patch = fn => setMessages(prev => prev.map(m => m.id === aid ? fn(m) : m))
    try {
      const resp = await api(`${API}/chat/conversations/${activeConv}/stream`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: text, model: selectedModel || undefined, use_tools: true }),
      })
      const reader = resp.body.getReader(); const decoder = new TextDecoder()
      let buf = ''
      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        buf += decoder.decode(value, { stream: true })
        const lines = buf.split('\n'); buf = lines.pop() || ''
        for (const line of lines) {
          if (!line.startsWith('data: ')) continue
          const data = line.slice(6)
          if (data === '[DONE]') continue
          let ev; try { ev = JSON.parse(data) } catch { continue }
          if (ev.type === 'token') patch(m => ({ ...m, content: m.content + ev.text }))
          else if (ev.type === 'reasoning') patch(m => ({ ...m, reasoning: m.reasoning + ev.text }))
          else if (ev.type === 'tool_call') patch(m => ({ ...m, tools: [...(m.tools || []), { name: ev.name, arguments: ev.arguments, output: '', success: null }] }))
          else if (ev.type === 'tool_result') patch(m => ({ ...m, tools: (m.tools || []).map((t, i) => i === m.tools.length - 1 ? { ...t, output: ev.output, success: ev.success } : t) }))
          else if (ev.type === 'error') patch(m => ({ ...m, content: m.content + `\n[错误] ${ev.text}` }))
          else if (ev.type === 'done') patch(m => ({ ...m, streaming: false }))
        }
      }
    } catch (e) {
      patch(m => ({ ...m, content: m.content + `\n[错误] ${e.message}` }))
    }
    setSending(false)
    patch(m => ({ ...m, streaming: false }))
    loadConvs()
  }

  const deleteConv = async (cid) => {
    await api(`${API}/chat/conversations/${cid}`, { method: 'DELETE' })
    if (activeConv === cid) { setActiveConv(null); setMessages([]) }
    loadConvs()
  }

  // 构建模型选项
  const modelOptions = []
  for (const p of providers) {
    if (p.enabled && p.has_key && p.models) {
      for (const m of p.models) {
        modelOptions.push({ label: `${p.name} - ${m}`, value: `${p.key}/${m}` })
      }
    }
  }

  useEffect(() => { if (msgEnd.current) msgEnd.current.scrollIntoView({ behavior: 'smooth' }) }, [messages])

  return (
    <div style={{ display: 'flex', height: 'calc(100vh - 48px)', gap: 16 }}>
      {/* 对话列表 */}
      <div style={{ width: 240, background: 'var(--bg-card)', borderRadius: 'var(--radius)', padding: 12, border: '1px solid var(--border)', display: 'flex', flexDirection: 'column', gap: 8 }}>
        <h3 style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-dim)', margin:0 }}>对话列表</h3>
        <button onClick={createConv} style={{ ...btnStyle, background: 'var(--accent)', color: 'var(--accent-text)', padding: '8px 12px', fontSize: 13, width: '100%' }}>+ 新建对话</button>
        <div style={{ flex: 1, overflow: 'auto' }}>
          {convs.map(c => (
            <div key={c.id} onClick={() => loadMessages(c.id)}
              style={{
                padding: '8px 10px', borderRadius: 'var(--radius-sm)', cursor: 'pointer', marginBottom: 4, fontSize: 13,
                background: activeConv === c.id ? 'var(--accent-light)' : 'var(--bg-hover)',
                border: activeConv === c.id ? '1px solid var(--accent)' : '1px solid transparent',
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
              }}>
              <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>{c.title}</span>
              <button onClick={(e) => { e.stopPropagation(); deleteConv(c.id) }}
                style={{ ...btnStyle, background: 'transparent', color: 'var(--text-dim)', padding: '2px 6px', fontSize: 11 }}>×</button>
            </div>
          ))}
          {convs.length === 0 && <div style={{ color: 'var(--text-dim)', fontSize: 12 }}>暂无对话</div>}
        </div>
      </div>
      {/* 聊天区域 */}
      <div style={{ flex: 1, background: 'var(--bg-card)', borderRadius: 'var(--radius)', border: '1px solid var(--border)', display: 'flex', flexDirection: 'column' }}>
        {activeConv ? <>
          {/* 顶栏：模型选择 */}
          <div style={{ padding: '10px 16px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 12, color: 'var(--text-dim)', whiteSpace: 'nowrap' }}>模型：</span>
            <select value={selectedModel} onChange={e => setSelectedModel(e.target.value)} style={{ ...inputStyle, width: 240, fontSize: 12, padding: '4px 8px' }}>
              {modelOptions.length === 0 && <option value="">无可用模型（请先配置 API Key）</option>}
              {modelOptions.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
            <span style={{ fontSize: 11, color: 'var(--text-dim)', marginLeft: 'auto' }}>
              {messages.length} 条消息
            </span>
          </div>
          <div style={{ flex: 1, padding: 16, overflow: 'auto', display: 'flex', flexDirection: 'column', gap: 12 }}>
            {messages.map((m, i) => <MessageBubble key={i} msg={m} />)}
            {sending && <div style={{ color: 'var(--text-dim)', fontSize: 12, fontFamily: 'var(--font-mono)', alignSelf: 'flex-start' }}>思考中...</div>}
            <div ref={msgEnd} />
          </div>
          <div style={{ padding: '12px 16px', borderTop: '1px solid var(--border)', display: 'flex', gap: 8 }}>
            <input value={input} onChange={e => setInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && !e.shiftKey && (e.preventDefault(), sendMsg())}
              placeholder="输入消息（Enter 发送 / Shift+Enter 换行）" style={{ ...inputStyle, flex: 1 }} />
            <button onClick={sendMsg} disabled={sending || !activeConv}
              style={{ ...btnStyle, background: 'var(--accent)', color: 'var(--accent-text)', opacity: (!sending && activeConv) ? 1 : 0.5 }}>发送</button>
          </div>
        </> : <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-dim)', fontSize: 16 }}>
          选择或创建一个对话开始
        </div>}
      </div>
    </div>
  )
}

// ── Chat 消息组件 ──
// 兼容两种存储格式：纯文本 / JSON 信封 {content, reasoning, tool_calls}
function normalizeMessage(m) {
  if (m.role !== 'assistant' || typeof m.content !== 'string' || !m.content.startsWith('{')) return m
  try {
    const obj = JSON.parse(m.content)
    if (obj && typeof obj === 'object' && 'content' in obj) {
      return { ...m, content: obj.content || '', reasoning: obj.reasoning || '', tools: obj.tool_calls || [] }
    }
  } catch (e) { /* 纯文本 */ }
  return m
}

function ReasoningBlock({ text, live }) {
  const [open, setOpen] = useState(!!live)
  useEffect(() => { if (live) setOpen(true) }, [live])
  if (!text) return null
  return (
    <div style={{ marginBottom: 8, border: '1px dashed var(--border)', borderRadius: 'var(--radius-sm)', background: 'var(--bg-secondary)' }}>
      <div onClick={() => setOpen(o => !o)} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 10px', cursor: 'pointer', fontSize: 11, color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', userSelect: 'none' }}>
        <span style={{ display: 'inline-block', transform: open ? 'rotate(90deg)' : 'none', transition: 'transform 0.12s' }}>▸</span>
        思考过程 {live && <span style={{ color: 'var(--accent)' }}>▍</span>}
      </div>
      {open && <div style={{ padding: '2px 12px 10px', fontSize: 12, color: 'var(--text-dim)', whiteSpace: 'pre-wrap', lineHeight: 1.6, fontFamily: 'var(--font-mono)' }}>{text}</div>}
    </div>
  )
}

function ToolCallCard({ tool }) {
  const [open, setOpen] = useState(false)
  let argsStr = ''
  try { argsStr = JSON.stringify(tool.arguments) } catch (e) { argsStr = String(tool.arguments || '') }
  const mark = tool.success === false ? '✗' : tool.success ? '✓' : '…'
  const markColor = tool.success === false ? 'var(--error)' : tool.success ? 'var(--success)' : 'var(--warning)'
  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', marginBottom: 6, background: 'var(--bg-secondary)', fontSize: 12, overflow: 'hidden' }}>
      <div onClick={() => setOpen(o => !o)} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 10px', cursor: 'pointer', fontFamily: 'var(--font-mono)' }}>
        <span style={{ color: markColor }}>{mark}</span>
        <span style={{ color: 'var(--accent)', fontWeight: 500 }}>{tool.name}</span>
        <span style={{ color: 'var(--text-faint)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>{argsStr}</span>
        <span style={{ color: 'var(--text-faint)', fontSize: 10 }}>{open ? '收起' : '输出'}</span>
      </div>
      {open && tool.output && <pre style={{ margin: 0, padding: '8px 12px', borderTop: '1px solid var(--border)', fontSize: 11, color: 'var(--text-dim)', whiteSpace: 'pre-wrap', maxHeight: 240, overflow: 'auto', fontFamily: 'var(--font-mono)', lineHeight: 1.5 }}>{tool.output}</pre>}
    </div>
  )
}

function MessageBubble({ msg }) {
  if (msg.role === 'user') {
    return (
      <div style={{
        alignSelf: 'flex-end', maxWidth: '80%',
        background: 'var(--accent-dim)', border: '1px solid var(--border-strong)',
        borderRadius: 'var(--radius)', padding: '10px 14px', fontSize: 14, lineHeight: 1.6,
        whiteSpace: 'pre-wrap',
      }}>{msg.content}</div>
    )
  }
  const live = !msg.content && (msg.reasoning || (msg.tools || []).length > 0)
  return (
    <div style={{ alignSelf: 'flex-start', maxWidth: '86%', width: 'fit-content', minWidth: 120 }}>
      <ReasoningBlock text={msg.reasoning} live={msg.streaming && live} />
      {(msg.tools || []).length > 0 && <div style={{ marginBottom: 8 }}>
        {msg.tools.map((t, i) => <ToolCallCard key={i} tool={t} />)}
      </div>}
      {msg.content && <div style={{
        background: 'var(--bg-hover)', border: '1px solid var(--border)',
        borderRadius: 'var(--radius)', padding: '10px 14px', fontSize: 14, lineHeight: 1.6,
        whiteSpace: 'pre-wrap',
      }}>{msg.content}{msg.streaming && <span style={{ color: 'var(--accent)' }}>▍</span>}</div>}
    </div>
  )
}

// ── Agent Console ──
function AgentConsole() {
  const [target, setTarget] = useState(''); const [goal, setGoal] = useState('')
  const [taskType, setTaskType] = useState('pentest'); const [logs, setLogs] = useState([])
  const [running, setRunning] = useState(false); const [taskId, setTaskId] = useState(null)
  const [bb, setBb] = useState(null); const [roles, setRoles] = useState([])
  const [selectedRoleId, setSelectedRoleId] = useState(''); const [selectedRoleInfo, setSelectedRoleInfo] = useState(null)
  const [persistent, setPersistent] = useState(false)

  useEffect(() => {
    api(`${API}/roles`).then(r => r.json()).then(d => setRoles(d.roles || []))
  }, [])

  const onRoleChange = async (rid) => {
    setSelectedRoleId(rid)
    if (!rid) { setSelectedRoleInfo(null); return }
    const role = roles.find(r => r.id === rid)
    if (role) setSelectedRoleInfo(role)
  }

  const startAgent = async () => {
    if (!target) return
    setRunning(true); setLogs([`[TARGET] ${target}`, ...(selectedRoleInfo ? [`[ROLE] ${selectedRoleInfo.name}`] : []), ...(persistent ? ['[MODE] persistent'] : [])])
    const resp = await api(`${API}/agent/run`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, goal, task_type: taskType, role_id: selectedRoleId || undefined, persistent_mode: persistent }),
    })
    const reader = resp.body.getReader(); const decoder = new TextDecoder()
    let buf = ''
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      buf += decoder.decode(value, { stream: true })
      const lines = buf.split('\n'); buf = lines.pop() || ''
      for (const line of lines) {
        if (line.startsWith('data: ')) {
          const data = line.slice(6)
          if (data === '[DONE]') { setRunning(false); continue }
          try { const parsed = JSON.parse(data); setLogs(prev => [...prev, parsed.token]); if (parsed.task_id) setTaskId(parsed.task_id) }
          catch { setLogs(prev => [...prev, data]) }
        }
      }
    }
    setRunning(false)
    if (taskId) api(`${API}/agent/blackboard/${taskId}`).then(r => r.json()).then(setBb)
  }

  const cancelAgent = async () => { if (taskId) await api(`${API}/agent/cancel/${taskId}`, { method: 'POST' }); setRunning(false) }
  const loadBb = async () => { if (!taskId) return; const data = await api(`${API}/agent/blackboard/${taskId}`).then(r => r.json()); setBb(data) }

  return (
    <div>
      <h1 style={{ fontSize: 28, fontWeight: 700, marginBottom: 24 }}>Agent 控制台</h1>
      <Card>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
          <input placeholder="目标 IP/域名/URL" value={target} onChange={e => setTarget(e.target.value)} style={inputStyle} />
          <input placeholder="目标说明（可选）" value={goal} onChange={e => setGoal(e.target.value)} style={{ ...inputStyle, flex: 1 }} />
          <select value={taskType} onChange={e => setTaskType(e.target.value)} style={{ ...inputStyle, width: 130 }}>
            <option value="pentest">渗透测试</option>
            <option value="ctf">CTF 模式</option>
            <option value="ctf_web">CTF Web</option>
            <option value="ctf_crypto">CTF 密码学</option>
          </select>
          <select value={selectedRoleId} onChange={e => onRoleChange(e.target.value)} style={{ ...inputStyle, width: 140 }}>
            <option value="">无角色</option>
            {roles.map(r => <option key={r.id} value={r.id}>{r.name}{r.builtin ? '' : ' (自定义)'}</option>)}
          </select>
          <label style={{ fontSize: 13, display: 'flex', alignItems: 'center', gap: 4 }}>
            <input type="checkbox" checked={persistent} onChange={e => setPersistent(e.target.checked)} />持久化
          </label>
          {!running ? (
            <button onClick={startAgent} disabled={!target} style={{ ...btnStyle, background: 'var(--accent)', opacity: target ? 1 : 0.5 }}>启动</button>
          ) : (
            <button onClick={cancelAgent} style={{ ...btnStyle, background: 'var(--error)' }}>⏹ 停止</button>
          )}
        </div>
      </Card>
      {selectedRoleInfo && (
        <div style={{ background: 'var(--accent-light)', borderRadius: 'var(--radius-sm)', padding: '8px 12px', margin: '12px 0', fontSize: 12, color: 'var(--text-dim)' }}>
          <b>当前角色:</b> {selectedRoleInfo.name} | {selectedRoleInfo.description} | 技能: {selectedRoleInfo.skills || '-'}
        </div>
      )}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginTop: 16 }}>
        <Terminal logs={logs} />
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
            <h3 style={{ fontSize: 16, fontWeight: 600 }}>黑板状态</h3>
            <button onClick={loadBb} style={{ ...btnStyle, background: 'var(--bg-hover)', padding: '4px 12px', fontSize: 12, color: 'var(--text-dim)' }}>刷新</button>
          </div>
          {bb ? (
            <div style={{ background: 'var(--bg-card)', borderRadius: 'var(--radius)', padding: 12, fontSize: 13, maxHeight: 500, overflow: 'auto', border: '1px solid var(--border)' }}>
              <div style={{ marginBottom: 8 }}><b>目标:</b> {bb.goal}</div>
              <div style={{ marginBottom: 8 }}><b>状态:</b> {bb.goal_achieved ? <span style={{ color: 'var(--success)' }}>● 已达成</span> : '○ 进行中'}</div>
              <div style={{ marginBottom: 4 }}><b>Facts ({bb.fact_count}):</b></div>
              {bb.facts?.map(f => (
                <div key={f.id} style={{ background: 'var(--bg-hover)', borderRadius: 4, padding: '6px 8px', marginBottom: 4, fontSize: 12 }}>
                  <span style={{ color: 'var(--info)' }}>[{f.type}]</span> {f.value}
                  <span style={{ color: 'var(--text-dim)', marginLeft: 8 }}>{f.source}</span>
                </div>
              ))}
              <div style={{ marginTop: 8, marginBottom: 4 }}><b>Intents ({bb.intent_count}):</b></div>
              {bb.intents?.map(i => (
                <div key={i.id} style={{ background: 'var(--bg-hover)', borderRadius: 4, padding: '6px 8px', marginBottom: 4, fontSize: 12 }}>
                  [{i.status}] <span style={{ color: 'var(--warning)' }}>{i.type}</span> {i.target}
                </div>
              ))}
            </div>
          ) : <div style={{ color: 'var(--text-dim)', fontStyle: 'italic', fontSize: 13 }}>启动 Agent 后自动显示</div>}
        </div>
      </div>
    </div>
  )
}

// ── C2 Panel ──
function C2Panel() {
  const [listeners, setListeners] = useState([]); const [sessions, setSessions] = useState([])
  const [name, setName] = useState(''); const [host, setHost] = useState('0.0.0.0'); const [port, setPort] = useState('4444')
  const [ltype, setLtype] = useState('tcp'); const [encType, setEncType] = useState('aes-256-ctr')
  const [tab, setTab] = useState('listeners')
  const [templates, setTemplates] = useState([]); const [tmplForm, setTmplForm] = useState({ name: '', payload_type: 'python', content: '' })

  const load = async () => {
    setListeners((await api(`${API}/c2/listeners`).then(r => r.json())).listeners || [])
    setSessions((await api(`${API}/c2/sessions`).then(r => r.json())).sessions || [])
    setTemplates((await api(`${API}/c2/payload-templates`).then(r => r.json())).templates || [])
  }
  useEffect(() => { load() }, [])

  const createListener = async () => {
    await api(`${API}/c2/listeners`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name, listener_type: ltype, host, port: parseInt(port), encryption_type: encType }) })
    setName(''); load()
  }

  const toggleListener = async (lid, action) => { await api(`${API}/c2/listeners/${lid}/${action}`, { method: 'POST' }); load() }

  const updateEncryption = async (lid, enc) => {
    await api(`${API}/c2/listeners/${lid}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ encryption_type: enc }) })
    load()
  }

  const saveTemplate = async () => {
    await api(`${API}/c2/payload-templates`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(tmplForm) })
    setTmplForm({ name: '', payload_type: 'python', content: '' }); load()
  }

  const deleteTemplate = async (tid) => {
    if (!confirm('确定删除？')) return
    await api(`${API}/c2/payload-templates/${tid}`, { method: 'DELETE' }); load()
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 20, alignItems: 'center' }}>
        <h1 style={{ fontSize: 28, fontWeight: 700 }}>C2 面板</h1>
        <div style={{ display: 'flex', gap: 4 }}>
          {['listeners', 'templates'].map(t => (
            <button key={t} onClick={() => setTab(t)}
              style={{ ...btnStyle, background: tab === t ? 'var(--accent)' : 'var(--bg-hover)', padding: '6px 14px', fontSize: 12 }}>{t === 'listeners' ? '监听器' : 'Payload 模板'}</button>
          ))}
        </div>
      </div>

      {tab === 'listeners' && <>
        <Card title="新建监听器">
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <input placeholder="名称" value={name} onChange={e => setName(e.target.value)} style={inputStyle} />
            <select value={ltype} onChange={e => setLtype(e.target.value)} style={{ ...inputStyle, width: 110 }}>
              <option value="tcp">TCP</option><option value="http">HTTP</option><option value="ws">WebSocket</option>
            </select>
            <input placeholder="Host" value={host} onChange={e => setHost(e.target.value)} style={{ ...inputStyle, width: 130 }} />
            <input placeholder="Port" value={port} onChange={e => setPort(e.target.value)} style={{ ...inputStyle, width: 90 }} />
            <select value={encType} onChange={e => setEncType(e.target.value)} style={{ ...inputStyle, width: 130 }}>
              <option value="aes-256-ctr">AES-256-CTR</option><option value="xor">XOR</option>
            </select>
            <button onClick={createListener} style={{ ...btnStyle, background: 'var(--success)' }}>➕ 创建</button>
          </div>
        </Card>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginTop: 16 }}>
          <Card title={`监听器 (${listeners.length})`}>
            {listeners.map(l => (
              <div key={l.id} style={{ background: 'var(--bg-hover)', borderRadius: 'var(--radius-sm)', padding: 12, marginBottom: 8, fontSize: 13 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span><b>{l.name}</b> ({l.listener_type})</span>
                  <span style={{ color: l.status === 'running' ? 'var(--success)' : 'var(--text-dim)' }}>{l.status}</span>
                </div>
                <div style={{ color: 'var(--text-dim)', fontSize: 12 }}>{l.host}:{l.port} | 加密: {l.encryption_type || 'aes-256-ctr'}</div>
                <div style={{ marginTop: 6, display: 'flex', gap: 6, alignItems: 'center' }}>
                  {l.status === 'stopped' ? (
                    <button onClick={() => toggleListener(l.id, 'start')} style={{ ...btnStyle, background: 'var(--info)', padding: '2px 10px', fontSize: 12 }}>▶ 启动</button>
                  ) : (
                    <button onClick={() => toggleListener(l.id, 'stop')} style={{ ...btnStyle, background: 'var(--error)', padding: '2px 10px', fontSize: 12 }}>⏹ 停止</button>
                  )}
                  <select value={l.encryption_type || 'aes-256-ctr'} onChange={e => updateEncryption(l.id, e.target.value)} style={{ ...inputStyle, width: 110, fontSize: 11, padding: '2px 6px' }}>
                    <option value="aes-256-ctr">AES-256-CTR</option><option value="xor">XOR</option>
                  </select>
                </div>
              </div>
            ))}
            {listeners.length === 0 && <div style={{ color: 'var(--text-dim)', fontSize: 13 }}>暂无监听器</div>}
          </Card>
          <Card title={`会话 (${sessions.length})`}>
            {sessions.map(s => (
              <div key={s.id} style={{ background: 'var(--bg-hover)', borderRadius: 'var(--radius-sm)', padding: 12, marginBottom: 8, fontSize: 13 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span>{s.remote_addr}</span>
                  <span style={{ color: s.status === 'active' ? 'var(--success)' : 'var(--text-dim)' }}>{s.status}</span>
                </div>
                <div style={{ color: 'var(--text-dim)', fontSize: 12 }}>{s.hostname} | {s.username} | {s.os_info}</div>
                <div style={{ color: 'var(--text-dim)', fontSize: 11 }}>{s.last_seen}</div>
              </div>
            ))}
            {sessions.length === 0 && <div style={{ color: 'var(--text-dim)', fontSize: 13 }}>暂无会话</div>}
          </Card>
        </div>
      </>}

      {tab === 'templates' && <>
        <Card title="新建 Payload 模板">
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <input placeholder="模板名称" value={tmplForm.name} onChange={e => setTmplForm({ ...tmplForm, name: e.target.value })} style={inputStyle} />
            <select value={tmplForm.payload_type} onChange={e => setTmplForm({ ...tmplForm, payload_type: e.target.value })} style={{ ...inputStyle, width: 120 }}>
              <option value="python">Python</option><option value="powershell">PowerShell</option><option value="bash">Bash</option><option value="http">HTTP Beacon</option><option value="ws">WebSocket</option>
            </select>
            <textarea placeholder="代码内容（支持 {host} {port} {secret} 占位符）" value={tmplForm.content}
              onChange={e => setTmplForm({ ...tmplForm, content: e.target.value })}
              style={{ ...inputStyle, width: '100%', minHeight: 100, fontFamily: 'monospace', fontSize: 12 }} />
            <button onClick={saveTemplate} style={{ ...btnStyle, background: 'var(--success)' }}>保存</button>
          </div>
        </Card>
        <Card title={`Payload 模板 (${templates.length})`} style={{ marginTop: 16 }}>
          {templates.map(t => (
            <div key={t.id} style={{ background: 'var(--bg-hover)', borderRadius: 'var(--radius-sm)', padding: 12, marginBottom: 8, fontSize: 13 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span><b>{t.name}</b> ({t.payload_type})</span>
                <button onClick={() => deleteTemplate(t.id)} style={{ ...btnStyle, background: 'var(--error)', padding: '2px 10px', fontSize: 12 }}>删除</button>
              </div>
            </div>
          ))}
          {templates.length === 0 && <div style={{ color: 'var(--text-dim)', fontSize: 13 }}>暂无模板</div>}
        </Card>
      </>}
    </div>
  )
}

// ── InteractiveTerminal ──
function InteractiveTerminal({ webshellId, protocol }) {
  const [history, setHistory] = useState([]); const [cmdIndex, setCmdIndex] = useState(-1)
  const [cmdBuf, setCmdBuf] = useState(''); const [output, setOutput] = useState([])
  const [loading, setLoading] = useState(false); const ref = useRef(null); const inputRef = useRef(null)
  const cmdHistory = useRef([]); const histIdx = useRef(-1)

  const exec = useCallback(async (c) => {
    if (!c.trim() || !webshellId) return
    setLoading(true)
    setOutput(prev => [...prev, { text: `$ ${c}`, type: 'input' }])
    cmdHistory.current.push(c); histIdx.current = cmdHistory.current.length

    if (c.trim() === 'clear') { setOutput([]); setLoading(false); return }

    try {
      const r = await api(`${API}/webshell/${webshellId}/exec?command=${encodeURIComponent(c)}`, { method: 'POST' }).then(r => r.json())
      const out = r.output || r.error || '无输出'
      setOutput(prev => [...prev, { text: out, type: 'output' }])
    } catch (e) {
      setOutput(prev => [...prev, { text: `[错误] ${e.message}`, type: 'error' }])
    }
    setLoading(false)
  }, [webshellId])

  const onKeyDown = (e) => {
    if (e.key === 'Enter') {
      exec(cmdBuf); setCmdBuf('')
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      if (cmdHistory.current.length > 0) {
        histIdx.current = Math.max(0, histIdx.current - 1)
        setCmdBuf(cmdHistory.current[histIdx.current])
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault()
      if (histIdx.current < cmdHistory.current.length - 1) {
        histIdx.current += 1
        setCmdBuf(cmdHistory.current[histIdx.current])
      } else {
        histIdx.current = cmdHistory.current.length
        setCmdBuf('')
      }
    } else if (e.key === 'c' && e.ctrlKey) {
      setOutput(prev => [...prev, { text: '^C', type: 'info' }])
      setCmdBuf('')
    }
  }

  useEffect(() => { if (ref.current) ref.current.scrollTop = ref.current.scrollHeight }, [output])

  const quickCmds = ['whoami', 'id', 'ls', 'pwd', 'uname -a', 'ipconfig']
  return (
    <div>
      <div ref={ref} style={{
        background: '#000', borderRadius: 'var(--radius)', padding: 12, fontFamily: 'monospace',
        fontSize: 13, height: 350, overflow: 'auto', whiteSpace: 'pre-wrap', lineHeight: 1.6, marginBottom: 8,
      }}>
        {output.length === 0 && <span style={{ color: '#666' }}>等待命令...</span>}
        {output.map((l, i) => (
          <div key={i} style={{
            color: l.type === 'input' ? '#22c55e' : l.type === 'error' ? '#ef4444' : l.type === 'info' ? '#f59e0b' : '#e0e0e0',
          }}>{l.text}</div>
        ))}
        {loading && <div style={{ color: '#666' }}>执行中...</div>}
      </div>
      <div style={{ display: 'flex', gap: 6, marginBottom: 8, flexWrap: 'wrap' }}>
        {quickCmds.map(c => (
          <button key={c} onClick={() => { setCmdBuf(c); exec(c) }}
            style={{ ...btnStyle, background: '#1a1a1a', color: '#22c55e', padding: '3px 10px', fontSize: 11, border: '1px solid #333' }}>{c}</button>
        ))}
      </div>
      <div style={{ display: 'flex', gap: 8 }}>
        <span style={{ color: '#22c55e', fontFamily: 'monospace', fontSize: 14, lineHeight: '34px' }}>$</span>
        <input ref={inputRef} value={cmdBuf} onChange={e => setCmdBuf(e.target.value)} onKeyDown={onKeyDown}
          placeholder="输入命令..." style={{
            ...inputStyle, flex: 1, fontFamily: 'monospace', fontSize: 13,
          }} />
      </div>
    </div>
  )
}

// ── WebShell Panel ──
function WebShellPanel() {
  const [shells, setShells] = useState([]); const [selectedId, setSelectedId] = useState(null)
  const [form, setForm] = useState({ name: '', url: '', password: '', shell_type: 'php', protocol: 'antsword' })
  const [fileTab, setFileTab] = useState(false); const [files, setFiles] = useState([])
  const [filePath, setFilePath] = useState('/'); const [fileOutput, setFileOutput] = useState('')
  const [testResult, setTestResult] = useState(null)
  const [testingId, setTestingId] = useState(null)

  const load = async () => { const d = await api(`${API}/webshell`).then(r => r.json()); setShells(d.webshells || []) }
  useEffect(() => { load() }, [])

  const createWs = async () => {
    await api(`${API}/webshell`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(form) })
    setForm({ name: '', url: '', password: '', shell_type: 'php', protocol: 'antsword' }); load()
  }

  const testWs = async (wid) => {
    setTestingId(wid); setTestResult(null)
    try {
      const r = await api(`${API}/webshell/${wid}/test`, { method: 'POST' }).then(r => r.json())
      setTestResult(r)
    } catch (e) {
      setTestResult({ ok: false, error: e.message })
    }
    setTestingId(null)
    setTimeout(() => setTestResult(null), 3000)
  }

  const deleteWs = async (wid) => {
    if (!confirm('确定删除此 WebShell？')) return
    await api(`${API}/webshell/${wid}`, { method: 'DELETE' })
    if (selectedId === wid) { setSelectedId(null) }
    load()
  }

  const loadFiles = async () => {
    if (!selectedId) return
    const r = await api(`${API}/webshell/${selectedId}/files/list?path=${encodeURIComponent(filePath)}`, { method: 'POST' }).then(r => r.json())
    if (r.success) {
      setFiles(r.output ? r.output.split('\n').filter(l => l.trim()).map(l => ({ name: l, isDir: l.endsWith('/') })) : [])
    }
  }

  const readFile = async (path) => {
    if (!selectedId) return
    const r = await api(`${API}/webshell/${selectedId}/files/read?path=${encodeURIComponent(path)}`, { method: 'POST' }).then(r => r.json())
    setFileOutput(r.output || r.error || '')
  }

  const selectedWs = shells.find(s => s.id === selectedId)

  return (
    <div>
      <h1 style={{ fontSize: 28, fontWeight: 700, marginBottom: 20 }}>WebShell 管理</h1>
      <Card title="添加 WebShell">
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <input placeholder="名称" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} style={inputStyle} />
          <input placeholder="URL" value={form.url} onChange={e => setForm({ ...form, url: e.target.value })} style={{ ...inputStyle, flex: 1 }} />
          <input placeholder="密码" value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} style={{ ...inputStyle, width: 110 }} />
          <select value={form.shell_type} onChange={e => setForm({ ...form, shell_type: e.target.value })} style={{ ...inputStyle, width: 90 }}>
            <option value="php">PHP</option><option value="asp">ASP</option><option value="aspx">ASPX</option><option value="jsp">JSP</option>
          </select>
          <select value={form.protocol} onChange={e => setForm({ ...form, protocol: e.target.value })} style={{ ...inputStyle, width: 120 }}>
            <option value="antsword">蚁剑 (AntSword)</option>
            <option value="behinder">冰蝎 (Behinder)</option>
            <option value="godzilla">哥斯拉 (Godzilla)</option>
          </select>
          <button onClick={createWs} style={{ ...btnStyle, background: 'var(--success)' }}>➕ 添加</button>
        </div>
      </Card>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginTop: 16 }}>
        <div>
          <div style={{ display: 'flex', gap: 4, marginBottom: 8 }}>
            {['terminal', 'files'].map(t => (
              <button key={t} onClick={() => { setFileTab(t === 'files'); if (t === 'files') loadFiles() }}
                style={{ ...btnStyle, background: (fileTab === (t === 'files')) ? 'var(--accent)' : 'var(--bg-hover)', padding: '6px 14px', fontSize: 12 }}>{t === 'terminal' ? '终端' : '文件管理'}</button>
            ))}
          </div>
          <Card title={`WebShell (${shells.length})`}>
            {shells.map(ws => (
              <div key={ws.id} onClick={() => { setSelectedId(ws.id); setFileTab(false) }}
                style={{
                  background: selectedId === ws.id ? 'var(--accent-light)' : 'var(--bg-hover)',
                  borderRadius: 'var(--radius-sm)', padding: 10, marginBottom: 6, fontSize: 13, cursor: 'pointer',
                  border: selectedId === ws.id ? '1px solid var(--accent)' : '1px solid transparent',
                }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ flex: 1 }}>
                    <div><b>{ws.name}</b> ({ws.shell_type}) <span style={{ fontSize: 11, color: 'var(--text-dim)' }}>{ws.protocol || 'antsword'}</span></div>
                    <div style={{ color: 'var(--text-dim)', fontSize: 12 }}>{ws.url}</div>
                  </div>
                  <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                    <button onClick={(e) => { e.stopPropagation(); testWs(ws.id) }} disabled={testingId === ws.id}
                      style={{ ...btnStyle, background: 'var(--info)', padding: '4px 10px', fontSize: 11 }}>
                      {testingId === ws.id ? '测试中...' : '测试'}
                    </button>
                    <button onClick={(e) => { e.stopPropagation(); deleteWs(ws.id) }}
                      style={{ ...btnStyle, background: 'var(--error)', padding: '4px 10px', fontSize: 11 }}>删除</button>
                  </div>
                </div>
                {testResult && testingId === null && (
                  <div style={{
                    marginTop: 6, padding: '4px 8px', borderRadius: 4, fontSize: 11,
                    background: testResult.ok ? '#064e3b' : '#7f1d1d',
                    color: testResult.ok ? '#6ee7b7' : '#fca5a5',
                  }}>
                    {testResult.ok
                      ? `连接成功 | 用户: ${testResult.user || '?'}`
                      : `连接失败: ${testResult.error || '未知错误'}`}
                  </div>
                )}
              </div>
            ))}
            {shells.length === 0 && <div style={{ color: 'var(--text-dim)', fontSize: 13 }}>暂无 WebShell</div>}
          </Card>
        </div>
        <Card title={!selectedId ? '选择 WebShell' : fileTab ? '文件管理器' : '终端'}>
          {!selectedId && <div style={{ color: 'var(--text-dim)', fontSize: 13 }}>请选择一个 WebShell</div>}
          {selectedId && fileTab && (
            <div>
              <div style={{ display: 'flex', gap: 6, marginBottom: 8, alignItems: 'center' }}>
                <input value={filePath} onChange={e => setFilePath(e.target.value)} style={{ ...inputStyle, flex: 1, fontSize: 12 }} />
                <button onClick={loadFiles} style={{ ...btnStyle, background: 'var(--info)', padding: '4px 10px', fontSize: 11 }}>列目录</button>
              </div>
              <div style={{ background: '#000', borderRadius: 'var(--radius-sm)', padding: 8, fontSize: 12, fontFamily: 'monospace', maxHeight: 300, overflow: 'auto', marginBottom: 8 }}>
                {fileOutput ? <pre style={{ color: '#22c55e', margin: 0 }}>{fileOutput}</pre> :
                  files.map((f, i) => <div key={i} style={{ color: f.isDir ? '#3b82f6' : '#e0e0e0', cursor: 'pointer' }}
                    onClick={() => { if (f.isDir) { setFilePath(f.name); loadFiles() } else { readFile(f.name) } }}>{f.name}</div>)}
                {files.length === 0 && fileOutput === '' && <span style={{ color: '#666' }}>点击列目录</span>}
              </div>
            </div>
          )}
          {selectedId && !fileTab && <InteractiveTerminal webshellId={selectedId} protocol={selectedWs?.protocol} />}
        </Card>
      </div>
    </div>
  )
}

// ── Vulnerabilities ──
function Vulnerabilities() {
  const [vulns, setVulns] = useState([]); const [stats, setStats] = useState(null)
  const [filter, setFilter] = useState({ severity: '', status: '' })
  const [showForm, setShowForm] = useState(false); const [form, setForm] = useState({ title: '', target: '', vuln_type: '', severity: 'medium', status: 'open', description: '', evidence: '', source: '' })

  const load = async () => {
    const params = new URLSearchParams()
    if (filter.severity) params.set('severity', filter.severity)
    if (filter.status) params.set('status', filter.status)
    const d = await api(`${API}/vulnerabilities?${params}`).then(r => r.json())
    setVulns(d.vulnerabilities || [])
    api(`${API}/vulnerabilities/stats`).then(r => r.json()).then(setStats)
  }
  useEffect(() => { load() }, [filter])

  const save = async () => {
    await api(`${API}/vulnerabilities`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(form) })
    setForm({ title: '', target: '', vuln_type: '', severity: 'medium', status: 'open', description: '', evidence: '', source: '' })
    setShowForm(false); load()
  }

  const updateStatus = async (vid, status) => {
    await api(`${API}/vulnerabilities/${vid}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ status }) })
    load()
  }

  const del = async (vid) => { if (confirm('确定删除？')) { await api(`${API}/vulnerabilities/${vid}`, { method: 'DELETE' }); load() } }

  const severityColor = (s) => ({ critical: 'var(--error)', high: '#f97316', medium: 'var(--warning)', low: 'var(--info)', info: 'var(--text-dim)' })[s] || 'var(--text-dim)'
  const statusColor = (s) => ({ open: 'var(--error)', confirmed: '#f97316', fixed: 'var(--success)', false_positive: 'var(--text-dim)' })[s] || 'var(--text-dim)'

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <h1 style={{ fontSize: 28, fontWeight: 700 }}>漏洞管理</h1>
        <button onClick={() => setShowForm(!showForm)} style={{ ...btnStyle, background: 'var(--accent)' }}>{showForm ? '取消' : '➕ 新建'}</button>
      </div>

      {stats && <div style={{ display: 'flex', gap: 12, marginBottom: 16, flexWrap: 'wrap' }}>
        <MiniStat label="总数" value={stats.total} color="var(--accent)" />
        {Object.entries(stats.by_severity || {}).map(([k, v]) => <MiniStat key={k} label={k} value={v} color={severityColor(k)} />)}
      </div>}

      {showForm && <Card title="新建漏洞" style={{ marginBottom: 16 }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <input placeholder="标题" value={form.title} onChange={e => setForm({ ...form, title: e.target.value })} style={inputStyle} />
            <input placeholder="目标" value={form.target} onChange={e => setForm({ ...form, target: e.target.value })} style={inputStyle} />
            <select value={form.severity} onChange={e => setForm({ ...form, severity: e.target.value })} style={inputStyle}>
              <option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="info">Info</option>
            </select>
            <select value={form.status} onChange={e => setForm({ ...form, status: e.target.value })} style={inputStyle}>
              <option value="open">Open</option><option value="confirmed">Confirmed</option><option value="fixed">Fixed</option><option value="false_positive">False Positive</option>
            </select>
          </div>
          <textarea placeholder="描述" value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} style={{ ...inputStyle, width: '100%', minHeight: 60 }} />
          <textarea placeholder="证据" value={form.evidence} onChange={e => setForm({ ...form, evidence: e.target.value })} style={{ ...inputStyle, width: '100%', minHeight: 60 }} />
          <button onClick={save} style={{ ...btnStyle, background: 'var(--success)', width: 100 }}>保存</button>
        </div>
      </Card>}

      <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
        <select value={filter.severity} onChange={e => setFilter({ ...filter, severity: e.target.value })} style={{ ...inputStyle, width: 120 }}>
          <option value="">全部严重度</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
        </select>
        <select value={filter.status} onChange={e => setFilter({ ...filter, status: e.target.value })} style={{ ...inputStyle, width: 120 }}>
          <option value="">全部状态</option><option value="open">Open</option><option value="confirmed">Confirmed</option><option value="fixed">Fixed</option>
        </select>
      </div>

      <Card>
        {vulns.map(v => (
          <div key={v.id} style={{ background: 'var(--bg-hover)', borderRadius: 'var(--radius-sm)', padding: 12, marginBottom: 8, fontSize: 13 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <b>{v.title}</b>
                  <span style={{ fontSize: 11, padding: '1px 8px', borderRadius: 10, background: severityColor(v.severity) + '22', color: severityColor(v.severity), fontWeight: 600 }}>{v.severity}</span>
                  <span style={{ fontSize: 11, padding: '1px 8px', borderRadius: 10, background: statusColor(v.status) + '22', color: statusColor(v.status) }}>{v.status}</span>
                </div>
                <div style={{ color: 'var(--text-dim)', fontSize: 12, marginTop: 2 }}>{v.target} | {v.vuln_type} | {v.source}</div>
              </div>
              <div style={{ display: 'flex', gap: 4 }}>
                <select value={v.status} onChange={e => updateStatus(v.id, e.target.value)} style={{ ...inputStyle, width: 100, fontSize: 11, padding: '2px 6px' }}>
                  <option value="open">Open</option><option value="confirmed">Confirmed</option><option value="fixed">Fixed</option><option value="false_positive">FP</option>
                </select>
                <button onClick={() => del(v.id)} style={{ ...btnStyle, background: 'var(--error)', padding: '2px 8px', fontSize: 11 }}>×</button>
              </div>
            </div>
            {v.description && <div style={{ color: 'var(--text-dim)', fontSize: 12, marginTop: 4 }}>{v.description}</div>}
          </div>
        ))}
        {vulns.length === 0 && <div style={{ color: 'var(--text-dim)', fontSize: 13 }}>暂无漏洞</div>}
      </Card>
    </div>
  )
}

function MiniStat({ label, value, color }) {
  return <div style={{ background: 'var(--bg-card)', borderRadius: 'var(--radius)', padding: '8px 16px', border: '1px solid var(--border)', textAlign: 'center' }}>
    <div style={{ fontSize: 20, fontWeight: 700, color }}>{value}</div>
    <div style={{ fontSize: 11, color: 'var(--text-dim)', textTransform: 'capitalize' }}>{label}</div>
  </div>
}

// ── YAML Tools ──
function YamlTools() {
  const [tools, setTools] = useState([]); const [form, setForm] = useState({ name: '', description: '', category: 'custom', tool_type: 'subprocess', command: '', parameters: '{}', timeout: 60 })
  const [editId, setEditId] = useState(null); const [testOutput, setTestOutput] = useState({})

  const load = async () => { const d = await api(`${API}/yaml-tools`).then(r => r.json()); setTools(d.tools || []) }
  useEffect(() => { load() }, [])

  const save = async () => {
    if (!form.name || !form.command) return
    try { JSON.parse(form.parameters) } catch { alert('parameters 必须是合法 JSON'); return }
    if (editId) {
      await api(`${API}/yaml-tools/${editId}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(form) })
    } else {
      await api(`${API}/yaml-tools`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(form) })
    }
    setForm({ name: '', description: '', category: 'custom', tool_type: 'subprocess', command: '', parameters: '{}', timeout: 60 })
    setEditId(null); load()
  }

  const edit = (t) => {
    setForm({ name: t.name, description: t.description, category: t.category, tool_type: t.tool_type, command: t.command, parameters: t.parameters, timeout: t.timeout })
    setEditId(t.id)
  }

  const del = async (tid) => { if (!confirm('确定删除？')) return; await api(`${API}/yaml-tools/${tid}`, { method: 'DELETE' }); load() }
  const reloadTools = async () => { const r = await api(`${API}/yaml-tools/reload`, { method: 'POST' }).then(r => r.json()); alert(`已加载 ${r.count} 个工具`); load() }

  const testTool = async (tid) => {
    const r = await api(`${API}/yaml-tools/${tid}/test`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ args: {} }) }).then(r => r.json())
    setTestOutput({ ...testOutput, [tid]: r })
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <h1 style={{ fontSize: 28, fontWeight: 700 }}>自定义工具</h1>
        <button onClick={reloadTools} style={{ ...btnStyle, background: 'var(--info)', fontSize: 12 }}>重载到 Agent</button>
      </div>

      <Card title={editId ? '编辑工具' : '新建工具'}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <input placeholder="工具名称" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} style={inputStyle} />
            <input placeholder="描述" value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} style={{ ...inputStyle, flex: 1 }} />
            <select value={form.tool_type} onChange={e => setForm({ ...form, tool_type: e.target.value })} style={{ ...inputStyle, width: 110 }}>
              <option value="subprocess">子进程</option><option value="api">API</option>
            </select>
            <input placeholder="超时秒数" type="number" value={form.timeout} onChange={e => setForm({ ...form, timeout: parseInt(e.target.value) || 60 })} style={{ ...inputStyle, width: 80 }} />
          </div>
          <input placeholder='命令 (如: ["nmap", "-sV", "{target}"])' value={form.command}
            onChange={e => setForm({ ...form, command: e.target.value })} style={inputStyle} />
          <textarea placeholder='参数 JSON (如: {"target":{"type":"string","description":"IP"}})' value={form.parameters}
            onChange={e => setForm({ ...form, parameters: e.target.value })}
            style={{ ...inputStyle, width: '100%', minHeight: 80, fontFamily: 'monospace', fontSize: 12 }} />
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={save} style={{ ...btnStyle, background: 'var(--success)' }}>{editId ? '保存' : '创建'}</button>
            {editId && <button onClick={() => { setForm({ name: '', description: '', category: 'custom', tool_type: 'subprocess', command: '', parameters: '{}', timeout: 60 }); setEditId(null) }} style={{ ...btnStyle, background: 'var(--bg-hover)', color: 'var(--text-dim)' }}>取消</button>}
          </div>
        </div>
      </Card>

      <Card title={`工具列表 (${tools.length})`} style={{ marginTop: 16 }}>
        {tools.map(t => (
          <div key={t.id} style={{ background: 'var(--bg-hover)', borderRadius: 'var(--radius-sm)', padding: 12, marginBottom: 8, fontSize: 13 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ flex: 1 }}>
                <div><b>{t.name}</b> <span style={{ color: 'var(--text-dim)', fontSize: 11 }}>({t.tool_type})</span>
                  <span style={{ fontSize: 11, marginLeft: 8, color: t.loaded ? 'var(--success)' : 'var(--warning)' }}>{t.loaded ? '● 已加载' : '○ 未加载'}</span>
                </div>
                <div style={{ color: 'var(--text-dim)', fontSize: 12 }}>{t.description}</div>
              </div>
              <div style={{ display: 'flex', gap: 4 }}>
                <button onClick={() => testTool(t.id)} style={{ ...btnStyle, background: 'var(--info)', padding: '2px 10px', fontSize: 11 }}>测试</button>
                <button onClick={() => edit(t)} style={{ ...btnStyle, background: 'var(--warning)', padding: '2px 10px', fontSize: 11 }}>编辑</button>
                <button onClick={() => del(t.id)} style={{ ...btnStyle, background: 'var(--error)', padding: '2px 10px', fontSize: 11 }}>删除</button>
              </div>
            </div>
            {testOutput[t.id] && (
              <div style={{ marginTop: 6, padding: 6, background: '#000', borderRadius: 4, fontSize: 11, fontFamily: 'monospace', color: testOutput[t.id].success ? '#22c55e' : '#ef4444' }}>
                {testOutput[t.id].output || testOutput[t.id].error}
              </div>
            )}
          </div>
        ))}
        {tools.length === 0 && <div style={{ color: 'var(--text-dim)', fontSize: 13 }}>暂无自定义工具</div>}
      </Card>
    </div>
  )
}

// ── Tasks ──
function Tasks() {
  const [tasks, setTasks] = useState([]); const [name, setName] = useState(''); const [target, setTarget] = useState('')
  const [report, setReport] = useState(null); const [reportTaskId, setReportTaskId] = useState(null)

  const load = async () => { const d = await api(`${API}/tasks`).then(r => r.json()); setTasks(d.tasks || []) }
  useEffect(() => { load() }, [])

  const createTask = async () => { await api(`${API}/tasks`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name, target }) }); setName(''); setTarget(''); load() }

  const genReport = async (tid) => {
    setReportTaskId(tid)
    const r = await api(`${API}/tasks/${tid}/report`, { method: 'POST' }).then(r => r.json())
    setReport(r)
  }

  return (
    <div>
      <h1 style={{ fontSize: 28, fontWeight: 700, marginBottom: 20 }}>任务管理</h1>
      <Card title="新建任务">
        <div style={{ display: 'flex', gap: 8 }}>
          <input placeholder="任务名称" value={name} onChange={e => setName(e.target.value)} style={inputStyle} />
          <input placeholder="目标" value={target} onChange={e => setTarget(e.target.value)} style={{ ...inputStyle, flex: 1 }} />
          <button onClick={createTask} style={{ ...btnStyle, background: 'var(--success)' }}>创建</button>
        </div>
      </Card>
      <Card title={`任务列表 (${tasks.length})`} style={{ marginTop: 16 }}>
        {tasks.map(t => (
          <div key={t.id} style={{ background: 'var(--bg-hover)', borderRadius: 'var(--radius-sm)', padding: 12, marginBottom: 8, fontSize: 13 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <b>{t.name}</b> → {t.target}
                <span style={{ marginLeft: 8, fontSize: 12, color: t.status === 'completed' ? 'var(--success)' : t.status === 'failed' ? 'var(--error)' : 'var(--warning)' }}>{t.status}</span>
              </div>
              <button onClick={() => genReport(t.id)} style={{ ...btnStyle, background: 'var(--info)', padding: '4px 10px', fontSize: 11 }}>生成报告</button>
            </div>
          </div>
        ))}
        {tasks.length === 0 && <div style={{ color: 'var(--text-dim)', fontSize: 13 }}>暂无任务</div>}
      </Card>

      {report && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.7)', zIndex: 1000, display: 'flex', justifyContent: 'center', alignItems: 'center', padding: 40 }}
          onClick={() => setReport(null)}>
          <div onClick={e => e.stopPropagation()} style={{ background: 'var(--bg-card)', borderRadius: 'var(--radius)', maxWidth: 700, width: '100%', maxHeight: '80vh', overflow: 'auto', padding: 24 }}>
            <h2 style={{ fontSize: 18, marginBottom: 12 }}>报告预览</h2>
            <pre style={{ whiteSpace: 'pre-wrap', fontSize: 12, fontFamily: 'monospace', color: 'var(--text)', lineHeight: 1.6 }}>{report.markdown?.content || report.html?.content}</pre>
          </div>
        </div>
      )}
    </div>
  )
}

// ── MCP Config ──
function McpConfig() {
  const [servers, setServers] = useState([])
  const [form, setForm] = useState({ name: '', base_url: '', server_type: 'mcp', api_key: '', description: '', command: '', args: '' })
  const [editId, setEditId] = useState(null); const [testing, setTesting] = useState({}); const [testResults, setTestResults] = useState({})

  const load = async () => { const d = await api(`${API}/mcp/servers`).then(r => r.json()); setServers(d.servers || []) }
  useEffect(() => { load() }, [])

  const save = async () => {
    if (!form.name || (!form.base_url && form.server_type !== 'stdio')) return
    if (editId) {
      const body = { ...form }; if (!body.api_key) body.api_key = undefined
      await api(`${API}/mcp/servers/${editId}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
    } else {
      const body = { ...form }
      if (form.server_type === 'stdio') {
        body.base_url = `stdio://${form.command || 'unknown'}`
      }
      await api(`${API}/mcp/servers`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
    }
    setForm({ name: '', base_url: '', server_type: 'mcp', api_key: '', description: '', command: '', args: '' })
    setEditId(null); load()
  }

  const edit = (s) => {
    setForm({ name: s.name, base_url: s.base_url, server_type: s.server_type, api_key: '', description: s.description || '', command: s.command || '', args: s.args || '' })
    setEditId(s.id)
  }

  const del = async (sid) => { if (!confirm('确定删除？')) return; await api(`${API}/mcp/servers/${sid}`, { method: 'DELETE' }); load() }

  const testServer = async (sid) => {
    setTesting(prev => ({ ...prev, [sid]: true })); setTestResults(prev => ({ ...prev, [sid]: null }))
    try { const r = await api(`${API}/mcp/servers/${sid}/test`, { method: 'POST' }).then(r => r.json()); setTestResults(prev => ({ ...prev, [sid]: r })) }
    catch (e) { setTestResults(prev => ({ ...prev, [sid]: { status: 'error', error: e.message } })) }
    setTesting(prev => ({ ...prev, [sid]: false }))
  }

  return (
    <div>
      <h1 style={{ fontSize: 28, fontWeight: 700, marginBottom: 20 }}>MCP 服务器配置</h1>
      <Card title={editId ? '编辑 MCP 服务器' : '添加 MCP 服务器'}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <input placeholder="名称" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} style={{ ...inputStyle, width: 130 }} />
            <select value={form.server_type} onChange={e => setForm({ ...form, server_type: e.target.value })} style={{ ...inputStyle, width: 100 }}>
              <option value="mcp">HTTP MCP</option><option value="stdio">Stdio 进程</option><option value="openai">OpenAI</option>
            </select>
            {form.server_type === 'stdio' ? <>
              <input placeholder="命令 (如: tshark)" value={form.command} onChange={e => setForm({ ...form, command: e.target.value })} style={{ ...inputStyle, flex: 1 }} />
              <input placeholder="参数 (空格分隔)" value={form.args} onChange={e => setForm({ ...form, args: e.target.value })} style={{ ...inputStyle, flex: 1 }} />
            </> : <>
              <input placeholder="基础 URL" value={form.base_url} onChange={e => setForm({ ...form, base_url: e.target.value })} style={{ ...inputStyle, flex: 1 }} />
              <input placeholder="API Key" value={form.api_key} onChange={e => setForm({ ...form, api_key: e.target.value })} style={{ ...inputStyle, width: 160 }} />
            </>}
            <input placeholder="描述" value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} style={{ ...inputStyle, width: 150 }} />
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={save} style={{ ...btnStyle, background: 'var(--success)' }}>{editId ? '保存' : '添加'}</button>
            {editId && <button onClick={() => { setForm({ name: '', base_url: '', server_type: 'mcp', api_key: '', description: '', command: '', args: '' }); setEditId(null) }} style={{ ...btnStyle, background: 'var(--bg-hover)', color: 'var(--text-dim)' }}>取消</button>}
          </div>
        </div>
      </Card>

      <Card title={`MCP 服务器 (${servers.length})`} style={{ marginTop: 16 }}>
        {servers.map(s => (
          <div key={s.id} style={{ background: 'var(--bg-hover)', borderRadius: 'var(--radius-sm)', padding: 12, marginBottom: 8, fontSize: 13 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ flex: 1 }}>
                <div><b>{s.name}</b> <span style={{ color: 'var(--text-dim)', fontSize: 11 }}>({s.server_type})</span></div>
                <div style={{ color: 'var(--text-dim)', fontSize: 12 }}>{s.server_type === 'stdio' ? `${s.command || ''} ${s.args || ''}` : s.base_url}</div>
              </div>
              <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                <span style={{ color: s.enabled ? 'var(--success)' : 'var(--text-dim)', fontSize: 11 }}>{s.enabled ? '启用' : '禁用'}</span>
                <button onClick={() => testServer(s.id)} disabled={testing[s.id]} style={{ ...btnStyle, background: 'var(--info)', padding: '4px 10px', fontSize: 11 }}>{testing[s.id] ? '测试中' : '测试'}</button>
                <button onClick={() => edit(s)} style={{ ...btnStyle, background: 'var(--warning)', padding: '4px 10px', fontSize: 11 }}>编辑</button>
                <button onClick={() => del(s.id)} style={{ ...btnStyle, background: 'var(--error)', padding: '4px 10px', fontSize: 11 }}>删除</button>
              </div>
            </div>
            {testResults[s.id] && (
              <div style={{ marginTop: 6, padding: '4px 8px', borderRadius: 4, fontSize: 11, background: testResults[s.id].status === 'connected' ? '#064e3b' : '#7f1d1d', color: testResults[s.id].status === 'connected' ? '#6ee7b7' : '#fca5a5' }}>
                {testResults[s.id].status === 'connected' ? `连接成功` : `连接失败: ${testResults[s.id].status || testResults[s.id].error || 'error'}`}
              </div>
            )}
          </div>
        ))}
        {servers.length === 0 && <div style={{ color: 'var(--text-dim)', fontSize: 13 }}>暂无 MCP 服务器</div>}
      </Card>
    </div>
  )
}

// ── Roles ──
function Roles() {
  const [roles, setRoles] = useState([]); const [form, setForm] = useState({ name: '', description: '', role_type: 'custom', system_prompt: '', skills: '' })
  const [editId, setEditId] = useState(null); const [expanded, setExpanded] = useState({})

  const load = async () => { const d = await api(`${API}/roles`).then(r => r.json()); setRoles(d.roles || []) }
  useEffect(() => { load() }, [])

  const save = async () => {
    if (!form.name) return
    if (editId) { await api(`${API}/roles/${editId}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(form) }) }
    else { await api(`${API}/roles`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(form) }) }
    setForm({ name: '', description: '', role_type: 'custom', system_prompt: '', skills: '' }); setEditId(null); load()
  }

  const edit = (r) => { setForm({ name: r.name, description: r.description || '', role_type: r.role_type, system_prompt: r.system_prompt || '', skills: r.skills || '' }); setEditId(r.id) }
  const del = async (rid) => { if (!confirm('确定删除？')) return; try { const resp = await api(`${API}/roles/${rid}`, { method: 'DELETE' }); if (!resp.ok) { const err = await resp.json(); alert(err.detail || '删除失败'); return }; load() } catch (e) { alert('删除失败: ' + e.message) } }

  return (
    <div>
      <h1 style={{ fontSize: 28, fontWeight: 700, marginBottom: 20 }}>角色管理</h1>
      <Card title={editId ? '编辑角色' : '创建自定义角色'}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <input placeholder="角色名称" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} style={{ ...inputStyle, width: 160 }} />
            <input placeholder="描述" value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} style={{ ...inputStyle, flex: 1 }} />
            <input placeholder="技能 (逗号分隔)" value={form.skills} onChange={e => setForm({ ...form, skills: e.target.value })} style={{ ...inputStyle, width: 260 }} />
          </div>
          <textarea placeholder="系统提示词" value={form.system_prompt} onChange={e => setForm({ ...form, system_prompt: e.target.value })} style={{ ...inputStyle, width: '100%', minHeight: 80, fontFamily: 'monospace', fontSize: 12 }} />
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={save} style={{ ...btnStyle, background: 'var(--success)' }}>{editId ? '保存' : '创建'}</button>
            {editId && <button onClick={() => { setForm({ name: '', description: '', role_type: 'custom', system_prompt: '', skills: '' }); setEditId(null) }} style={{ ...btnStyle, background: 'var(--bg-hover)', color: 'var(--text-dim)' }}>取消</button>}
          </div>
        </div>
      </Card>
      <Card title={`角色列表 (${roles.length})`} style={{ marginTop: 16 }}>
        {roles.map(r => {
          const isExpanded = expanded[r.id]
          return (
            <div key={r.id} style={{ background: 'var(--bg-hover)', borderRadius: 'var(--radius-sm)', padding: 12, marginBottom: 8, fontSize: 13, border: r.builtin ? '1px solid var(--border)' : '1px solid var(--accent)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ flex: 1 }}>
                  <div><b>{r.name}</b><span style={{ fontSize: 10, marginLeft: 8, padding: '1px 6px', borderRadius: 10, background: r.builtin ? 'var(--bg-hover)' : 'var(--accent-light)', color: r.builtin ? 'var(--text-dim)' : 'var(--accent)' }}>{r.builtin ? '预定义' : '自定义'}</span></div>
                  {r.description && <div style={{ color: 'var(--text-dim)', fontSize: 12 }}>{r.description}</div>}
                </div>
                <div style={{ display: 'flex', gap: 4 }}>
                  <button onClick={() => setExpanded({ ...expanded, [r.id]: !isExpanded })} style={{ ...btnStyle, background: 'var(--bg-hover)', padding: '4px 10px', fontSize: 11, color: 'var(--text-dim)' }}>{isExpanded ? '收起' : '展开'}</button>
                  {!r.builtin && <><button onClick={() => edit(r)} style={{ ...btnStyle, background: 'var(--warning)', padding: '4px 10px', fontSize: 11 }}>编辑</button><button onClick={() => del(r.id)} style={{ ...btnStyle, background: 'var(--error)', padding: '4px 10px', fontSize: 11 }}>删除</button></>}
                </div>
              </div>
              {isExpanded && <div style={{ marginTop: 8, borderTop: '1px solid var(--border)', paddingTop: 8 }}><pre style={{ background: '#0f0f0f', borderRadius: 4, padding: 8, fontSize: 11, whiteSpace: 'pre-wrap', color: 'var(--text)', margin: 0 }}>{r.system_prompt || '(无)'}</pre></div>}
            </div>
          )
        })}
        {roles.length === 0 && <div style={{ color: 'var(--text-dim)', fontSize: 13 }}>暂无角色</div>}
      </Card>
    </div>
  )
}

// ── Config ──
function Config() {
  const [providers, setProviders] = useState([])
  useEffect(() => {
    api(`${API}/config/providers`)
      .then(r => r.json())
      .then(d => setProviders(d.providers || []))
  }, [])

  const saveProvider = async (key, data) => {
    await api(`${API}/config/providers/${key}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) })
    alert('已保存')
  }

  return (
    <div>
      <h1 style={{ fontSize: 28, fontWeight: 700, marginBottom: 20 }}>LLM 配置</h1>
      {Array.isArray(providers) && providers.length === 0 && <div style={{ color: 'var(--text-dim)', fontSize: 13 }}>加载中...</div>}
      {Array.isArray(providers) && providers.map(p => (
        <Card key={p.key} title={`${p.name} (${p.key})`} style={{ marginBottom: 12 }}>
          <ProviderForm providerKey={p.key} provider={p} onSave={saveProvider} />
        </Card>
      ))}
    </div>
  )
}

function ProviderForm({ providerKey, provider, onSave }) {
  const [apiKey, setApiKey] = useState('')
  const [enabled, setEnabled] = useState(provider.enabled || false)
  const [baseUrl, setBaseUrl] = useState('')
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <input type="password" placeholder="API Key" value={apiKey}
          onChange={e => setApiKey(e.target.value)} style={{ ...inputStyle, flex: 1 }} />
        <input type="url" placeholder="Base URL (可选)" value={baseUrl}
          onChange={e => setBaseUrl(e.target.value)} style={{ ...inputStyle, width: 250 }} />
        <label style={{ fontSize: 13, display: 'flex', alignItems: 'center', gap: 4, whiteSpace: 'nowrap' }}>
          <input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} />启用
        </label>
        <button onClick={() => onSave(providerKey, { api_key: apiKey, enabled, base_url: baseUrl })}
          style={{ ...btnStyle, background: 'var(--accent)' }}>保存</button>
      </div>
      {provider.has_key && <div style={{ fontSize: 11, color: 'var(--text-dim)' }}>✓ 已配置 API Key</div>}
      <div style={{ fontSize: 11, color: 'var(--text-dim)' }}>
        模型: {provider.models?.join(', ') || '(默认)'}
      </div>
    </div>
  )
}

// ── Skills / 技能页面 ──
function SkillsPage() {
  const [skills, setSkills] = useState([])
  const [activeSkill, setActiveSkill] = useState(null)
  const [content, setContent] = useState('')
  useEffect(() => {
    api(`${API}/skills`).then(r => r.json()).then(d => {
      const list = d.skills || []
      setSkills(list)
      if (list.length) pick(list[0].name)
    })
  }, [])
  const pick = (name) => {
    setActiveSkill(name)
    api(`${API}/skills/${name}`).then(r => r.json()).then(d => setContent(d.content || ''))
  }
  return (
    <div>
      <h1 style={{ fontSize: 28, fontWeight: 700, marginBottom: 24, letterSpacing: -0.5 }}>技能库</h1>
      <div style={{ display: 'flex', gap: 16, alignItems: 'flex-start' }}>
        <div style={{ width: 240, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 6 }}>
          {skills.map(s => (
            <div key={s.name} onClick={() => pick(s.name)} style={{
              padding: '10px 12px', borderRadius: 'var(--radius-sm)', cursor: 'pointer', fontSize: 13,
              background: activeSkill === s.name ? 'var(--accent-light)' : 'var(--bg-card)',
              border: `1px solid ${activeSkill === s.name ? 'var(--accent)' : 'var(--border)'}`,
            }}>
              <div style={{ fontWeight: 600 }}>{s.title || s.name}</div>
              <div style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 2 }}>{s.name}.md</div>
            </div>
          ))}
          {!skills.length && <Loading />}
        </div>
        <Card style={{ flex: 1, minHeight: 400 }}>
          <pre style={{ margin: 0, whiteSpace: 'pre-wrap', fontSize: 13, lineHeight: 1.7, fontFamily: 'inherit' }}>{content}</pre>
        </Card>
      </div>
    </div>
  )
}

// ── Shared Components ──
function Card({ title, children, style }) {
  return (
    <div style={{ background: 'var(--bg-card)', borderRadius: 'var(--radius)', padding: 16, border: '1px solid var(--border)', boxShadow: 'var(--shadow)', ...style }}>
      {title && <h3 style={{ fontSize: 10.5, color: 'var(--text-dim)', marginBottom: 12, textTransform: 'uppercase', letterSpacing: '0.12em', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>{title}</h3>}
      {children}
    </div>
  )
}

function Terminal({ logs }) {
  const ref = useRef(null)
  useEffect(() => { if (ref.current) ref.current.scrollTop = ref.current.scrollHeight }, [logs])
  return (
    <div ref={ref} style={{
      background: 'var(--bg-terminal)', borderRadius: 'var(--radius)', padding: 14, fontFamily: 'var(--font-mono)',
      fontSize: 12, height: 400, overflow: 'auto', whiteSpace: 'pre-wrap', lineHeight: 1.6,
      border: '1px solid var(--border)',
    }}>
      {logs.length === 0 ? <span style={{ color: '#4a525e' }}>等待输出...</span> :
        logs.map((l, i) => <div key={i} style={{
          color: l.startsWith('[ERROR]') || l.startsWith('❌') ? 'var(--error)' : l.startsWith('[OK]') || l.startsWith('✅') ? 'var(--success)' : l.startsWith('[TOOL]') || l.startsWith('🔧') ? 'var(--warning)' : l.startsWith('[') ? 'var(--info)' : '#d5dae2',
        }}>{l}</div>)}
    </div>
  )
}

function Loading() { return <div style={{ color: 'var(--text-dim)', fontSize: 13, fontFamily: 'var(--font-mono)' }}>loading...</div> }

function Button({ children, onClick }) {
  return <button onClick={onClick} style={{ ...btnStyle, background: 'var(--accent)', color: 'var(--accent-text)', textAlign: 'center', width: '100%' }}>{children}</button>
}

const inputStyle = {
  background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text)',
  padding: '8px 12px', borderRadius: 'var(--radius-sm)', fontSize: 13, outline: 'none',
}

const btnStyle = {
  border: 'none', color: 'var(--accent-text)', padding: '8px 16px', borderRadius: 'var(--radius-sm)',
  fontSize: 13, cursor: 'pointer', fontWeight: 500, transition: 'opacity 0.12s',
}

// ── App ──
export default function App() {
  const [active, setActive] = useState('dashboard')
  const pages = {
    dashboard: <Dashboard setActive={setActive} />,
    chat: <ChatPage />,
    agent: <AgentConsole />,
    c2: <C2Panel />,
    webshell: <WebShellPanel />,
    vulns: <Vulnerabilities />,
    yaml: <YamlTools />,
    tasks: <Tasks />,
    skills: <SkillsPage />,
    mcp: <McpConfig />,
    roles: <Roles />,
    config: <Config />,
  }
  return (
    <div>
      <Layout active={active} setActive={setActive}>{pages[active]}</Layout>
      <LoginOverlay />
    </div>
  )
}

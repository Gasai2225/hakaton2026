import assert from 'node:assert/strict'
import { after, before, test } from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'
import { createServer } from 'vite'

let vite, connectPresence
before(async () => {
  vite = await createServer({ configFile: false, cacheDir: 'node_modules/.vite-board-presence-tests',
    optimizeDeps: { noDiscovery: true }, server: { middlewareMode: true, watch: null, hmr: false, ws: false } })
  connectPresence = (await vite.ssrLoadModule('/src/boardPresence.ts')).connectPresence
})
after(async () => vite?.close())

async function until(condition) {
  const deadline = Date.now() + 2500
  while (!condition() && Date.now() < deadline) await delay(10)
  assert.ok(condition(), 'timed out waiting for presence')
}

function fixture(t, fetch) {
  const streams = [], states = []
  class Stream {
    static CLOSED = 2
    readyState = 0
    constructor(url) { this.url = url; streams.push(this) }
    receive(peers, locks = [], server_time = Date.now()) {
      this.readyState = 1
      this.onmessage({ data: JSON.stringify({ peers, locks, server_time }) })
    }
    close() { this.readyState = 2 }
  }
  const browser = Object.assign(new EventTarget(), { setTimeout, clearTimeout, setInterval, clearInterval, EventSource: Stream })
  globalThis.window = browser
  globalThis.document = Object.assign(new EventTarget(), { hidden: false, visibilityState: 'visible' })
  globalThis.EventSource = Stream
  t.mock.method(globalThis, 'fetch', fetch)
  const session = connectPresence('lesson', state => states.push(state))
  t.after(() => {
    session.stop()
    delete globalThis.window
    delete globalThis.document
    delete globalThis.EventSource
  })
  return { session, streams, states }
}

test('leaving the canvas wins over movements queued during an in-flight cursor upload', async t => {
  const sent = []
  let finishUpload
  const firstUpload = new Promise(resolve => { finishUpload = resolve })
  const { session, streams } = fixture(t, async (url, options) => {
    assert.equal(url, '/api/projects/lesson/presence/cursor')
    sent.push(JSON.parse(options.body))
    if (sent.length === 1) await firstUpload
    return new Response(null, { status: 204 })
  })
  session.setCursor({ x: 8, y: -15 })
  streams[0].receive([])
  await until(() => sent.length === 1)
  session.setCursor({ x: 16, y: 2 })
  session.setCursor(null)
  finishUpload()
  await until(() => sent.length === 2)
  assert.deepEqual(sent.map(packet => packet.cursor), [{ x: 8, y: -15 }, null])
  assert.equal(new URL(streams[0].url, 'http://localhost').searchParams.get('client_id'), sent[1].client_id)
})

test('reconnect restores the current cursor and a hidden tab drops its old stream', async t => {
  const sent = []
  const { session, streams, states } = fixture(t, async (_, options) => {
    sent.push(JSON.parse(options.body))
    return new Response(null, { status: 204 })
  })
  const peer = { id: 'other', name: 'Саша', cursor: { x: 31, y: 20 } }
  session.setCursor({ x: 7, y: 0 })
  streams[0].receive([peer])
  await until(() => sent.length === 1)
  assert.deepEqual(states.at(-1), { status: 'online', peers: [peer], locks: [] })
  streams[0].readyState = 0
  streams[0].onerror()
  assert.deepEqual(states.at(-1), { status: 'offline', peers: [], locks: [] })
  assert.equal(session.getClientId(), undefined)
  session.setCursor({ x: 22, y: 0 })
  window.dispatchEvent(new Event('pageshow'))
  streams[1].receive([])
  await until(() => sent.length === 2)
  assert.deepEqual(sent[1].cursor, { x: 22, y: 0 })

  document.hidden = true
  document.dispatchEvent(new Event('visibilitychange'))
  assert.equal(streams[1].readyState, 2)
  document.hidden = false
  document.dispatchEvent(new Event('visibilitychange'))
  const state = states.at(-1)
  streams[0].receive([peer])
  assert.equal(states.at(-1), state)
  streams[2].receive([])
  await until(() => sent.length === 3)
  assert.equal(sent[2].cursor, null)
  assert.notEqual(sent[2].client_id, sent[1].client_id)
})

test('a held node survives a tab switch, while page exit ends its ownership', async t => {
  const calls = []
  const { session, streams, states } = fixture(t, async (url, init) => {
    if (url.endsWith('/lock')) {
      calls.push(JSON.parse(init.body))
      return Response.json({ lease_id: 'first' })
    }
    return new Response(null, { status: 204 })
  })
  const lock = { node_id: 'node1', user_id: 'user1', name: 'Саша', mine: true, lease_id: 'first', expires_at: Date.now() + 180000 }
  streams[0].receive([])
  const id = session.getClientId()
  const opening = session.setLock(lock.node_id)
  await until(() => calls.length > 0)
  streams[0].receive([], [lock])
  await opening
  document.hidden = true
  document.dispatchEvent(new Event('visibilitychange'))
  assert.equal(session.getClientId(), id)
  assert.equal(states.at(-1).locks[0].lease_id, 'first')
  assert.deepEqual(calls, [{ client_id: id, node_id: 'node1', previous_lease_id: null, return_lease: true }])
  window.dispatchEvent(new Event('pagehide'))
  assert.equal(session.getClientId(), undefined)
  assert.deepEqual(states.at(-1).locks, [])
})

test('an expired heartbeat clears editing rights even before the stream reports an error', async t => {
  const { session, streams, states } = fixture(t, async () =>
    Response.json({ detail: 'Связь с доской прервалась' }, { status: 409 }))
  streams[0].receive([], [{ node_id: 'node1', user_id: 'user1', name: 'Саша', mine: true }])
  await until(() => states.at(-1).status === 'offline')
  assert.equal(session.getClientId(), undefined)
  assert.deepEqual(states.at(-1).locks, [])
  await assert.rejects(session.setLock('node1'), /подключения/)
})

test('lock switches run in order and queued requests cannot take ownership after disconnect', async t => {
  const calls = []
  let finish
  const first = new Promise(resolve => { finish = resolve })
  const { session, streams } = fixture(t, async (url, init) => {
    if (url.endsWith('/lock')) {
      const { node_id, previous_lease_id } = JSON.parse(init.body)
      calls.push(node_id)
      if (calls.length === 1) await first
      if (node_id === null) assert.equal(previous_lease_id, 'c-lease')
      return Response.json({ lease_id: node_id && node_id + '-lease' })
    }
    return new Response(null, { status: 204 })
  })
  streams[0].receive([])
  const oldId = session.getClientId()
  const requests = Promise.allSettled([session.setLock('a'), session.setLock('b'), session.setLock(null)])
  await until(() => calls.length > 0)
  assert.deepEqual(calls, ['a'])
  streams[0].onerror()
  window.dispatchEvent(new Event('pageshow'))
  streams[1].receive([])
  assert.notEqual(session.getClientId(), oldId)
  finish()
  assert.deepEqual((await requests).map(result => result.status), ['rejected', 'rejected', 'rejected'])
  assert.deepEqual(calls, ['a'])
  const opening = session.setLock('c')
  await until(() => calls.includes('c'))
  streams[1].receive([], [{ node_id: 'c', mine: true, lease_id: 'c-lease', expires_at: Date.now() + 180000 }])
  await opening
  const closing = session.setLock(null)
  await until(() => calls.includes(null))
  streams[1].receive([])
  await closing
  assert.deepEqual(calls, ['a', 'c', null])
})

test('a second click waits for the first confirmed lease when SSE lags behind POST', async t => {
  const calls = []
  const { session, streams } = fixture(t, async (url, init) => {
    if (!url.endsWith('/lock')) return new Response(null, { status: 204 })
    const body = JSON.parse(init.body)
    calls.push([body.node_id, body.previous_lease_id])
    return Response.json({ lease_id: body.node_id + '-lease' })
  })
  const snapshot = id => [{ node_id: id, mine: true, lease_id: id + '-lease', expires_at: Date.now() + 180000 }]
  streams[0].receive([])
  const opening = Promise.all([session.setLock('a'), session.setLock('b')])
  await until(() => calls.length > 0)
  streams[0].receive([])
  assert.deepEqual(calls, [['a', null]])
  streams[0].receive([], snapshot('a'))
  await until(() => calls.length > 1)
  assert.deepEqual(calls, [['a', null], ['b', 'a-lease']])
  streams[0].receive([], snapshot('b'))
  assert.deepEqual(await opening, ['a-lease', 'b-lease'])
  assert.equal(session.getLeaseId(), 'b-lease')
})

test('only activity on the owned node renews its specific lease and explicit continuation skips throttling', async t => {
  const activity = []
  const { session, streams, states } = fixture(t, async (url, options) => {
    if (url.endsWith('/activity')) activity.push(JSON.parse(options.body))
    return new Response(null, { status: 204 })
  })
  const serverTime = Date.now() + 900000
  const lock = { node_id: 'a', user_id: 'u', name: 'Саша', mine: true, lease_id: 'old', expires_at: serverTime + 180000 }
  streams[0].receive([], [lock], serverTime)
  assert.ok(Math.abs(states.at(-1).locks[0].expires_at - Date.now() - 180000) < 1000)
  session.setCursor({ x: 1, y: 2 })
  session.noteActivity('b')
  assert.equal(activity.length, 0)
  session.noteActivity('a')
  session.noteActivity('a')
  await session.continueEditing('a')
  assert.deepEqual(activity.map(a => a.lease_id), ['old', 'old'])
  streams[0].receive([], [{ ...lock, mine: false, lease_id: 'theirs' }], serverTime + 1000)
  await assert.rejects(session.continueEditing('a'), /снята/)
  assert.equal(session.getLeaseId(), undefined)
  session.noteActivity('a')
  streams[0].receive([], [{ ...lock, lease_id: 'new' }], serverTime + 2000)
  session.noteActivity('a')
  assert.deepEqual(activity.map(a => a.lease_id), ['old', 'old', 'new'])
})

test('a new click after expiry does not submit an expired previous lease while SSE catches up', async t => {
  const calls = []
  const { session, streams } = fixture(t, async (url, init) => {
    if (!url.endsWith('/lock')) return new Response(null, { status: 204 })
    calls.push(JSON.parse(init.body))
    return Response.json({ lease_id: 'new' })
  })
  streams[0].receive([], [{ node_id: 'a', mine: true, lease_id: 'old', expires_at: Date.now() - 1000 }])
  const opening = session.setLock('b')
  await until(() => calls.length === 1)
  assert.equal(calls[0].previous_lease_id, null)
  streams[0].receive([], [{ node_id: 'b', mine: true, lease_id: 'new', expires_at: Date.now() + 180000 }])
  assert.equal(await opening, 'new')
})

test('a hidden tab closes its stream once the idle lock expires', async t => {
  const { session, streams } = fixture(t, () => new Response(null, { status: 204 }))
  streams[0].receive([], [{ node_id: 'a', mine: true, lease_id: 'old', expires_at: Date.now() + 180000 }])
  document.hidden = true
  document.dispatchEvent(new Event('visibilitychange'))
  streams[0].receive([])
  assert.equal(streams[0].readyState, 2)
  assert.equal(session.getClientId(), undefined)
})

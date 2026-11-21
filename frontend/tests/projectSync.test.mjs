import assert from 'node:assert/strict'
import { after, before, test } from 'node:test'
import { createServer } from 'vite'

let vite, connect
before(async () => {
  vite = await createServer({ configFile: false, cacheDir: 'node_modules/.vite-project-sync-tests',
    optimizeDeps: { noDiscovery: true }, server: { middlewareMode: true, watch: null, hmr: false } })
  connect = (await vite.ssrLoadModule('/src/useProjectSync.ts')).connectProjectSync
})
after(async () => vite?.close())

const initial = { name: 'Project', nodes: [], edges: [], files: [] }
const detail = (revision, workflow) => ({ id: 'lesson', role: 'editor', can_run: true, revision, workflow })
const json = value => Response.json(value)

function deferred() {
  let resolve
  const promise = new Promise(done => { resolve = done })
  return { promise, resolve }
}

function fixture(t, fetch, clientId) {
  let timer
  const browser = new EventTarget()
  browser.setTimeout = callback => { timer = callback; return 1 }
  browser.clearTimeout = () => {}
  globalThis.window = browser
  t.mock.method(globalThis, 'fetch', fetch)
  const applied = [], changes = []
  let draft = initial
  const session = connect('lesson', () => ({
    snapshot: () => draft, apply: graph => { draft = graph; applied.push(graph) }, saved: () => {}, clientId,
  }), state => changes.push(state))
  session.init(detail(1, initial))
  t.after(() => { session.stop(); delete globalThis.window })
  return { session, applied, changes, tick: () => timer(), edit(value, leaseId) { draft = value; session.touch(leaseId) } }
}

test('a late GET cannot overwrite local edits, and a late PUT cannot discard subsequent typing', async t => {
  const pendingGet = deferred(), getStarted = deferred(), pendingPut = deferred(), putStarted = deferred()
  const remoteFile = [{ path: 'Remote.kt', content: 'class Remote' }]
  const mine = { ...initial, name: 'Mine' }
  const newer = { ...mine, name: 'Mine again' }
  const puts = []
  const box = fixture(t, async (_, init) => {
    if (init.method !== 'PUT') {
      const tag = init.headers['If-None-Match']
      if (tag === '"lesson-4-editor-1"') return new Response(null, { status: 304 })
      assert.equal(tag, '"lesson-1-editor-1"')
      getStarted.resolve()
      return pendingGet.promise
    }
    const body = JSON.parse(init.body); puts.push(body)
    if (puts.length === 1) { putStarted.resolve(); return pendingPut.promise }
    return json(detail(4, { ...body.workflow, files: remoteFile }))
  })
  const poll = box.tick()
  await getStarted.promise
  box.edit(mine)
  const saved = box.session.flush()
  pendingGet.resolve(json(detail(2, { ...initial, files: remoteFile })))
  await poll
  await putStarted.promise
  box.edit(newer)
  pendingPut.resolve(json(detail(3, { ...mine, files: remoteFile })))
  assert.equal(await saved, 4)
  assert.deepEqual(puts, [
    { workflow: mine, base_revision: 1 }, { workflow: newer, edit_base: mine, base_revision: 3 },
  ])
  assert.deepEqual(box.applied, [{ ...newer, files: remoteFile }])
  await box.tick()
  assert.equal(box.applied.length, 1)
})

test('a conflict preserves local edits while access is rechecked', async t => {
  let access = true
  const box = fixture(t, async (_, init) => init.method === 'PUT'
    ? Response.json({ detail: 'Конфликт имени' }, { status: 409 })
    : new Response(null, { status: access ? 304 : 404 }))
  box.edit({ ...initial, name: 'Another' })
  await assert.rejects(box.session.flush(), /Конфликт/)
  await box.tick()
  assert.equal(box.changes.at(-1).conflict, true)
  access = false
  await box.tick()
  assert.equal(box.changes.at(-1).forbidden, true)
  assert.equal(box.applied.length, 0)
})

test('a shared editor waits for its tab identity and preserves the draft if the node lock was lost', async t => {
  let client
  const puts = []
  const box = fixture(t, async (_, init) => {
    if (init.method !== 'PUT') return new Response(null, { status: 304 })
    puts.push(JSON.parse(init.body))
    return Response.json({ detail: 'Блок редактирует Саша' }, { status: 423 })
  }, () => client)
  box.edit({ ...initial, name: 'Моя правка' })
  await box.tick()
  assert.equal(puts.length, 0)
  client = 'a'.repeat(32)
  await assert.rejects(box.session.flush(), /Саша/)
  assert.equal(puts[0].client_id, client)
  assert.equal(box.changes.at(-1).conflict, true)
  await box.tick()
  assert.equal(puts.length, 1)
  assert.equal(box.applied.length, 0)
})

test('losing run permission while saving a schedule keeps the board and the unsaved draft available', async t => {
  const box = fixture(t, async (_, init) => init.method === 'PUT'
    ? Response.json({ detail: 'Для изменения расписания нужно право запуска' }, { status: 403 })
    : new Response(null, { status: 304 }))
  box.edit({ ...initial, nodes: [{ id: 'schedule', kind: 'schedule', enabled: true }] })
  await assert.rejects(box.session.flush(), /право запуска/)
  await box.tick()
  assert.equal(box.changes.at(-1).forbidden, false)
  assert.equal(box.changes.at(-1).conflict, true)
  assert.equal(box.applied.length, 0)
})

test('an expired lease can be recovered without rebasing the draft onto intervening writes', async t => {
  const sent = []
  const remote = { ...initial, files: [{ path: 'Other.kt', content: 'class Other' }] }
  const draft = { ...initial, nodes: [{ id: 'scan', pattern: '*.kt' }] }
  const box = fixture(t, async (_, init) => {
    if (init.method !== 'PUT') return json(detail(2, remote))
    const body = JSON.parse(init.body)
    sent.push(body)
    if (sent.length === 1) return Response.json({ detail: 'Снова откройте блок' }, { status: 423 })
    return json(detail(sent.length + 1, { ...body.workflow, files: remote.files }))
  })
  box.edit(draft, 'old')
  box.edit({ ...draft, name: 'Mine' })
  await box.tick()
  assert.equal(sent[0].lease_id, 'old')
  await box.tick()
  assert.equal(box.applied.length, 0)
  assert.equal(await box.session.flush('new'), 3)
  assert.deepEqual(sent[1], { ...sent[0], lease_id: 'new', base_revision: 1 })
  assert.deepEqual(box.applied[0], { ...draft, name: 'Mine', files: remote.files })
  box.edit({ ...box.applied[0], name: 'Renamed' })
  await box.session.flush()
  assert.equal(sent[2].lease_id, undefined)
})

test('reacquiring an invalid field allows correction and preserves genuine content conflicts', async t => {
  const sent = []
  const box = fixture(t, async (_, init) => {
    if (init.method !== 'PUT') return json(detail(2, { ...initial, name: 'Shared' }))
    sent.push(JSON.parse(init.body))
    return sent.length === 1 ? Response.json({ detail: 'Недопустимое поле' }, { status: 422 })
      : Response.json({ detail: 'Конфликт поля' }, { status: 409 })
  })
  box.edit({ ...initial, nodes: [{ id: 'scan', pattern: '' }] }, 'old')
  await box.tick()
  assert.equal(await box.session.flush('new'), 1)
  assert.equal(sent.length, 1)
  box.edit({ ...initial, nodes: [{ id: 'scan', pattern: '*.kt' }] }, 'new')
  await box.tick()
  assert.equal(sent[1].lease_id, 'new')
  assert.equal(sent[1].base_revision, 1)
  assert.equal(await box.session.flush('another'), 1)
  await box.tick()
  assert.equal(box.changes.at(-1).conflict, true)
  assert.equal(sent.length, 2)
  assert.equal(box.applied.length, 0)
})

test('an invalid edit waits for a change, a lost response retries the same snapshot', async t => {
  const sent = []
  const box = fixture(t, async (_, init) => {
    if (init.method !== 'PUT') return new Response(null, { status: 304 })
    const body = JSON.parse(init.body)
    sent.push(body)
    if (sent.length === 1) return Response.json({ detail: 'Введите имя' }, { status: 422 })
    if (sent.length === 2) throw new TypeError('Connection lost')
    return json(detail(sent.length, body.workflow))
  })
  box.edit({ ...initial, name: '' })
  await box.tick()
  await box.tick()
  assert.equal(sent.length, 1)
  box.edit({ ...initial, name: 'First' })
  await box.tick()
  box.edit({ ...initial, name: 'Second' })
  assert.equal(await box.session.flush(), 4)
  assert.deepEqual(sent[2], sent[1])
  assert.deepEqual(sent[3].edit_base, sent[1].workflow)
  assert.deepEqual(box.applied, [{ ...initial, name: 'Second' }])
})

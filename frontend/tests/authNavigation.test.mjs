import assert from 'node:assert/strict'
import { after, before, test } from 'node:test'
import { createServer } from 'vite'

let vite, authNavigation, authLink
before(async () => {
  vite = await createServer({ configFile: false, cacheDir: 'node_modules/.vite-auth-navigation-tests',
    optimizeDeps: { noDiscovery: true }, server: { middlewareMode: true, watch: null, hmr: false, ws: false } })
  const navigation = await vite.ssrLoadModule('/src/authNavigation.ts')
  authNavigation = navigation.authNavigation
  authLink = navigation.authLink
})
after(async () => vite?.close())

const oldInvite = '/#invite=old_invitation'
const newInvite = '/#invite=fresh_invitation'
const inspect = (path, pending = oldInvite) => authNavigation(new URL(path, 'https://garden.test'), () => pending)

test('an invitation opens registration and keeps the same invite when switching to login and back', () => {
  for (const url of [newInvite, '/?invite=fresh_invitation', '/invite/fresh_invitation']) {
    const entry = inspect(url)
    assert.equal(entry.showRegistration, true)
    const login = inspect(authLink('login', entry.next))
    assert.equal(login.showRegistration, false)
    assert.equal(login.next, newInvite)
    const signup = inspect(authLink('register', login.next))
    assert.equal(signup.showRegistration, true)
    assert.equal(signup.next, newInvite)
  }
  assert.equal(inspect('/').showRegistration, false)
  assert.equal(inspect('/register').showRegistration, true)
})

test('ordinary navigation and a freshly opened invitation ignore an abandoned social login', () => {
  assert.equal(inspect('/').next, '/projects')
  assert.equal(inspect('/templates').next, '/templates')
  const route = inspect(newInvite)
  assert.equal(route.next, newInvite)
  assert.equal(route.oauthComplete, false)
  assert.equal(route.authRoute, false)
})

test('a successful OAuth callback restores its saved destination or the projects page', () => {
  assert.equal(inspect('/?auth_complete=1').oauthComplete, true)
  assert.equal(inspect('/?auth_complete=1').next, oldInvite)
  assert.equal(inspect('/?auth_complete=1#invite=fresh_invitation').next, newInvite)
  assert.equal(inspect('/?auth_complete=1', null).next, '/projects')
  assert.equal(inspect('/?auth_complete=1', 'https://other.test').next, '/projects')
})

test('a failed callback retains the invitation when switching to registration or password login', () => {
  const failed = inspect('/?auth_error=cancelled')
  assert.equal(failed.oauthError, true)
  assert.equal(failed.oauthComplete, false)
  assert.equal(failed.next, oldInvite)
  for (const page of ['login', 'register']) {
    const destination = authLink(page, failed.next)
    assert.equal(inspect(destination, null).next, oldInvite)
    assert.equal(new URL(destination, 'https://garden.test').search, '')
  }
  assert.equal(inspect('/?auth_error=cancelled#invite=fresh_invitation').next, newInvite)
})

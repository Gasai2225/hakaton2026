export const projectRoute = /^\/projects\/([\w-]+)(\/access)?$/

function safeDestination(value: string | null) {
  if (value && (projectRoute.test(value) || ['/templates', '/profile', '/projects'].includes(value)
    || /^\/#invite=[A-Za-z0-9_-]{8,256}$/.test(value))) return value
  return '/projects'
}

export function authNavigation(url: URL, pending: () => string | null) {
  const path = url.pathname.replace(/\/$/, '') || '/'
  const query = url.searchParams
  const invite = new URLSearchParams(url.hash.slice(1)).get('invite') || query.get('invite') || path.match(/^\/invite\/([^/]+)$/)?.[1]
  const authRoute = path === '/register' || path === '/login'
  const showRegistration = path === '/register' || (Boolean(invite) && path !== '/login')
  const oauthError = path === '/' && query.has('auth_error')
  const oauthComplete = path === '/' && query.get('auth_complete') === '1' && !oauthError
  let next = safeDestination(authRoute ? query.get('next') : path)
  if (oauthComplete || oauthError) next = safeDestination(pending())
  if (invite && /^[A-Za-z0-9_-]{8,256}$/.test(invite)) next = '/#invite=' + invite
  return { path, query, invite, authRoute, showRegistration, oauthError, oauthComplete, next }
}

export function authLink(route: 'register' | 'login', next: string) {
  if (next.startsWith('/#invite=')) return '/' + route + next.slice(1)
  return '/' + route + (next === '/projects' ? '' : '?next=' + encodeURIComponent(next))
}

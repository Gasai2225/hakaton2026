import { useEffect, useState, type ReactNode } from 'react'
import { ArrowRight, GitFork, LayoutGrid, LogOut, UserRound } from 'lucide-react'
import { ApiError, message, request } from './api'
import { CatalogPage } from './CatalogPage'
import { AccessPage, ProjectsPage } from './ProjectPages'
import { projectUrl, useAction, useResource, type Account, type Project } from './workspaceData'
import s from './workspace.module.css'
export type { Account } from './workspaceData'

const path = window.location.pathname.replace(/\/$/, '') || '/'
const query = new URLSearchParams(window.location.search)
const fragment = new URLSearchParams(window.location.hash.slice(1))
const invite = fragment.get('invite') || query.get('invite') || path.match(/^\/invite\/([^/]+)$/)?.[1]
const pendingKey = 'garden.oauth.return'
const projectRoute = /^\/projects\/([\w-]+)(\/access)?$/
const local = ['127.0.0.1', 'localhost', '[::1]'].includes(window.location.hostname)
const authRoute = path === '/register' || path === '/login'

function safeDestination(value: string | null) {
  if (value && (projectRoute.test(value) || ['/templates', '/profile', '/projects'].includes(value)
    || /^\/#invite=[A-Za-z0-9_-]{8,256}$/.test(value))) return value
  return '/projects'
}

function nextPage() {
  if (invite && /^[A-Za-z0-9_-]{8,256}$/.test(invite)) return '/#invite=' + invite
  if (query.has('auth_error')) return safeDestination(sessionStorage.getItem(pendingKey))
  return safeDestination(authRoute ? query.get('next') : path)
}

function resume(destination: string) {
  const target = new URL(destination, window.location.origin)
  if (target.pathname === window.location.pathname && target.search === window.location.search) {
    window.history.replaceState(null, '', target)
    window.location.reload()
  } else window.location.replace(target)
}

function authLink(route: 'register' | 'login', next: string) {
  if (next.startsWith('/#invite=')) return '/' + route + next.slice(1)
  return '/' + route + (next === '/projects' ? '' : '?next=' + encodeURIComponent(next))
}

function Header({ user }: { user?: Account }) {
  return <header className={s.header}><div className={s.navbar}>
    <a href="/projects" className={s.brand} aria-label="Garden — проекты"><span><GitFork size={21}/></span>Garden</a>
    {user && <nav aria-label="Рабочая область">
      <a href="/projects" aria-current={path === '/' || path === '/projects' ? 'page' : undefined}>Проекты</a>
      <a href="/templates" aria-current={path === '/templates' ? 'page' : undefined}>Шаблоны</a>
    </nav>}
    {user && <a href="/profile" className={s.userLink} aria-label={'Личный кабинет · ' + user.name}>
      <UserRound size={16}/><span>{user.name}</span></a>}
  </div></header>
}

function AuthForm({ register }: { register: boolean }) {
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const providers = useResource<{ id: string; name: string; enabled: boolean }[]>('auth/providers')
  const action = useAction()
  const next = nextPage()
  return <main className={s.narrow}><section className={s.panel}>
    <h1>{register ? 'Регистрация' : 'Вход в Garden'}</h1>
    {invite && <p className={s.note}>Используйте адрес, на который вас пригласили в проект.</p>}
    <form className={s.form} onSubmit={e => { e.preventDefault(); void action.perform(async () => {
      const body = register ? { name: name.trim(), email: email.trim(), password } : { email: email.trim(), password }
      await request<Account>('auth/' + (register ? 'register' : 'login'), 'POST', body)
      sessionStorage.removeItem(pendingKey)
      resume(next)
    }) }}>
      {register && <label>Имя<input autoComplete="name" required maxLength={100} value={name} onChange={e => setName(e.target.value)} /></label>}
      <label>Электронная почта<input type="email" autoComplete="email" required value={email} onChange={e => setEmail(e.target.value)}/></label>
      <label>Пароль<input type="password" autoComplete={register ? 'new-password' : 'current-password'} required minLength={register ? 8 : 1} maxLength={128}
        aria-describedby={register ? 'password-hint' : undefined} value={password} onChange={e => setPassword(e.target.value)}/></label>
      {register && <small id="password-hint">От 8 символов</small>}
      {(action.error || query.get('auth_error')) && <p role="alert" className={s.error}>{action.error || query.get('auth_error')}</p>}
      <button className={s.primary} disabled={action.busy || (register && !name.trim())}>{register ? 'Создать аккаунт' : 'Войти'}<ArrowRight size={16}/></button>
    </form>
    {providers.error && <p className={s.note}>Способы быстрого входа временно недоступны.</p>}
    {providers.data && providers.data.length > 0 && <div className={s.social} aria-label="Быстрый вход">
      {providers.data.map(provider => provider.enabled ? <a key={provider.id} className={s.button}
        href={'/api/auth/oauth/' + encodeURIComponent(provider.id) + '/start'}
        onClick={() => sessionStorage.setItem(pendingKey, next)}>Войти через {provider.name}</a>
        : <button type="button" key={provider.id} disabled title="Способ входа ещё не подключён">{provider.name}</button>)}
      {providers.data.some(p => !p.enabled) && <small>Недоступные способы входа ещё не подключены администратором.</small>}
    </div>}
    <p className={s.authSwitch}>{register ? 'Уже есть аккаунт?' : 'Нет аккаунта?'}{' '}
      <a href={authLink(register ? 'login' : 'register', next)}>{register ? 'Войти' : 'Зарегистрироваться'}</a></p>
    {local && <a href="/local" className={s.localLink}>Локальный редактор</a>}
  </section></main>
}

function ProfilePage({ user, update }: { user: Account; update: (v: Account) => void }) {
  const [name, setName] = useState(user.name)
  const [saved, setSaved] = useState(false)
  const action = useAction()
  return <main className={s.content}><div className={s.pageHead}><h1>Личный кабинет</h1></div>
    <section className={s.panel + ' ' + s.profile}>
      <form className={s.form} onSubmit={e => { e.preventDefault(); void action.perform(async () => {
        const updated = await request<Account>('auth/me', 'PATCH', { name: name.trim() })
        update(updated); setName(updated.name); setSaved(true)
      }) }}>
        <label>Электронная почта<input type="email" value={user.email} readOnly/></label>
        <label>Имя<input autoComplete="name" value={name} maxLength={100} required onChange={e => { setName(e.target.value); setSaved(false) }}/></label>
        <div className={s.actions}><button className={s.primary} disabled={action.busy || !name.trim() || user.name === name.trim()}>Сохранить имя</button>
          {saved && <span role="status">Имя сохранено</span>}</div>
      </form>
      <div className={s.accountActions}>{local && <a className={s.button} href="/local"><LayoutGrid size={15}/>Локальный редактор</a>}
        <button disabled={action.busy} onClick={() => void action.perform(async () => {
          await request<void>('auth/logout', 'POST'); sessionStorage.removeItem(pendingKey); window.location.replace('/login')
        })}><LogOut size={15}/>Выйти</button></div>
      {action.error && <p role="alert" className={s.error}>{action.error}</p>}
    </section></main>
}

function InvitePage({ user, token }: { user: Account; token: string }) {
  const action = useAction()
  return <main className={s.narrow}><section className={s.panel}><h1>Приглашение в проект</h1>
    <p className={s.note}>Вы вошли как <strong>{user.email}</strong>. После принятия приглашения вы сможете редактировать граф вместе с командой.</p>
    {action.error && <p role="alert" className={s.error}>{action.error}</p>}
    <div className={s.actions}><button className={s.primary} disabled={action.busy} onClick={() => void action.perform(async () => {
      const project = await request<Project>('project-invitations/accept', 'POST', { token })
      window.location.replace(projectUrl(project.id))
    })}>Принять приглашение</button>
    <button disabled={action.busy} onClick={() => void action.perform(async () => {
      await request<void>('auth/logout', 'POST'); window.location.replace(authLink('login', nextPage()))
    })}>Сменить аккаунт</button></div></section></main>
}

export function Workspace({ renderEditor }: { renderEditor: (projectId: string, user: Account) => ReactNode }) {
  const [user, setUser] = useState<Account | null>()
  const [error, setError] = useState('')
  const [retry, setRetry] = useState(0)
  useEffect(() => {
    const controller = new AbortController()
    const refresh = () => window.location.reload()
    window.addEventListener('hashchange', refresh)
    request<Account>('auth/me', 'GET', undefined, controller.signal).then(account => {
      if (controller.signal.aborted) return
      const fromProvider = path === '/' && sessionStorage.getItem(pendingKey)
      if (fromProvider && !query.has('auth_error')) {
        sessionStorage.removeItem(pendingKey); resume(safeDestination(fromProvider)); return
      }
      if (authRoute) { window.location.replace(nextPage()); return }
      setUser(account)
    }).catch(err => {
      if (controller.signal.aborted) return
      if (err instanceof ApiError && err.status === 401) setUser(null)
      else setError(message(err))
    })
    return () => { controller.abort(); window.removeEventListener('hashchange', refresh) }
  }, [retry])
  const project = projectRoute.exec(path)
  let page: ReactNode
  if (error) page = <main className={s.narrow}><div role="alert" className={s.panel}>{error}{' '}
    <button onClick={() => { setError(''); setRetry(n => n + 1) }}>Повторить</button></div></main>
  else if (user === undefined) page = <main className={s.narrow}><p role="status">Загружаем личный кабинет…</p></main>
  else if (!user) page = <AuthForm register={path === '/register'}/>
  else if (invite) page = <InvitePage user={user} token={invite}/>
  else if (project?.[2]) page = <AccessPage id={project[1]}/>
  else if (project) return renderEditor(project[1], user)
  else if (path === '/templates') page = <CatalogPage/>
  else if (path === '/profile') page = <ProfilePage user={user} update={setUser}/>
  else if (path === '/' || path === '/projects') page = <ProjectsPage/>
  else page = <main className={s.narrow}><h1>Страница не найдена</h1><a href="/projects">К проектам</a></main>
  return <div className={s.workspace}><Header user={user ?? undefined}/>{page}</div>
}

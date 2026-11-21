import { lazy, Suspense, useEffect, useState, type ReactNode } from 'react'
import { ArrowRight, GitFork, LayoutGrid, LogOut, UserRound } from 'lucide-react'
import { ApiError, message, request } from './api'
import { CatalogPage } from './CatalogPage'
import { reportRoute } from './browserReportLinks'
import { AccessPage, ProjectsPage } from './ProjectPages'
import { ProjectReportsPage } from './ProjectReportsPage'
import { authLink, authNavigation, projectRoute } from './authNavigation'
import { projectUrl, useAction, useResource, type Account, type Project } from './workspaceData'
import s from './workspace.module.css'
export type { Account } from './workspaceData'

const NotificationSettings = lazy(() => import('./NotificationSettings'))
const BrowserReportPage = lazy(() => import('./BrowserReportPage'))
const BrowserNotification = lazy(() => import('./BrowserNotification'))

const pendingKey = 'garden.oauth.return'
const { path, query, invite, authRoute, showRegistration, oauthComplete, oauthError, next } =
  authNavigation(new URL(window.location.href), () => sessionStorage.getItem(pendingKey))
const local = ['127.0.0.1', 'localhost', '[::1]'].includes(window.location.hostname)

function nextPage() {
  return next
}

function resume(destination: string) {
  const target = new URL(destination, window.location.origin)
  if (target.pathname === window.location.pathname && target.search === window.location.search) {
    window.history.replaceState(null, '', target)
    window.location.reload()
  } else window.location.replace(target)
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

type InvitationPreview =
  | { status: 'pending'; project_name: string; email_hint: string }
  | { status: 'wrong_account'; project_name?: string; email_hint?: string }
  | { status: 'sign_in' }
  | { status: 'accepted'; project_name: string; project_id: string }

function AuthForm({ register, invitation }: { register: boolean; invitation?: InvitationPreview }) {
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const providers = useResource<{ id: string; name: string; enabled: boolean }[]>('auth/providers')
  const action = useAction()
  const next = nextPage()
  const joinToken = register && invitation?.status === 'pending' ? invite : null
  async function submit() {
    const credentials = { email: email.trim(), password }
    let destination = next
    if (joinToken) {
      const result = await request<{ project_id: string }>('auth/register-and-join', 'POST',
        { ...credentials, name: name.trim(), invitation_token: joinToken })
      destination = projectUrl(result.project_id)
    } else if (register) {
      await request('auth/register', 'POST', { ...credentials, name: name.trim() })
    } else {
      await request('auth/login', 'POST', credentials)
    }
    sessionStorage.removeItem(pendingKey)
    resume(destination)
  }
  const switchMode = <p className={s.authSwitch}>{register ? 'Уже есть аккаунт?' : 'Нет аккаунта?'}{' '}
    <a href={authLink(register ? 'login' : 'register', next)}>{register ? 'Войти' : 'Зарегистрироваться'}</a></p>
  return <main className={s.narrow}><section className={s.panel}>
    <h1>{register ? 'Регистрация' : 'Вход в Garden'}</h1>
    {invitation?.status === 'pending' && <p className={s.note}>
      Вас пригласили в проект <strong>«{invitation.project_name}»</strong>. Используйте почту <strong>{invitation.email_hint}</strong>.
    </p>}
    {invitation?.status === 'sign_in' && <p className={s.note}>Войдите в аккаунт, с которого вы приняли приглашение.</p>}
    {joinToken && switchMode}
    <form className={s.form} onSubmit={e => { e.preventDefault(); void action.perform(submit) }}>
      {register && <label>Имя<input autoComplete="name" required maxLength={100} value={name} onChange={e => setName(e.target.value)} /></label>}
      <label>Электронная почта<input type="email" autoComplete="email" required value={email} onChange={e => setEmail(e.target.value)}/></label>
      <label>Пароль<input type="password" autoComplete={register ? 'new-password' : 'current-password'} required minLength={register ? 8 : 1} maxLength={128}
        aria-describedby={register ? 'password-hint' : undefined} value={password} onChange={e => setPassword(e.target.value)}/></label>
      {register && <small id="password-hint">От 8 символов</small>}
      {(action.error || query.get('auth_error')) && <p role="alert" className={s.error}>{action.error || query.get('auth_error')}</p>}
      <button className={s.primary} disabled={action.busy || (register && !name.trim())}>
        {joinToken ? 'Зарегистрироваться и вступить' : register ? 'Создать аккаунт' : 'Войти'}<ArrowRight size={16}/>
      </button>
    </form>
    {providers.error && <p className={s.note}>Способы быстрого входа временно недоступны.</p>}
    {providers.data && providers.data.length > 0 && <div className={s.social} aria-label="Быстрый вход">
      {providers.data.map(provider => provider.enabled ? <a key={provider.id} className={s.button}
        href={'/api/auth/oauth/' + encodeURIComponent(provider.id) + '/start'}
        onClick={() => sessionStorage.setItem(pendingKey, next)}>Войти через {provider.name}</a>
        : <button type="button" key={provider.id} disabled title="Способ входа ещё не подключён">{provider.name}</button>)}
      {providers.data.some(p => !p.enabled) && <small>Недоступные способы входа ещё не подключены администратором.</small>}
    </div>}
    {!joinToken && invitation?.status !== 'sign_in' && switchMode}
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
    </section>
    <Suspense fallback={<p role="status">Загрузка настроек уведомлений…</p>}>
      <NotificationSettings email={user.email}/>
    </Suspense>
  </main>
}

function InvitePage({ user, token }: { user: Account | null; token: string }) {
  const action = useAction()
  const [preview, setPreview] = useState<InvitationPreview>()
  const [problem, setProblem] = useState<{ text: string; invalid: boolean }>()
  const [version, setVersion] = useState(0)
  useEffect(() => {
    const controller = new AbortController()
    setPreview(undefined); setProblem(undefined)
    request<InvitationPreview>('project-invitations/preview', 'POST', { token }, controller.signal)
      .then(result => { if (!controller.signal.aborted) setPreview(result) })
      .catch(err => {
        if (controller.signal.aborted) return
        const invalid = err instanceof ApiError && [404, 422].includes(err.status)
        setProblem({ invalid, text: invalid ? 'Ссылка больше не действует. Попросите владельца проекта прислать новую.' : message(err) })
      })
    return () => controller.abort()
  }, [token, user?.id, version])
  if (preview && (!user || preview.status === 'sign_in'))
    return <AuthForm register={showRegistration && preview.status === 'pending'} invitation={preview}/>
  return <main className={s.narrow}><section className={s.panel}><h1>Приглашение в проект</h1>
    {!preview && !problem && <p role="status">Проверяем приглашение…</p>}
    {problem && <div><p className={s.error} role="alert">{problem.text}</p>
      {problem.invalid ? <a href="/projects">К моим проектам</a>
        : <button onClick={() => setVersion(n => n + 1)}>Повторить</button>}</div>}
    {user && preview?.status === 'accepted' && <>
      <p>У вас уже есть доступ к проекту «{preview.project_name}».</p>
      <a className={s.button} href={projectUrl(preview.project_id)}>Открыть проект</a>
    </>}
    {user && preview && (preview.status === 'pending' || preview.status === 'wrong_account') && <>
    {preview.project_name && <h2>{preview.project_name}</h2>}
    {preview.status === 'wrong_account'
      ? <p>Вы вошли как <strong>{user.email}</strong>. Для этого приглашения войдите {preview.email_hint
        ? <>с почтой <strong>{preview.email_hint}</strong></> : 'в аккаунт участника'}.</p>
      : <p>Приглашение для <strong>{user.email}</strong>.</p>}
    {action.error && <p role="alert" className={s.error}>{action.error}</p>}
    <div className={s.actions}>{preview.status === 'pending' && <button className={s.primary} disabled={action.busy} onClick={() => void action.perform(async () => {
      try {
        const project = await request<Project>('project-invitations/accept', 'POST', { token })
        window.location.replace(projectUrl(project.id))
      } catch (err) {
        if (err instanceof ApiError && [401, 403, 404].includes(err.status)) window.location.reload()
        else throw err
      }
    })}>Принять приглашение</button>}
    <button disabled={action.busy} onClick={() => void action.perform(async () => {
      await request<void>('auth/logout', 'POST'); window.location.replace(authLink('login', nextPage()))
    })}>Сменить аккаунт</button></div></>}
  </section></main>
}

type RenderEditor = (project: Project, user: Account) => ReactNode

function ProjectPage({ id, accessPage, user, renderEditor }: {
  id: string; accessPage: boolean; user: Account; renderEditor: RenderEditor
}) {
  const { data, error, denied, reload } = useResource<Project>('projects/' + encodeURIComponent(id) + '/access', 2500)
  if (data && !accessPage && data.role !== 'reporter') return renderEditor(data, user)
  let content: ReactNode
  if (data) content = accessPage && (data.role === 'owner' || data.role === 'editor') ? <AccessPage project={data}/>
    : data.role === 'reporter' ? <ProjectReportsPage project={data}/>
    : <main className={s.content}><h1>Управление доступом</h1><p>Доступом управляет владелец проекта.</p><a href={projectUrl(id)}>К проекту</a></main>
  else content = <main className={s.content}>{denied ? <><h1>Нет доступа к проекту</h1><a href="/projects">Мои проекты</a></>
    : error ? <p role="alert">{error} <button onClick={reload}>Повторить</button></p> : <p role="status">Загружаем проект…</p>}</main>
  return <div className={s.workspace}><Header user={user}/>{content}</div>
}

export function Workspace({ renderEditor }: { renderEditor: RenderEditor }) {
  const [user, setUser] = useState<Account | null>()
  const [error, setError] = useState('')
  const [retry, setRetry] = useState(0)
  useEffect(() => {
    const controller = new AbortController()
    const refresh = () => window.location.reload()
    window.addEventListener('hashchange', refresh)
    request<Account>('auth/me', 'GET', undefined, controller.signal).then(account => {
      if (controller.signal.aborted) return
      if (oauthError && !invite) { setUser(null); return }
      if (oauthComplete || authRoute) {
        sessionStorage.removeItem(pendingKey); resume(nextPage()); return
      }
      setUser(account)
    }).catch(err => {
      if (controller.signal.aborted) return
      if (err instanceof ApiError && err.status === 401) setUser(null)
      else setError(message(err))
    })
    return () => { controller.abort(); window.removeEventListener('hashchange', refresh) }
  }, [retry])
  const project = projectRoute.exec(path)
  const report = reportRoute.exec(path)
  const notification = user && !report && <Suspense fallback={null}><BrowserNotification/></Suspense>
  let page: ReactNode
  if (error) page = <main className={s.narrow}><div role="alert" className={s.panel}>{error}{' '}
    <button onClick={() => { setError(''); setRetry(n => n + 1) }}>Повторить</button></div></main>
  else if (user === undefined) page = <main className={s.narrow}><p role="status">Загружаем личный кабинет…</p></main>
  else if (invite) page = <InvitePage user={user} token={invite}/>
  else if (!user) page = <AuthForm register={showRegistration}/>
  else if (project) return <>
    <ProjectPage id={project[1]} accessPage={!!project[2]} user={user} renderEditor={renderEditor}/>
    {notification}
  </>
  else if (report) page = <Suspense fallback={<p role="status">Загружаем отчёт…</p>}>
    <BrowserReportPage runId={report[1]} nodeId={report[2]}/>
  </Suspense>
  else if (path === '/templates') page = <CatalogPage/>
  else if (path === '/profile') page = <ProfilePage user={user} update={setUser}/>
  else if (path === '/' || path === '/projects') page = <ProjectsPage/>
  else page = <main className={s.narrow}><h1>Страница не найдена</h1><a href="/projects">К проектам</a></main>
  return <div className={s.workspace}><Header user={user ?? undefined}/>{page}{notification}</div>
}

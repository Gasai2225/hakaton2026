import { useState } from 'react'
import { ArrowRight, Check, Copy, Folder, Plus, UsersRound, X } from 'lucide-react'
import { request } from './api'
import { projectUrl, useAction, useResource, type Project } from './workspaceData'
import s from './workspace.module.css'

const date = new Intl.DateTimeFormat('ru-RU', { dateStyle: 'medium', timeStyle: 'short' })

export function ProjectsPage() {
  const { data: projects, error, reload } = useResource<Project[]>('projects')
  const [name, setName] = useState('')
  const [creating, setCreating] = useState(false)
  const action = useAction()
  return <main className={s.content}>
    <div className={s.pageHead}><h1>Проекты</h1><button className={s.primary} aria-expanded={creating} onClick={() => setCreating(!creating)}>
      <Plus size={16}/>Новый проект</button></div>
    {creating && <form className={s.createForm} onSubmit={e => { e.preventDefault(); void action.perform(async () => {
      const project = await request<Project>('projects', 'POST', { name: name.trim() })
      window.location.assign(projectUrl(project.id))
    }) }}>
      <label>Название проекта<input maxLength={100} autoFocus required placeholder="Например, проверка зависимостей" value={name}
        onChange={e => setName(e.target.value)}/></label>
      <button className={s.primary} disabled={action.busy || !name.trim()}>Создать</button>
      <button type="button" disabled={action.busy} onClick={() => setCreating(false)} aria-label="Закрыть форму"><X size={16}/></button>
      {action.error && <p role="alert" className={s.error}>{action.error}</p>}
    </form>}
    {error && <div role="alert" className={s.error}>{error} <button onClick={reload}>Повторить</button></div>}
    {!projects && !error && <p role="status">Загружаем проекты…</p>}
    {projects && <>{(['owner','editor'] as const).map(role => {
      const list = projects.filter(project => project.role === role)
      return <section key={role} className={s.section}><h2>{role === 'owner' ? 'Мои черновики' : 'Доступные мне'}</h2>
        {list.length ? <div className={s.projectList}>{list.map(project => <div key={project.id} className={s.projectRow}>
          <a href={projectUrl(project.id)} className={s.projectLink}>
            <span className={s.projectIcon}>{role === 'owner' ? <Folder size={21}/> : <UsersRound size={21}/>}</span>
            <span><strong>{project.name}</strong><small>Изменён {date.format(new Date(project.updated_at))}</small></span>
            <ArrowRight size={16}/></a>
          {role === 'owner' && <a className={s.accessLink} href={projectUrl(project.id) + '/access'} aria-label={'Доступ · ' + project.name}>
            <UsersRound size={16}/><span>Доступ</span></a>}
        </div>)}</div> : <div className={s.empty}>{role === 'owner'
          ? <>Пока нет личных проектов. Создайте черновик или <a href="/templates">выберите шаблон</a>.</>
          : 'Здесь появятся проекты, в которые вас пригласили.'}</div>}
      </section>
    })}</>}
  </main>
}

type Member = { id: string; email: string; name: string | null; role: 'owner' | 'editor'; status: 'active' | 'pending' }
type Invitation = { id: string; email: string; token: string; delivery: 'link' | 'sent' | 'failed' }

export function AccessPage({ id }: { id: string }) {
  const projects = useResource<Project[]>('projects')
  const project = projects.data?.find(item => item.id === id)
  const path = 'projects/' + encodeURIComponent(id) + '/members'
  const members = useResource<Member[]>(path)
  const [email, setEmail] = useState('')
  const [invitation, setInvitation] = useState<Invitation>()
  const [copied, setCopied] = useState(false)
  const [confirm, setConfirm] = useState('')
  const action = useAction()
  const owner = project?.role === 'owner'
  const url = invitation ? window.location.origin + '/#invite=' + encodeURIComponent(invitation.token) : ''
  async function invite(address: string) {
    const result = await request<Invitation>(path, 'POST', { email: address.trim() })
    setInvitation(result); setCopied(false); setEmail(''); setConfirm(''); members.reload()
  }
  return <main className={s.content}><a href={projectUrl(id)} className={s.back}>← {project?.name || 'К редактору'}</a>
    <div className={s.pageHead}><h1>Доступ к проекту</h1></div>
    {owner && <section className={s.panel}><h2>Пригласить редактора</h2>
      <form className={s.inviteForm} onSubmit={e => { e.preventDefault(); void action.perform(() => invite(email)) }}>
        <label>Электронная почта<input type="email" autoComplete="off" value={email} placeholder="name@example.com" required
          onChange={e => setEmail(e.target.value)}/></label>
        <button className={s.primary} disabled={action.busy || !email.trim()}>Пригласить</button>
      </form>
      {invitation && <div className={s.inviteResult}><p role="status">
        {invitation.delivery === 'sent' ? 'Приглашение отправлено на ' + invitation.email + '.'
          : invitation.delivery === 'failed' ? 'Не удалось отправить письмо. Передайте ссылку участнику ' + invitation.email + '.'
          : 'Передайте ссылку участнику ' + invitation.email + '.'}</p>
        <div className={s.inline}><input aria-label="Ссылка для приглашённого участника" value={url} readOnly onFocus={e => e.target.select()}/>
          <button onClick={() => void action.perform(async () => {
            if (!navigator.clipboard) throw new Error('Выделите и скопируйте ссылку из поля.')
            await navigator.clipboard.writeText(url); setCopied(true)
          })}>{copied ? <Check size={15}/> : <Copy size={15}/>} {copied ? 'Скопировано' : 'Копировать'}</button></div>
      </div>}
    </section>}
    {action.error && <p role="alert" className={s.error}>{action.error}</p>}
    <section className={s.section}><h2>Участники</h2>
      {projects.error && <p className={s.error} role="alert">{projects.error} <button onClick={projects.reload}>Повторить</button></p>}
      {members.error && <p className={s.error} role="alert">{members.error} <button onClick={members.reload}>Повторить</button></p>}
      {!members.data && !members.error && <p role="status">Загружаем участников…</p>}
      {members.data && <div className={s.projectList}>{members.data.map(member => <div key={member.id} className={s.member}>
        <span className={s.avatar}>{(member.name || member.email)[0]?.toUpperCase()}</span>
        <span className={s.memberName}><strong>{member.name || member.email}</strong>{member.name && <small>{member.email}</small>}</span>
        <span className={s.role}>{member.status === 'pending' ? 'Ожидает принятия' : member.role === 'owner' ? 'Владелец' : 'Редактор'}</span>
        {owner && member.role !== 'owner' && (confirm === member.id
          ? <div className={s.actions}><button className={s.danger} disabled={action.busy} onClick={() => void action.perform(async () => {
            await request<void>(path + '/' + encodeURIComponent(member.id), 'DELETE')
            if (invitation?.email === member.email) setInvitation(undefined)
            setConfirm(''); members.reload()
          })}>Подтвердить отзыв</button><button onClick={() => setConfirm('')}>Отмена</button></div>
          : <div className={s.actions}>
            {member.status === 'pending' && <button disabled={action.busy} onClick={() => void action.perform(() => invite(member.email))}>Новая ссылка</button>}
            <button className={s.danger} disabled={action.busy} onClick={() => setConfirm(member.id)}>Отозвать доступ</button>
          </div>)}
      </div>)}</div>}
    </section></main>
}

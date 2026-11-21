import { useId, useState } from 'react'
import { ArrowRight, Check, Copy, Folder, Plus, UsersRound, X } from 'lucide-react'
import { request } from './api'
import { accessLabel, projectUrl, roleNames, useAction, useResource, type Access, type Project, type SharedRole } from './workspaceData'
import s from './workspace.module.css'

const date = new Intl.DateTimeFormat('ru-RU', { dateStyle: 'medium', timeStyle: 'short' })

export function ProjectsPage() {
  const { data: projects, error, reload } = useResource<Project[]>('projects', 5000)
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
    {projects && <>{[true, false].map(owned => {
      const list = projects.filter(project => (project.role === 'owner') === owned)
      return <section key={String(owned)} className={s.section}><h2>{owned ? 'Мои черновики' : 'Доступные мне'}</h2>
        {list.length ? <div className={s.projectList}>{list.map(project => <div key={project.id} className={s.projectRow}>
          <a href={projectUrl(project.id)} className={s.projectLink}>
            <span className={s.projectIcon}>{owned ? <Folder size={21}/> : <UsersRound size={21}/>}</span>
            <span><strong>{project.name}</strong><small>{!owned && accessLabel(project) + ' · '}Изменён {date.format(new Date(project.updated_at))}</small></span>
            <ArrowRight size={16}/></a>
          {owned && <a className={s.accessLink} href={projectUrl(project.id) + '/access'} aria-label={'Доступ · ' + project.name}>
            <UsersRound size={16}/><span>Доступ</span></a>}
        </div>)}</div> : <div className={s.empty}>{owned
          ? <>Пока нет личных проектов. Создайте черновик или <a href="/templates">выберите шаблон</a>.</>
          : 'Здесь появятся проекты, в которые вас пригласили.'}</div>}
      </section>
    })}</>}
  </main>
}

type Member = Pick<Project, 'role' | 'can_run'> & { id: string; email: string; name: string | null; status: 'active' | 'pending' | 'expired'; invite_version?: string }
type Invitation = Access & { id: string; email: string; token: string; invite_version: string; delivery: 'link' | 'sent' | 'failed' }
const statuses = { expired: 'Срок приглашения истёк', pending: 'Ожидает принятия' }
const defaultAccess: Access = { role: 'viewer', can_run: false }
const roleHelp = {
  viewer: 'Видит граф, исходники и отчёты.',
  editor: 'Видит отчёты и может менять граф и исходники.',
  reporter: 'Видит историю проверок и готовые отчёты.',
}

function AccessFields({ value, change }: { value: Access; change: (access: Access) => void }) {
  const help = useId()
  return <>
    <div className={s.roleChoice}><label>Роль<select value={value.role} aria-describedby={help} onChange={e => {
      const role = e.target.value as SharedRole
      change({ role, can_run: role !== 'reporter' && value.can_run })
    }}>{(['viewer', 'editor', 'reporter'] as const).map(role => <option key={role} value={role}>{roleNames[role]}</option>)}</select></label>
      <small id={help}>{roleHelp[value.role]}</small></div>
    <label className={s.runPermission}><input type="checkbox" checked={value.can_run} disabled={value.role === 'reporter'}
      onChange={e => change({ ...value, can_run: e.target.checked })}/>Запускать проверки</label>
  </>
}

export function AccessPage({ project }: { project: Project }) {
  const id = project.id
  const path = 'projects/' + encodeURIComponent(id) + '/members'
  const members = useResource<Member[]>(path, 5000)
  const [email, setEmail] = useState('')
  const [invitation, setInvitation] = useState<Invitation>()
  const [copied, setCopied] = useState(false)
  const [confirm, setConfirm] = useState('')
  const [access, setAccess] = useState<Access>(defaultAccess)
  const [editing, setEditing] = useState<{ id: string; access: Access }>()
  const action = useAction()
  const owner = project.role === 'owner'
  const validLink = invitation && members.data?.some(member => member.id === invitation.id &&
    member.status === 'pending' && member.invite_version === invitation.invite_version)
  const url = validLink ? window.location.origin + '/#invite=' + encodeURIComponent(invitation.token) : ''
  async function invite(address: string, options: Access | { reissue_id: string }) {
    const result = await request<Invitation>(path, 'POST', { email: address.trim(), ...options })
    const added: Member = { id: result.id, email: result.email, name: null, role: result.role, can_run: result.can_run,
      status: 'pending', invite_version: result.invite_version }
    members.setData(current => [...(current ?? []).filter(member => member.id !== added.id), added])
    setInvitation(result); setCopied(false); setEmail(''); setAccess(defaultAccess); setConfirm(''); members.reload()
  }
  if (members.denied) return <main className={s.content}><a href="/projects" className={s.back}>← К проектам</a>
    <h1>Доступ к проекту</h1><p role="alert" className={s.error}>{members.error}</p></main>
  return <main className={s.content}><a href={projectUrl(id)} className={s.back}>← {project.name}</a>
    <div className={s.pageHead}><h1>Доступ к проекту</h1></div>
    {owner && <section className={s.panel}><h2>Пригласить участника</h2>
      <form className={s.inviteForm} onSubmit={e => { e.preventDefault(); void action.perform(() => invite(email, access)) }}>
        <label>Электронная почта<input type="email" autoComplete="off" value={email} placeholder="name@example.com" required
          onChange={e => setEmail(e.target.value)}/></label>
        <AccessFields value={access} change={setAccess}/>
        <button className={s.primary} disabled={action.busy || !email.trim()}>Пригласить</button>
      </form>
      {validLink && <div className={s.inviteResult}><p role="status">
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
      {members.error && <p className={s.error} role="alert">{members.error} <button onClick={members.reload}>Повторить</button></p>}
      {!members.data && !members.error && <p role="status">Загружаем участников…</p>}
      {members.data && <div className={s.projectList}>{members.data.map(member => {
        const assigned: Access | null = member.role === 'owner' ? null : { role: member.role, can_run: member.can_run }
        return <div key={member.id} className={s.member}>
        <span className={s.avatar}>{(member.name || member.email)[0]?.toUpperCase()}</span>
        <span className={s.memberName}><strong>{member.name || member.email}</strong>{member.name && <small>{member.email}</small>}</span>
        <span className={s.role}>{accessLabel(member)}{member.status !== 'active' && <small>{statuses[member.status]}</small>}</span>
        {owner && assigned && (editing?.id === member.id
          ? <form className={s.editAccess} onSubmit={e => { e.preventDefault(); void action.perform(async () => {
            await request<void>(path + '/' + encodeURIComponent(member.id), 'PATCH', editing.access)
            members.setData(rows => rows?.map(row => row.id === member.id ? { ...row, ...editing.access } : row))
            setEditing(undefined); members.reload()
          }) }}>
            <AccessFields value={editing.access} change={access => setEditing({ id: member.id, access })}/>
            <button className={s.primary} disabled={action.busy}>Сохранить права</button>
            <button type="button" onClick={() => setEditing(undefined)}>Отмена</button>
          </form> : confirm === member.id
          ? <div className={s.actions}><button className={s.danger} disabled={action.busy} onClick={() => void action.perform(async () => {
            await request<void>(path + '/' + encodeURIComponent(member.id), 'DELETE')
            members.setData(current => current?.filter(row => row.id !== member.id))
            if (invitation?.email === member.email) setInvitation(undefined)
            setConfirm(''); members.reload()
          })}>Подтвердить отзыв</button><button onClick={() => setConfirm('')}>Отмена</button></div>
          : <div className={s.actions}>
            <button disabled={action.busy} onClick={() => {
              setEditing({ id: member.id, access: assigned })
              setConfirm('')
            }}>Изменить права</button>
            {member.status !== 'active' && <button disabled={action.busy} onClick={() => void action.perform(() => invite(member.email, { reissue_id: member.id }))}>Новая ссылка</button>}
            <button className={s.danger} disabled={action.busy} onClick={() => setConfirm(member.id)}>Отозвать доступ</button>
          </div>)}
      </div>})}</div>}
    </section></main>
}

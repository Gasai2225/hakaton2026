import { useState } from 'react'
import { ArrowUpRight, GitFork, Layers3, Plus } from 'lucide-react'
import { request } from './api'
import { projectUrl, useAction, useResource, type Project } from './workspaceData'
import s from './workspace.module.css'

type TemplateCard = { id: string; name: string; description: string; author: string; curated: boolean; node_count: number }

function PublishForm({ onPublished, close }: { onPublished: () => void; close: () => void }) {
  const projects = useResource<Project[]>('projects')
  const owned = projects.data?.filter(project => project.role === 'owner')
  const [id, setId] = useState('')
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const action = useAction()
  return <form className={s.panel + ' ' + s.publish} onSubmit={e => { e.preventDefault(); void action.perform(async () => {
    await request<TemplateCard>('catalog', 'POST', { project_id: id, name: name.trim(), description: description.trim() })
    onPublished()
  }) }}><h2>Опубликовать шаблон</h2>
    <p className={s.note}>Участники Garden увидят настройки графа, описание и ваше имя. По шаблону можно будет создать свой проект.</p>
    {projects.error && <p role="alert" className={s.error}>{projects.error} <button type="button" onClick={projects.reload}>Повторить</button></p>}
    {owned?.length === 0 ? <p>Сначала <a href="/projects">создайте свой проект</a>.</p> : <>
      <label>Проект<select value={id} required onChange={e => {
        setId(e.target.value); setName(owned?.find(project => project.id === e.target.value)?.name || '')
      }}><option value="">Выберите проект</option>{owned?.map(project => <option key={project.id} value={project.id}>{project.name}</option>)}</select></label>
      <label>Название шаблона<input required maxLength={100} value={name} onChange={e => setName(e.target.value)}/></label>
      <label>Описание<textarea required maxLength={1500} value={description} onChange={e => setDescription(e.target.value)}
        placeholder="Что проверяет граф и когда его использовать"/></label></>}
    {action.error && <p role="alert" className={s.error}>{action.error}</p>}
    <div className={s.actions}><button className={s.primary} disabled={action.busy || !id || !name.trim() || !description.trim()}>Опубликовать</button>
      <button type="button" disabled={action.busy} onClick={close}>Отмена</button></div>
  </form>
}

export function CatalogPage() {
  const { data: catalog, error, reload } = useResource<TemplateCard[]>('catalog')
  const action = useAction()
  const [publishing, setPublishing] = useState(false)
  const [notice, setNotice] = useState('')
  return <main className={s.content}><div className={s.pageHead}><h1>Шаблоны</h1>
    <button className={s.primary} aria-expanded={publishing} onClick={() => { setPublishing(!publishing); setNotice('') }}>
      <Plus size={16}/>Опубликовать шаблон</button></div>
    {publishing && <PublishForm close={() => setPublishing(false)} onPublished={() => {
      setPublishing(false); reload(); setNotice('Шаблон опубликован в разделе «Сообщество».')
    }}/>}
    {notice && <p role="status" className={s.success}>{notice}</p>}
    {action.error && <p role="alert" className={s.error}>{action.error}</p>}
    {error && <p role="alert" className={s.error}>{error} <button onClick={reload}>Повторить</button></p>}
    {!catalog && !error && <p role="status">Загружаем шаблоны…</p>}
    {catalog && [true, false].map(curated => {
      const cards = catalog.filter(template => template.curated === curated)
      return <section className={s.section} key={String(curated)}><h2>{curated ? 'От команды Garden' : 'Сообщество'}</h2>
        {cards.length ? <div className={s.cards}>{cards.map(card => <article className={s.card} key={card.id}>
          <div className={s.cardMeta}><span className={s.cardIcon}>{curated ? <GitFork size={20}/> : <Layers3 size={20}/>}</span>
            <span>Блоков · {card.node_count}</span></div>
          <h3>{card.name}</h3><p>{card.description}</p>
          <footer><span>{card.author}</span><button disabled={action.busy} aria-label={'Создать проект · ' + card.name}
            onClick={() => void action.perform(async () => {
              const project = await request<{id: string}>('catalog/' + encodeURIComponent(card.id) + '/projects', 'POST')
              window.location.assign(projectUrl(project.id))
            })}>Создать проект <ArrowUpRight size={14}/></button></footer>
        </article>)}</div> : <p className={s.empty}>{curated ? 'Пока нет шаблонов команды.' : 'Первый шаблон сообщества можно опубликовать из своего проекта.'}</p>}
      </section>
    })}
  </main>
}

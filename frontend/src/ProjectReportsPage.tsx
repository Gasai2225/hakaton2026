import { Fragment, useState } from 'react'
import { ChevronDown, Download, FileText } from 'lucide-react'
import type { Run, Step, Summary } from './api'
import { labels } from './blocks'
import { FindingsTable } from './Results'
import { useResource, type Project } from './workspaceData'
import s from './workspace.module.css'
import studio from './studio.module.css'

type RunReport = {
  complete: boolean
  findings: NonNullable<Run['findings']>
  reviews: { label: string; report: NonNullable<Step['report']> }[]
}
const date = new Intl.DateTimeFormat('ru-RU', { dateStyle: 'medium', timeStyle: 'short' })

function ReportDetails({ id }: { id: string }) {
  const path = 'runs/' + encodeURIComponent(id)
  const { data, error, reload } = useResource<RunReport>(path + '/report')
  if (error) return <p className={s.error} role="alert">{error} <button onClick={reload}>Повторить</button></p>
  if (!data) return <p role="status">Загружаем отчёт…</p>
  const download = '/api/' + path + '/submission'
  return <section className={s.panel} aria-label="Отчёт о проверке">
    <div className={s.pageHead}><h3>Результаты проверки</h3>
      <div className={s.actions}><a className={s.button} href={download} download><Download size={14}/>Скачать JSON</a>
        <a className={s.button} href={download + '?format=html'} download><Download size={14}/>Скачать HTML</a></div></div>
    {!data.complete && <p className={s.note}>Проверка неполная.</p>}
    {data.findings.length ? <FindingsTable findings={data.findings}/> :
      <p>{data.complete ? 'Находок нет.' : 'В проверенной части находок нет.'}</p>}
    {data.reviews.length > 0 && <section className={s.section}><h3>Ответы моделей</h3><div className={studio.reviews}>
      {data.reviews.map((review, i) => <article key={i}><h3>{review.label}</h3>
        {review.report.groups.map((group, j) => <section key={j}><p>{group.risk}</p><p>{group.fix}</p></section>)}
      </article>)}
    </div></section>}
  </section>
}

export function ProjectReportsPage({ project }: { project: Project }) {
  const history = useResource<Summary[]>('projects/' + encodeURIComponent(project.id) + '/runs', 5000)
  const [expanded, setExpanded] = useState('')
  return <main className={s.content}><a href="/projects" className={s.back}>← Мои проекты</a>
    <div className={s.pageHead}><div><h1>Отчёты проекта</h1><p>{project.name}</p></div></div>
    {history.error && <p className={s.error} role="alert">{history.error} <button onClick={history.reload}>Повторить</button></p>}
    {!history.data && !history.error && <p role="status">Загружаем историю проверок…</p>}
    {history.data?.length === 0 && <p className={s.empty}>В этом проекте ещё не запускали проверки.</p>}
    {!!history.data?.length && <div className={s.projectList}><div className={studio.rows}>
      {history.data.map(run => <Fragment key={run.id}>
        <button className={studio.historyRow} aria-expanded={expanded === run.id}
          onClick={() => setExpanded(expanded === run.id ? '' : run.id)}>
          <FileText size={15}/><strong>{run.name}</strong><small>{date.format(new Date(run.started))}</small>
          <span>{labels[run.status]}</span><ChevronDown size={14}/>
        </button>
        {expanded === run.id && (run.status === 'running' || run.status === 'pending'
          ? <p className={s.note}>Отчёт появится после завершения проверки.</p> : <ReportDetails id={run.id}/>)}
      </Fragment>)}
    </div></div>}
  </main>
}

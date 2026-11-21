import { Fragment, useEffect, useState } from 'react'
import { ChevronDown, ExternalLink, GitBranch, History } from 'lucide-react'
import { message, request, type Run, type Summary } from './api'
import { eventNames, labels } from './blocks'
import s from './studio.module.css'

type CiRun = {
  id: number; number: number; attempt: number; event: keyof typeof eventNames; sha: string; branch: string
  started: string; status: string; conclusion: string | null; url: string
}
type CiFinding = {
  path: string; severity: string; description: string; remediation: string
} & ({ category: 'SECRET' | 'SAST'; class: string; line: number }
  | { category: 'SCA'; group: string; artifact: string; version: string; advisoryId: string | null })
type CiHistory = { runs: CiRun[]; error: string | null }
type CiReports = { reports: { name: string; findings: CiFinding[] }[]; artifact_url: string | null; error: string | null }

const ciStatus: Record<string, string> = {
  completed: 'Завершён', success: 'Успешно', failure: 'Ошибка', cancelled: 'Отменён', timed_out: 'Время истекло',
  skipped: 'Пропущен', neutral: 'Нейтрально', action_required: 'Требуется действие', stale: 'Устарел',
  queued: 'В очереди', in_progress: 'В работе', waiting: 'Ожидает', pending: 'Ожидает', requested: 'Запрошен',
}
const severity: Record<string, string> = { LOW: 'Низкая', MEDIUM: 'Средняя', HIGH: 'Высокая', CRITICAL: 'Критическая' }
const date = new Intl.DateTimeFormat('ru-RU', { dateStyle: 'short', timeStyle: 'medium' })

function useHistoryRequest<T>(path: string | null, interval = 0) {
  const [data, setData] = useState<T>()
  const [error, setError] = useState('')
  const [reload, setReload] = useState(0)
  useEffect(() => {
    if (path === null) return
    const url = path
    const controller = new AbortController()
    let timer: number | undefined
    async function load() {
      try {
        const result = await request<T>(url, 'GET', undefined, controller.signal)
        if (!controller.signal.aborted) { setData(result); setError('') }
      } catch (e) {
        if (!controller.signal.aborted) setError(message(e))
      }
      if (interval && !controller.signal.aborted) timer = window.setTimeout(load, interval)
    }
    void load()
    return () => { controller.abort(); window.clearTimeout(timer) }
  }, [path, interval, reload])
  return { data, error, retry: () => { setError(''); setReload(n => n + 1) } }
}

export function RunHistory({ projectId, openLocal, onLoaded }: { projectId?: string; openLocal: (run: Run) => void; onLoaded: () => void }) {
  const local = useHistoryRequest<Summary[]>(projectId ? 'projects/' + projectId + '/runs' : 'runs', 5000)
  const ci = useHistoryRequest<CiHistory>(projectId ? null : 'ci/history', 30000)
  const [selected, setSelected] = useState('')
  const loaded = Boolean(local.data || ci.data || (local.error && (projectId || ci.error)))
  useEffect(() => { if (loaded) onLoaded() }, [loaded, onLoaded])
  const rows = [
    ...(local.data ?? []).map(run => ({ kind: 'local' as const, key: 'local-' + run.id, run })),
    ...(ci.data?.runs ?? []).map(run => ({ kind: 'github' as const, key: 'github-' + run.id, run })),
  ].sort((a, b) => Date.parse(b.run.started) - Date.parse(a.run.started))
  const ciError = ci.error || ci.data?.error
  return <div className={s.rows}>
    {local.error ? <LoadError text={'Локальная история · ' + local.error} retry={local.retry} />
      : !local.data && <p className={s.historyNote} role="status">Загружаем локальные прогоны…</p>}
    {projectId ? null : ciError ? <LoadError text={'GitHub Actions · ' + ciError} retry={ci.retry} />
      : !ci.data ? <p className={s.historyNote} role="status">Загружаем историю GitHub Actions…</p>
      : !ci.data.runs.length && <p className={s.historyNote}>В GitHub Actions пока нет проверок push или pull request.</p>}
    {local.data?.length === 0 && !local.error && <p className={s.historyNote}>{projectId ? 'У проекта пока нет прогонов.' : 'Локальных прогонов пока нет.'}</p>}
    {rows.map(item => {
      const expanded = selected === item.key
      const state = item.kind === 'github' ? item.run.conclusion ?? item.run.status : item.run.status
      const event = item.kind === 'github' ? { name: item.run.event, sha: item.run.sha } : item.run.git_event
      return <Fragment key={item.key}>
        <button className={s.historyRow} aria-expanded={expanded} onClick={() => setSelected(expanded ? '' : item.key)}>
          {item.kind === 'github' ? <GitBranch size={15}/> : <History size={15}/>}
          <strong>{item.kind === 'github' ? 'GitHub Actions #' + item.run.number : item.run.name}</strong>
          {item.kind === 'local' && <span>{projectId ? 'Проект' : 'Локально'}</span>}
          {event && <><span>{eventNames[event.name]}</span>
            {item.kind === 'github' && <span>{item.run.branch}</span>}<code title={event.sha}>{event.sha.slice(0, 12)}</code></>}
          <small>{date.format(new Date(item.run.started))}</small>
          <span data-state={state}>{item.kind === 'github' ? ciStatus[state] ?? state : labels[item.run.status]}</span>
          {item.kind === 'github' && <ChevronDown size={13} aria-hidden="true"/>}
        </button>
        {expanded && (item.kind === 'local' ? <LocalDetails id={item.run.id} open={openLocal} />
          : <div className={s.ciDetails}><div className={s.ciLinks}>
            <a href={item.run.url} target="_blank" rel="noreferrer">Открыть в GitHub Actions <ExternalLink size={13}/></a>
            {item.run.attempt > 1 && <span>Попытка {item.run.attempt}</span>}</div>
            {item.run.status === 'completed' ? <ProjectReports key={item.run.attempt} run={item.run} />
              : <p className={s.historyNote} role="status">Ожидаем завершения проверки.</p>}
          </div>)}
      </Fragment>
    })}
  </div>
}

function LoadError({ text, retry }: { text: string; retry: () => void }) {
  return <div className={s.historyNote} role="alert">{text} <button onClick={retry}>Повторить</button></div>
}

function LocalDetails({ id, open }: { id: string; open: (run: Run) => void }) {
  const { data, error, retry } = useHistoryRequest<Run>('runs/' + id)
  useEffect(() => { if (data) open(data) }, [data, open])
  return error ? <LoadError text={error} retry={retry} /> : <p className={s.historyNote} role="status">Открываем прогон…</p>
}

function ProjectReports({ run }: { run: CiRun }) {
  const { data, error, retry } = useHistoryRequest<CiReports>('ci/history/' + run.id + '/reports?attempt=' + run.attempt)
  const reportError = error || data?.error
  return <>
    {reportError && <LoadError text={reportError} retry={retry} />}
    {!data && !error && <p className={s.historyNote} role="status">Загружаем отчёты по проектам…</p>}
    {data?.artifact_url && <div className={s.ciLinks}><a href={data.artifact_url} target="_blank" rel="noreferrer">
      Артефакт с отчётами <ExternalLink size={13}/></a></div>}
    {data && !data.reports.length && !reportError && <p className={s.historyNote}>Для этого прогона нет отчётов по проектам.</p>}
    {data?.reports.map((project, index) => <section key={index + '-' + project.name} className={s.lockReport}>
      <h3>{project.name} · Находки {project.findings.length}</h3>
      {project.findings.length > 0 && <table aria-label={'Находки · ' + project.name}><thead><tr>
        <th>Категория</th><th>Находка</th><th>Класс или зависимость и место</th><th>Исправление</th><th>Критичность</th>
      </tr></thead><tbody>{project.findings.map((f, i) => <tr key={i}>
        <td>{f.category}</td><td>{f.description}</td><td>{f.category === 'SCA'
          ? <><code>{[f.group, f.artifact, f.version].join(':')}</code> {f.advisoryId}<small>{f.path}</small></>
          : <><code>{f.class}</code><small>{f.path}:{f.line}</small></>}</td>
        <td>{f.remediation}</td><td>{severity[f.severity] ?? f.severity}</td>
      </tr>)}</tbody></table>}
    </section>)}
  </>
}

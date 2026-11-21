import { useCallback, useRef } from 'react'
import { Activity, CircleDot, Download, FileWarning, History, ListTree } from 'lucide-react'
import { blocks, eventNames, labels } from './blocks'
import type { Run, Step } from './api'
import { RunHistory } from './RunHistory'
import s from './studio.module.css'

export type Tab = 'findings' | 'packages' | 'lockfile' | 'reviews' | 'steps' | 'history'
type Findings = NonNullable<Run['findings']>
const severity = { low: 'Низкая', medium: 'Средняя', high: 'Высокая', critical: 'Критическая' }
const osvStatus = { checked: 'Сверено по версии', incomplete: 'Проверка неполная', skipped: 'Нет точной версии' }
const time = (value: string) => new Date(value).toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'medium' })

export function FindingSource({ finding }: { finding: Findings[number] }) {
  const { category, dependency, classification, rule, path, line, column, advisory, advisory_url } = finding
  return <>
    {category === 'SCA' ? <>
      <code>{dependency ? [dependency.group, dependency.artifact, dependency.version].join(':') : finding.title}</code>
      {advisory && <div>{advisory_url ? <a href={advisory_url} target="_blank" rel="noreferrer">{advisory}</a> : advisory}</div>}
    </> : <code>{classification ?? (rule === 'SPRING-OPEN-DEFAULT' ? 'route-authorization' : rule)}</code>}
    <div><code>{path}:{line}:{column}</code></div>
  </>
}

export function FindingsTable({ findings, reviews }: {
  findings: Findings; reviews?: { has: (id: string) => boolean; open: () => void }
}) {
  return <div className={s.lockReport}><table aria-label="Находки"><thead><tr>
    <th>Категория</th><th>Находка</th><th>Класс или зависимость и место</th><th>Исправление</th><th>Критичность</th>
  </tr></thead><tbody>{findings.map(f => <tr key={f.id}>
    <td>{f.category}</td><td><strong>{f.title}</strong><small>{f.rule}</small></td>
    <td><FindingSource finding={f} /></td><td>{f.fix}
      {reviews?.has(f.id) && <div><button className={s.reviewLink} onClick={reviews.open}>Посмотреть ответы моделей</button></div>}
    </td><td>{severity[f.severity]}{f.severity_estimated && <small>Оценка анализатора</small>}</td>
  </tr>)}</tbody></table></div>
}

export function StepFindings({ step, findings }: { step: Step; findings: Findings }) {
  const byId = new Map(findings.map(f => [f.id, f]))
  return <>
    {step.branch && <p>Выбрана ветка «{step.branch === 'yes' ? 'Да' : 'Нет'}»</p>}
    {(['input_ids', 'output_ids'] as const).map(field => {
      const ids = step[field] ?? []
      return <div key={field}><strong>{field === 'input_ids' ? 'На входе' : 'На выходе'} · {ids.length}</strong>
        {ids.map(id => {
          const finding = byId.get(id)
          return finding && <div key={id}><small>{finding.category} · {finding.rule}</small><div><FindingSource finding={finding} /></div></div>
        })}
      </div>
    })}
  </>
}

export function Results({ run, projectId, tab, setTab, open, inspectWebhook }: {
  projectId?: string
  run: Run | null; tab: Tab; setTab: (tab: Tab) => void; open: (run: Run) => void
  inspectWebhook: (runId: string, nodeId: string) => void
}) {
  const section = useRef<HTMLElement>(null)
  const scrollToHistory = useRef(tab === 'history')
  const historyLoaded = useCallback(() => {
    if (scrollToHistory.current) {
      scrollToHistory.current = false
      section.current?.scrollIntoView({ block: 'start' })
    }
  }, [])
  const findings = run?.findings ?? []
  const direct = (run?.steps ?? []).filter(step => step.packages?.length)
  const locks = (run?.steps ?? []).filter(step => step.lockfile)
  const reviews = (run?.steps ?? []).flatMap(step => (step.reviews?.length ? step.reviews :
    step.report ? [{ label: 'Модель', connection: '', model: '', report: step.report, status: step.status, message: step.message }] : [])
    .map(r => ({ ...r, node: step.node_id })))
  return <section ref={section} className={s.results}>
    <div className={s.tabs}>
      <button data-active={tab === 'findings'} onClick={() => setTab('findings')}><CircleDot size={15} />Находки <b>{findings.length}</b></button>
      {direct.length > 0 && <button data-active={tab === 'packages'} onClick={() => setTab('packages')}>Прямые зависимости</button>}
      {locks.length > 0 && <button data-active={tab === 'lockfile'} onClick={() => setTab('lockfile')}>Транзитивные зависимости</button>}
      <button data-active={tab === 'reviews'} onClick={() => setTab('reviews')}>Ответы моделей <b>{reviews.length}</b></button>
      <button data-active={tab === 'steps'} onClick={() => setTab('steps')}><ListTree size={15} />Ход прогона</button>
      <button data-active={tab === 'history'} onClick={() => setTab('history')}><History size={15} />История</button>
    </div>
    {tab === 'history' ? <RunHistory projectId={projectId} openLocal={open} onLoaded={historyLoaded} />
      : !run ? <Empty title="Пока нет результатов" text="Запустите сценарий, чтобы увидеть результаты проверки." />
      : <>
        <div className={s.runMeta}><Activity size={13}/>{run.name} · {time(run.started)} · {labels[run.status]}
          {run.git_event && <code>{eventNames[run.git_event.name]} · {run.git_event.sha}</code>}
          {run.status !== 'running' && <a href={'/api/runs/' + run.id + '/submission'} download><Download size={13}/>Скачать JSON</a>}</div>
        {tab === 'packages' && direct.length ? direct.map(step =>
          <DirectResults key={step.node_id} step={step} showNode={direct.length > 1} />)
        : tab === 'lockfile' && locks.length ? locks.map(step =>
          <LockResults key={step.node_id} report={step.lockfile!} />)
        : tab === 'reviews' ? (reviews.length ? <div className={s.reviews}>{reviews.map(r =>
          <article key={[r.node,r.connection,r.model].join('/')}><h3>{r.label} {r.model}</h3>
            <span className={s.status} data-state={r.status}>{labels[r.status]}</span>{r.message && <p>{r.message}</p>}
            {r.report?.groups.map((g, i) => <section key={i} className={s.advice}><strong>Риск</strong><p>{g.risk}</p>
              <strong>Исправление</strong><p>{g.fix}</p><details><summary>Находки · {g.finding_ids.length}</summary>
                {g.finding_ids.map(id => { const f = findings.find(f => f.id === id)
                  return f && <p key={id}><code>{f.rule} · {f.path}:{f.line}:{f.column}</code></p> })}</details></section>)}
          </article>)}</div> : <Empty title="Пока нет ответов моделей" text="Ответы появятся при выполнении блока «AI-объяснение»."/>)
        : tab === 'steps' ? <div className={s.rows}>{run.steps.map(step => <div className={s.stepRow} key={step.node_id}>
          <span className={s.status} data-state={step.status}>{labels[step.status]}</span><strong>{blocks[step.kind].name}</strong>
          <span>{step.message}</span>
          {step.kind === 'webhook' && <button onClick={() => inspectWebhook(run.id, step.node_id)}>
            Открыть отправку · {step.node_id}</button>}
          <details><summary>Вход {step.input_ids?.length ?? 0} · выход {step.output_ids?.length ?? 0}</summary>
            <StepFindings step={step} findings={findings} />
          </details></div>)}</div>
          : findings.length ? <FindingsTable findings={findings} reviews={{
            has: id => reviews.some(r => r.report?.groups.some(g => g.finding_ids.includes(id))),
            open: () => setTab('reviews'),
          }}/>
          : <Empty title={run.status === 'running' ? 'Проверка выполняется' : run.status === 'failed' ? 'Проверка прервана' : 'Находок нет'}
            text={run.status === 'failed' ? 'Причина указана во вкладке «Ход прогона».' : 'Подробности доступны в ходе прогона.'} />}
      </>}
  </section>
}

function DirectResults({ step, showNode }: { step: Step; showNode: boolean }) {
  const packages = step.packages ?? []
  const online = packages.some(p => p.osv_status)
  return <div className={s.lockReport}>
    {showNode && <strong>{step.node_id}</strong>}
    <table><thead><tr><th>Пакет Maven</th><th>Версия</th><th>Источник версии</th><th>Локальный справочник</th>
      {online && <th>OSV</th>}</tr></thead><tbody>{packages.map((p, i) => <tr key={i}>
      <td><code>{p.package}</code><small>{p.path}:{p.line}</small></td><td>{p.version ?? '—'}</td>
      <td>{p.source === 'declaration' ? 'build.gradle.kts' : p.source === 'unknown' ? '—' : p.source}</td>
      <td>{{ checked: 'Проверено', 'outside-catalog': 'Вне справочника', unresolved: 'Версия не определена' }[p.status]}</td>
      {online && <td>{p.osv_status ? osvStatus[p.osv_status] : '—'}</td>}
    </tr>)}</tbody></table>
  </div>
}

function LockResults({ report }: { report: NonNullable<Step['lockfile']> }) {
  const packages = report.packages ?? []
  const checked = packages.filter(p => p.status === 'checked' || p.osv_status === 'checked').length
  const online = packages.some(p => p.osv_status)
  const count = packages.reduce((total, p) => total + (p.advisories?.length ?? 0), 0)
  return <div className={s.lockReport}>
    <strong>Проверено {checked} из {packages.length} · совпадений с бюллетенями {count}</strong>
    {report.issues?.map(issue => <p key={issue}>{issue}</p>)}
    {packages.length > 0 ? <table><thead><tr>
      <th>Пакет Maven</th><th>Версия</th><th>Конфигурация Gradle</th><th>Результат</th>{online && <th>OSV</th>}
    </tr></thead><tbody>{packages.map(p => <tr key={[p.path, p.package, p.version].join('|')}>
      <td><code>{p.package}</code><small>{p.path}:{p.line}{p.scope === 'unclassified' && ' · тип зависимости не определён'}</small></td>
      <td>{p.version}</td><td>{p.configurations.join(', ')}</td>
      <td>{p.advisories?.length ? p.advisories.map(a => <div key={a.id}>
        {a.advisory_url ? <a href={a.advisory_url} target="_blank" rel="noreferrer">{a.id}</a> : a.id} · {severity[a.severity]}
        {a.severity_estimated && ' · оценка анализатора'}</div>)
        : p.osv_status === 'checked' ? 'Совпадений нет' : p.status === 'outside-catalog' ? 'Вне справочника'
        : p.status === 'unresolved' ? 'Версия не распознана' : 'В локальном справочнике совпадений нет'}</td>
      {online && <td>{p.osv_status ? osvStatus[p.osv_status] : '—'}</td>}
    </tr>)}</tbody></table> : <p>Дополнительных пакетов в lockfile нет.</p>}
  </div>
}

function Empty({ title, text }: { title: string; text: string }) {
  return <div className={s.empty}><FileWarning size={22} strokeWidth={1.4}/><div><strong>{title}</strong><p>{text}</p></div></div>
}

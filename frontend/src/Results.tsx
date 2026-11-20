import { Activity, CircleDot, Download, FileWarning, History, ListTree } from 'lucide-react'
import { blocks, labels } from './blocks'
import type { Run, Step, Summary } from './api'
import s from './studio.module.css'

export type Tab = 'findings' | 'lockfile' | 'reviews' | 'steps' | 'history'
const severity = { low: 'Низкая', medium: 'Средняя', high: 'Высокая', critical: 'Критическая' }
const time = (value: string) => new Date(value).toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'medium' })

export function Results({ run, history, tab, setTab, open }: {
  run: Run | null; history: Summary[]; tab: Tab; setTab: (tab: Tab) => void; open: (key: string) => void
}) {
  const findings = run?.findings ?? []
  const locks = (run?.steps ?? []).filter(step => step.lockfile)
  const reviews = (run?.steps ?? []).flatMap(step => (step.reviews?.length ? step.reviews :
    step.report ? [{ label: 'Модель', connection: '', model: '', report: step.report, status: step.status, message: step.message }] : [])
    .map(r => ({ ...r, node: step.node_id })))
  return <section className={s.results}>
    <div className={s.tabs}>
      <button data-active={tab === 'findings'} onClick={() => setTab('findings')}><CircleDot size={15} />Находки <b>{findings.length}</b></button>
      {locks.length > 0 && <button data-active={tab === 'lockfile'} onClick={() => setTab('lockfile')}>Транзитивные зависимости</button>}
      <button data-active={tab === 'reviews'} onClick={() => setTab('reviews')}>Ответы моделей <b>{reviews.length}</b></button>
      <button data-active={tab === 'steps'} onClick={() => setTab('steps')}><ListTree size={15} />Ход прогона</button>
      <button data-active={tab === 'history'} onClick={() => setTab('history')}><History size={15} />История</button>
    </div>
    {tab === 'history' ? (history.length ? <div className={s.rows}>{history.map(item =>
      <button className={s.historyRow} key={item.id} onClick={() => open(item.id)}><History size={15} /><strong>{item.name}</strong>
        <small>{time(item.started)}</small><span data-state={item.status}>{labels[item.status]}</span></button>)}</div>
      : <Empty title="История пока пуста" text="Здесь появятся ручные и запланированные прогоны." />)
      : !run ? <Empty title="Пока нет результатов" text="Запустите сценарий, чтобы увидеть результаты проверки." />
      : <>
        <div className={s.runMeta}><Activity size={13}/>{run.name} · {time(run.started)} · {labels[run.status]}
          {run.status !== 'running' && <a href={'/api/runs/' + run.id + '/submission'} download><Download size={13}/>Скачать JSON</a>}</div>
        {tab === 'lockfile' && locks.length ? locks.map(step =>
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
          <span>{step.message}</span><details><summary>Вход {step.input_ids?.length ?? 0} · выход {step.output_ids?.length ?? 0}</summary>
            {(['input_ids', 'output_ids'] as const).map((field, i) => <div key={field}><b>{i ? 'На выходе' : 'На входе'}</b>
              {(step[field] ?? []).length ? findings.filter(f => step[field]?.includes(f.id)).map(f =>
                <p key={f.id}><code>{f.rule} · {f.path}:{f.line}:{f.column}</code></p>) : <p>Список находок пуст</p>}</div>)}
          </details></div>)}</div>
          : findings.length ? <div className={s.rows}>{findings.map(f => <article key={f.id} className={s.finding}>
            <div><span className={s.severity}>{severity[f.severity]}</span>
              <code>{f.category} · {f.classification ?? f.rule}</code></div><strong>{f.title}</strong>
            <code>{f.path} · строка {f.line}, столбец {f.column}</code><p>{f.fix}</p>
            {reviews.some(r => r.report?.groups.some(g => g.finding_ids.includes(f.id))) &&
              <button className={s.reviewLink} onClick={() => setTab('reviews')}>Посмотреть ответы моделей</button>}
          </article>)}</div>
          : <Empty title={run.status === 'running' ? 'Проверка выполняется' : run.status === 'failed' ? 'Проверка прервана' : 'Находок нет'}
            text={run.status === 'failed' ? 'Причина указана во вкладке «Ход прогона».' : 'Подробности доступны в ходе прогона.'} />}
      </>}
  </section>
}

function LockResults({ report }: { report: NonNullable<Step['lockfile']> }) {
  const packages = report.packages ?? []
  const checked = packages.filter(p => p.status === 'checked').length
  const count = packages.reduce((total, p) => total + (p.advisories?.length ?? 0), 0)
  return <div className={s.lockReport}>
    <strong>Проверено {checked} из {packages.length} · совпадений с бюллетенями {count}</strong>
    {report.issues?.map(issue => <p key={issue}>{issue}</p>)}
    {packages.length > 0 ? <table><thead><tr>
      <th>Пакет Maven</th><th>Версия</th><th>Конфигурация Gradle</th><th>Результат</th>
    </tr></thead><tbody>{packages.map(p => <tr key={[p.path, p.package, p.version].join('|')}>
      <td><code>{p.package}</code><small>{p.path}:{p.line}{p.scope === 'unclassified' && ' · тип зависимости не определён'}</small></td>
      <td>{p.version}</td><td>{p.configurations.join(', ')}</td>
      <td>{p.status === 'outside-catalog' ? 'Вне справочника' : p.status === 'unresolved' ? 'Версия не распознана' :
        p.advisories?.length ? p.advisories.map(a => <div key={a.id}>{a.id} · {severity[a.severity]}</div>) : 'Совпадений нет'}</td>
    </tr>)}</tbody></table> : <p>Дополнительных пакетов в lockfile нет.</p>}
  </div>
}

function Empty({ title, text }: { title: string; text: string }) {
  return <div className={s.empty}><FileWarning size={22} strokeWidth={1.4}/><div><strong>{title}</strong><p>{text}</p></div></div>
}

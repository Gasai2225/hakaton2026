import { useEffect, useState } from 'react'
import { message, request, type Delivery } from './api'
import { labels } from './blocks'
import { reportHref } from './browserReportLinks'
import { FindingSource, severity } from './Results'
import s from './workspace.module.css'

const deliveryStates: Record<Delivery['state'], string> = {
  pending: 'Ожидание отправки',
  attempted: 'Попытка отправки',
  delivered: 'Доставка подтверждена',
  not_sent: 'Отправки не было',
  unknown: 'Статус отправки неизвестен',
}

export default function WebhookDelivery({ runId, nodeId }: { runId: string; nodeId: string }) {
  const [delivery, setDelivery] = useState<Delivery>()
  const [error, setError] = useState('')
  const [retry, setRetry] = useState(0)
  useEffect(() => {
    const controller = new AbortController()
    const path = 'runs/' + encodeURIComponent(runId) + '/steps/' + encodeURIComponent(nodeId) + '/delivery'
    request<Delivery>(path, 'GET', undefined, controller.signal)
      .then(result => { if (!controller.signal.aborted) setDelivery(result) })
      .catch(e => { if (!controller.signal.aborted) setError(message(e)) })
    return () => controller.abort()
  }, [runId, nodeId, retry])

  if (error) return <div role="alert"><p>Не удалось загрузить отправку. {error}</p>
    <button onClick={() => { setError(''); setRetry(n => n + 1) }}>Повторить</button></div>
  if (!delivery) return <p role="status">Загрузка отправки…</p>
  const { state, payload } = delivery
  if (!payload) return <div><strong>{deliveryStates[state]}</strong>
    {['delivered', 'attempted', 'unknown'].includes(state) && <p>Отчёт отсутствует в истории шага.</p>}</div>

  return <section aria-label="Отчёт уведомления">
    <strong>{deliveryStates[state]}</strong>
    {delivery.browser_report && <p><a href={reportHref(runId, nodeId)}>Открыть отчёт</a></p>}
    <ReceiptDetails payload={payload}/>
  </section>
}

function ReceiptDetails({ payload }: { payload: NonNullable<Delivery['payload']> }) {
  const findings = new Map(payload.findings.map(f => [f.id, f]))
  const reviews = payload.reviews ?? []
  const withReport = reviews.filter(r => r.report)
  return <>
    <details><summary>Находки · {findings.size}</summary>
      {payload.findings.map(f => <article key={f.id} className={s.reportFinding}>
        <strong>{f.title}</strong><br/><small>{severity[f.severity]} · {f.category}</small>
        <FindingSource finding={f}/><p>{f.fix}</p>
      </article>)}
    </details>
    <p>Отчёты моделей · {payload.reports.length}</p>
    {payload.reports.map((report, i) => {
      const review = withReport[i]
      const model = review && JSON.stringify(review.report) === JSON.stringify(report) ? [review.label, review.model].filter(Boolean).join(' · ') : ''
      return <details key={i} open={payload.reports.length === 1 && report.groups.length === 1}>
        <summary>{model || 'Отчёт ' + (i + 1)} · групп {report.groups.length}</summary>
        {report.groups.map((group, j) => <section key={j}>
          <p><b>Риск</b> {group.risk}</p><p><b>Исправление</b> {group.fix}</p>
          {group.finding_ids.map(id => {
            const finding = findings.get(id)
            return <div key={id}><code>{id}</code>
              {finding && <div><b>{finding.title}</b><div><FindingSource finding={finding} /></div></div>}</div>
          })}
        </section>)}
      </details>
    })}
    {reviews.filter(r => !r.report).map((r, i) => <p key={i}>{r.label} · {r.model} · {labels[r.status]}
      {r.message && <small> · {r.message}</small>}</p>)}
  </>
}

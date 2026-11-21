import { useState } from 'react'
import type { Delivery } from './api'
import { reportHref, reportPath } from './browserReportLinks'
import { FindingSource, severity } from './Results'
import { useResource } from './workspaceData'
import s from './workspace.module.css'

type BrowserReport = {
  name: string
  created_at: string
  payload: NonNullable<Delivery['payload']>
}

const levels = ['critical', 'high', 'medium', 'low'] as const
const levelNames = { critical: 'Критические', high: 'Высокие', medium: 'Средние', low: 'Низкие' }
const analysisStatus = {
  complete: 'Проверка завершена',
  partial: 'Проверка неполная',
  not_run: 'Анализ исходников не запускался',
}
const reportDate = new Intl.DateTimeFormat('ru-RU', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'Europe/Moscow' })

export function ReportPreview({ name, created_at, payload }: BrowserReport) {
  const findings = [...payload.findings].sort((a, b) => levels.indexOf(a.severity) - levels.indexOf(b.severity))
  const numbers = new Map(findings.map((finding, index) => [finding.id, index + 1]))
  const counts = { critical: 0, high: 0, medium: 0, low: 0 }
  for (const finding of findings) counts[finding.severity]++
  const reviews = payload.reviews ?? []
  const withReport = reviews.filter(review => review.report)
  const failedReviews = reviews.filter(review => review.status === 'failed')
  const status = payload.analysis_status ? analysisStatus[payload.analysis_status] : 'Статус проверки неизвестен'

  return <>
    <section className={s.reportSummary} aria-labelledby="report-name">
      <h2 id="report-name">{name}</h2>
      <p className={s.reportMeta}><time dateTime={created_at}>{reportDate.format(new Date(created_at))} МСК</time>
        <span>{status}</span></p>
      {failedReviews.map((review, index) => <p className={s.error} key={index}>
        <strong>Ошибка модели {[review.label || review.connection, review.model].filter(Boolean).join(' · ')}</strong>
        {review.message && <> — {review.message}</>}
      </p>)}
      <dl className={s.reportMetrics} aria-label="Критичность находок">
        <div><dt>Всего</dt><dd>{findings.length}</dd></div>
        {levels.map(level => <div key={level} data-severity={level}><dt>{levelNames[level]}</dt><dd>{counts[level]}</dd></div>)}
      </dl>
    </section>
    <section className={s.section} aria-labelledby="report-findings">
      <h2 id="report-findings">Находки</h2>
      {findings.length ? <ol className={s.reportItems}>{findings.map((finding, index) =>
        <li className={s.reportCard} key={finding.id}>
          <div className={s.reportCardHead}>
            <h3>{index + 1}. {finding.title}</h3>
            <span className={s.reportSeverity} data-severity={finding.severity}>{severity[finding.severity]}</span>
          </div>
          <div className={s.reportSource}>
            <small>{finding.category}{finding.severity_estimated && ' · Оценка анализатора'}</small>
            <FindingSource finding={finding}/>
          </div>
          <p className={s.reportText}><strong>Исправление</strong>{'\n'}{finding.fix}</p>
        </li>)}</ol>
        : <p className={s.empty}>{payload.analysis_status === 'complete' ? 'Находок нет.' : 'Зарегистрированных находок нет.'}</p>}
    </section>
    {!!payload.reports.length && <section className={s.section} aria-labelledby="report-recommendations">
      <h2 id="report-recommendations">Рекомендации моделей</h2>
      <div className={s.reportItems}>{payload.reports.map((report, index) => {
        const review = withReport[index]
        const name = review && JSON.stringify(review.report) === JSON.stringify(report)
          ? [review.label, review.model].filter(Boolean).join(' · ') : ''
        return <article className={s.reportCard} key={index}>
          <h3>{name || 'Модель ' + (index + 1)}</h3>
          {report.groups.map((group, groupIndex) => {
            const references = group.finding_ids.flatMap(id => numbers.get(id) ?? []).join(', ')
            return <div className={s.reportAdvice} key={groupIndex}>
              {references && <small>Находки № {references}</small>}
              <p className={s.reportText}><strong>Риск</strong>{'\n'}{group.risk}</p>
              <p className={s.reportText}><strong>Исправление</strong>{'\n'}{group.fix}</p>
            </div>
          })}
        </article>
      })}</div>
    </section>}
  </>
}

export default function BrowserReportPage({ runId, nodeId, local = false }: { runId: string; nodeId: string; local?: boolean }) {
  const path = reportPath(runId, nodeId)
  const { data, error } = useResource<BrowserReport>(path)
  const [copyState, setCopyState] = useState<'copied' | 'manual'>()
  const shareUrl = new URL(reportHref(runId, nodeId), window.location.origin).href

  async function copyLink() {
    try {
      await navigator.clipboard.writeText(shareUrl)
      setCopyState('copied')
    } catch {
      setCopyState('manual')
    }
  }

  return <main className={s.content}>
    <a className={s.back} href={local ? '/local' : '/projects'}>{local ? '← Локальный редактор' : '← Мои проекты'}</a>
    <div className={s.pageHead}>
      <h1>Отчёт о проверке</h1>
      {data && <div className={s.actions}>
        <a className={s.button + ' ' + s.primary} href={'/api/' + path + '.pdf'} download>Скачать PDF</a>
        <a className={s.button} href={'/api/' + path + '.json'} download={`garden-report-${runId}-${nodeId}.json`}>Скачать JSON</a>
        {!local && <button className={s.button} type="button" onClick={() => void copyLink()}>Скопировать ссылку</button>}
        {copyState === 'copied' && <span role="status">Ссылка скопирована</span>}
      </div>}
    </div>
    {copyState === 'manual' && <label>Скопируйте ссылку на отчёт
      <input value={shareUrl} readOnly onFocus={event => event.currentTarget.select()}/>
    </label>}
    {error && <p className={s.error} role="alert">{error}{' '}
      <button type="button" onClick={() => window.location.reload()}>Повторить</button>
    </p>}
    {!data && !error && <p role="status">Загружаем отчёт…</p>}
    {data && <ReportPreview {...data}/>}
  </main>
}

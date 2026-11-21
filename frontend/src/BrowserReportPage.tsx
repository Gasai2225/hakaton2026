import type { Delivery } from './api'
import { type BrowserReportNotice } from './BrowserNotification'
import { formatReportTime } from './browserReportLinks'
import { ReceiptDetails } from './WebhookDelivery'
import { projectUrl, useResource } from './workspaceData'
import s from './workspace.module.css'

type BrowserReport = BrowserReportNotice & { payload: NonNullable<Delivery['payload']> }
const analysisStatus = { complete: 'Проверка завершена', partial: 'Проверка неполная', not_run: 'Анализ исходников не запускался' }

export default function BrowserReportPage({ runId, nodeId }: { runId: string; nodeId: string }) {
  const resource = useResource<BrowserReport>('runs/' + encodeURIComponent(runId) + '/steps/' + encodeURIComponent(nodeId) + '/report')
  const report = resource.data
  return <main className={s.content}>
    {resource.error && <div role="alert" className={s.error}>{resource.error}{' '}<button onClick={resource.reload}>Повторить</button></div>}
    {!report && !resource.error && <p role="status">Загружаем отчёт…</p>}
    {report && <article className={s.panel + ' ' + s.reportPage}>
      <p className={s.note}>Отчёт создан <time dateTime={report.created_at}>{formatReportTime(report.created_at)}</time></p>
      <h1>{report.name}</h1>
      {report.payload.analysis_status && <p>{analysisStatus[report.payload.analysis_status]}</p>}
      <ReceiptDetails payload={report.payload} openFindings />
      <a href={report.project_id ? projectUrl(report.project_id) : '/local'}>Вернуться в редактор</a>
    </article>}
  </main>
}

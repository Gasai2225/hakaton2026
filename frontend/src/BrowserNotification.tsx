import { useEffect, useState } from 'react'
import { X } from 'lucide-react'
import { message, request } from './api'
import { reportHref } from './browserReportLinks'
import s from './workspace.module.css'

type BrowserReportNotice = { run_id: string; node_id: string; name: string; created_at: string; project_id: string | null }

export default function BrowserNotification({ local = false }: { local?: boolean }) {
  const [notice, setNotice] = useState<BrowserReportNotice | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const suffix = local ? '?local=1' : ''
  useEffect(() => {
    if (notice) return
    const controller = new AbortController()
    let timer: number | undefined
    async function poll() {
      try {
        const next = await request<BrowserReportNotice | null>('browser-reports/next' + suffix, 'GET', undefined, controller.signal)
        if (!controller.signal.aborted && next) { setNotice(next); return }
      } catch {
        // Polling resumes when the backend is reachable again.
      }
      if (!controller.signal.aborted) timer = window.setTimeout(poll, 2000)
    }
    void poll()
    return () => { controller.abort(); window.clearTimeout(timer) }
  }, [notice, suffix])

  async function respond(current: BrowserReportNotice, open: boolean) {
    setBusy(true)
    setError('')
    try {
      await request<void>('browser-reports/' + encodeURIComponent(current.run_id) + '/' +
        encodeURIComponent(current.node_id) + '/dismiss' + suffix, 'POST')
      setNotice(null)
      if (open) window.location.assign(reportHref(current.run_id, current.node_id, local))
    } catch (error) {
      setError(message(error))
    } finally {
      setBusy(false)
    }
  }

  return <div aria-live="polite">
    {notice && <aside className={s.reportNotice} aria-labelledby="report-notice-title">
      <h2 id="report-notice-title">Отчёт готов</h2>
      <button type="button" className={s.reportNoticeClose} aria-label="Закрыть уведомление" disabled={busy}
        onClick={() => void respond(notice, false)}><X size={18} aria-hidden="true"/></button>
      <p>Сценарий «{notice.name}»</p>
      <button type="button" className={s.reportOpen} disabled={busy} onClick={() => void respond(notice, true)}>Открыть отчёт</button>
      {error && <small role="alert">{error}</small>}
    </aside>}
  </div>
}

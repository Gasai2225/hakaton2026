import { useEffect, useRef, useState } from 'react'
import { X } from 'lucide-react'
import { message, request } from './api'
import { reportHref } from './browserReportLinks'
import s from './workspace.module.css'

type BrowserReportNotice = { run_id: string; node_id: string; name: string; created_at: string; project_id: string | null }

export default function BrowserNotification({ local = false }: { local?: boolean }) {
  const [notice, setNotice] = useState<BrowserReportNotice | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const dialog = useRef<HTMLDialogElement>(null)
  const cancel = useRef<HTMLButtonElement>(null)
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

  useEffect(() => {
    const modal = dialog.current
    if (!notice || !modal) return
    modal.showModal()
    cancel.current?.focus()
    return () => { if (modal.open) modal.close() }
  }, [notice])

  if (!notice) return null

  async function respond(current: BrowserReportNotice, open: boolean) {
    setBusy(true)
    setError('')
    try {
      await request<void>('browser-reports/' + encodeURIComponent(current.run_id) + '/' +
        encodeURIComponent(current.node_id) + '/dismiss' + suffix, 'POST')
      dialog.current?.close()
      setNotice(null)
      if (open) window.location.assign(reportHref(current.run_id, current.node_id))
    } catch (error) {
      setError(message(error))
    } finally {
      setBusy(false)
    }
  }

  return <dialog ref={dialog} className={s.reportPrompt} aria-labelledby="report-prompt-title"
    aria-describedby="report-prompt-description" onCancel={event => {
      event.preventDefault()
      if (!busy) void respond(notice, false)
    }}>
    <h2 id="report-prompt-title">Открыть отчёт?</h2>
    <button type="button" className={s.reportPromptClose} aria-label="Закрыть окно" disabled={busy}
      onClick={() => void respond(notice, false)}><X size={18} aria-hidden="true"/></button>
    <p id="report-prompt-description">Отчёт по сценарию «{notice.name}» готов к просмотру.</p>
    <div className={s.reportPromptActions}>
      <button type="button" className={s.reportOpen} disabled={busy} onClick={() => void respond(notice, true)}>Открыть отчёт</button>
      <button type="button" ref={cancel} disabled={busy} onClick={() => void respond(notice, false)}>Отмена</button>
    </div>
    {error && <small role="alert">{error}</small>}
  </dialog>
}

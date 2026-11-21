import { useEffect, useRef, useState } from 'react'
import { X } from 'lucide-react'
import { message, request, type Blueprint, type Profile, type Source, type Template, type Workflow } from './api'
import s from './studio.module.css'

export function TemplatesDialog({ profiles, current, close, apply }: {
  profiles: Profile[]; current: Blueprint; close: () => void; apply: (graph: Blueprint, files?: Source[], focus?: string) => void
}) {
  const dialog = useRef<HTMLDialogElement>(null)
  const [templates, setTemplates] = useState<Template[]>([])
  const [description, setDescription] = useState('')
  const [text, setText] = useState('')
  const [connection, setConnection] = useState(profiles[0]?.id ?? '')
  const [model, setModel] = useState('')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    dialog.current?.showModal()
    request<Template[]>('templates').then(setTemplates).catch(e => setError(message(e)))
  }, [])
  async function perform(action: () => Promise<void>) {
    setBusy(true); setError(''); setNotice('')
    try { await action() } catch (e) { setError(message(e)) } finally { setBusy(false) }
  }
  return <dialog ref={dialog} onCancel={e => { if (busy) e.preventDefault(); else close() }}
    className={s.dialog} aria-labelledby="templates-title">
    <div className={s.dialogHead}><h2 id="templates-title">Шаблоны сценариев</h2><button disabled={busy} aria-label="Закрыть" onClick={close}><X size={16}/></button></div>
    <div className={s.templates}>{templates.map(t => <div key={t.id}><div><strong>{t.graph.name}</strong>
      {t.description && <p>{t.description}</p>}</div>
      <button disabled={busy} onClick={() => apply(t.graph)}>Взять копию</button></div>)}</div>
    <label>Описание публикуемого шаблона<textarea className={s.prompt} value={description} maxLength={1500}
      onChange={e => setDescription(e.target.value)} /></label>
    <div className={s.fileActions}><button disabled={busy} onClick={() => void perform(async () => {
      const t = await request<Template>('templates', 'POST', { ...current, description: description.trim() })
      setTemplates(list => [...list, t]); setDescription(''); setNotice('Граф опубликован в локальной библиотеке.')
    })}>Опубликовать текущий граф</button>
    <button disabled={busy} onClick={() => void perform(async () => {
      const demo = await request<Workflow>('demo/repair'); apply(demo, demo.files)
    })}>Открыть демо Repair Desk</button></div>
    <label>Новый граф по описанию<textarea className={s.prompt} value={text} maxLength={1500}
      placeholder="Проверь зависимости, при критической находке предложи исправление" onChange={e => setText(e.target.value)}/></label>
    <label>Подключение<select value={connection} onChange={e => { setConnection(e.target.value); setModel('') }}>
      {profiles.map(p => <option key={p.id} value={p.id}>{p.label}</option>)}</select></label>
    <label>Модель<input className={s.keyInput} value={model} placeholder={profiles.find(p => p.id === connection)?.model || 'ID модели'} onChange={e => setModel(e.target.value)}/></label>
    <p className={s.hint}>В черновике включите расписание в параметрах блока «Расписание» и сохраните граф.
      Для серверного webhook задайте адрес в GARDEN_WEBHOOK_URL.</p>
    {error && <p role="alert" className={s.error}>{error}</p>}{notice && <p role="status">{notice}</p>}
    <div className={s.dialogFoot}><button className={s.primary} disabled={busy || text.trim().length < 3} onClick={() => void perform(async () => {
      const draft = await request<Blueprint>('templates/generate', 'POST', { text, target: { connection, model } })
      const focus = draft.nodes.find(n => n.kind === 'schedule') ?? draft.nodes.find(n => n.kind === 'webhook')
      apply(draft, undefined, focus?.id)
    })}>{busy ? 'Выполняется…' : 'Создать черновик'}</button></div>
  </dialog>
}

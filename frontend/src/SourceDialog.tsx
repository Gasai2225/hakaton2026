import { useEffect, useRef, useState } from 'react'
import { FileCode2, FolderOpen, Upload, X } from 'lucide-react'
import { message, request, type Source } from './api'
import { sourceText } from './sourceText'
import s from './studio.module.css'

export function SourceDialog({ files, apply, close }: { files: Source[]; apply: (files: Source[]) => void; close: () => void }) {
  const [draft, setDraft] = useState(files)
  const [index, setIndex] = useState(0)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [practice, setPractice] = useState('')
  const dialog = useRef<HTMLDialogElement>(null)
  const picker = useRef<HTMLInputElement>(null)
  const folder = useRef<HTMLInputElement>(null)
  useEffect(() => { dialog.current?.showModal(); folder.current?.setAttribute('webkitdirectory', '') }, [])
  async function load(list: FileList | null) {
    if (!list?.length) return
    setError('')
    const selected = Array.from(list).filter(f => /\.(kt|kts|properties|ya?ml)$/i.test(f.name) || ['gradle.lockfile', 'libs.versions.toml'].includes(f.name))
    if (!selected.length) { setError('Выберите файлы Kotlin, Gradle Kotlin DSL или конфигурации Spring.'); return }
    if (selected.length > 400 || selected.reduce((size, f) => size + f.size, 0) > 5_000_000) {
      setError('Лимит проекта — 400 файлов и 5 МБ.'); return
    }
    setLoading(true)
    try {
      const sources = await Promise.all(selected.map(async f => ({
        path: f.webkitRelativePath.split('/').slice(1).join('/') || (f.name === 'libs.versions.toml' ? 'gradle/' + f.name : f.name),
        text: await sourceText(f),
      })))
      if (sources.some(f => f.text.length > 300_000) || new Set(sources.map(f => f.path)).size !== sources.length) {
        setError('Пути должны быть уникальными, размер каждого файла — до 300 000 символов.'); return
      }
      setDraft(sources); setIndex(0); setPractice('')
    } catch (error) { setError(error instanceof Error ? error.message : 'Не удалось прочитать файлы.') }
    finally { setLoading(false) }
  }
  async function loadPractice(project: string) {
    setLoading(true); setError('')
    try {
      const sources = await request<Source[]>('practice/' + project)
      setDraft(sources); setIndex(0); setPractice(project)
    } catch (error) { setError(message(error)) }
    finally { setLoading(false) }
  }
  return <dialog ref={dialog} className={s.dialog} onCancel={close} aria-labelledby="source-title">
    <div className={s.dialogHead}><h2 id="source-title">Исходники проекта</h2><button aria-label="Закрыть" onClick={close}><X size={18}/></button></div>
    <div className={s.fileActions}>
      <button onClick={() => picker.current?.click()} disabled={loading}><Upload size={15}/>Выбрать файлы</button>
      <button onClick={() => folder.current?.click()} disabled={loading}><FolderOpen size={15}/>Выбрать папку</button>
      <input hidden ref={picker} type="file" multiple accept=".kt,.kts,.properties,.yaml,.yml,.lockfile,.toml" onChange={e => void load(e.target.files)} />
      <input hidden ref={folder} type="file" multiple onChange={e => void load(e.target.files)} />
    </div>
    <label>Учебный проект<select value={practice} disabled={loading} onChange={e => void loadPractice(e.target.value)}>
      <option value="" disabled>Выбрать учебный проект</option>
      <option value="book-index">Book Index</option>
      <option value="label-studio">Label Studio</option>
      <option value="reading-room">Reading Room</option>
      <option value="parcel-ledger">Parcel Ledger</option>
    </select></label>
    {error && <p role="alert">{error}</p>}
    <label><FileCode2 size={15}/> Файл<select value={index} onChange={e => setIndex(Number(e.target.value))}>
      {draft.map((file, i) => <option key={file.path} value={i}>{file.path}</option>)}</select></label>
    <textarea aria-label="Текст учебного файла" spellCheck={false} value={draft[index]?.text ?? ''} onChange={e =>
      setDraft(draft.map((file, i) => i === index ? { ...file, text: e.target.value } : file))} />
    <div className={s.dialogFoot}><small>Файлов в проекте · {draft.length}</small>
      <button className={s.primary} disabled={loading} onClick={() => apply(draft)}>Применить</button></div>
  </dialog>
}

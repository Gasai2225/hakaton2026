import { useEffect, useRef, useState } from 'react'
import { FileCode2, FolderOpen, Upload, X } from 'lucide-react'
import { message, request, type Source } from './api'
import { sourceText } from './sourceText'
import s from './studio.module.css'

const attachedCatalog = 'gradle/imported-libs.versions.toml'
const referencesParentCatalog = (files: Source[]) => files.some(f =>
  ['settings.gradle', 'settings.gradle.kts'].includes(f.path) && /from\s*\(\s*files\s*\(\s*["']\.\.\//.test(f.text))

export function SourceDialog({ files, apply, close }: { files: Source[]; apply?: (files: Source[]) => void; close: () => void }) {
  const [draft, setDraft] = useState(files)
  const [index, setIndex] = useState(0)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [practice, setPractice] = useState('')
  const [repository, setRepository] = useState('https://github.com/TBagirov/training')
  const [revision, setRevision] = useState('fe1fcbe212669783480666b9b60147c8a8c6eef4')
  const dialog = useRef<HTMLDialogElement>(null)
  const picker = useRef<HTMLInputElement>(null)
  const folder = useRef<HTMLInputElement>(null)
  const catalog = useRef<HTMLInputElement>(null)
  const externalCatalog = referencesParentCatalog(draft)
  useEffect(() => { dialog.current?.showModal(); folder.current?.setAttribute('webkitdirectory', '') }, [])
  async function load(list: FileList | null, attach = false) {
    if (!list?.length) return
    setError('')
    const excluded = new Set(['.git', '.gradle', 'build', 'node_modules', '.venv'])
    const selected = Array.from(list).filter(f =>
      !f.webkitRelativePath.split('/').slice(1, -1).some(dir => excluded.has(dir)) &&
      (/\.(kt|kts|properties|ya?ml)$/i.test(f.name) || ['settings.gradle', 'gradle.lockfile', 'libs.versions.toml'].includes(f.name)))
    if (attach && (selected.length !== 1 || selected[0].name !== 'libs.versions.toml')) {
      setError('Выберите файл libs.versions.toml из настроек Gradle.'); return
    }
    if (!selected.length) { setError('Выберите файлы Kotlin, Gradle Kotlin DSL или конфигурации Spring.'); return }
    const existing = attach ? draft.filter(f => f.path !== attachedCatalog) : []
    const bytes = existing.reduce((n, f) => n + new TextEncoder().encode(f.text).length, 0)
    if (existing.length + selected.length > 400 || selected.reduce((size, f) => size + f.size, bytes) > 5_000_000) {
      setError('Лимит проекта — 400 файлов и 5 МБ.'); return
    }
    setLoading(true)
    try {
      const loaded = await Promise.all(selected.map(async f => ({
        path: attach ? attachedCatalog : f.webkitRelativePath.split('/').slice(1).join('/') || (f.name === 'libs.versions.toml' ? 'gradle/' + f.name : f.name),
        text: await sourceText(f),
      })))
      if (!attach && referencesParentCatalog(loaded)) {
        const catalogIndex = selected.findIndex(f => f.name === 'libs.versions.toml' && !f.webkitRelativePath)
        if (catalogIndex >= 0) loaded[catalogIndex].path = attachedCatalog
      }
      const sources = [...existing, ...loaded]
      if (sources.some(f => f.text.length > 300_000) || new Set(sources.map(f => f.path)).size !== sources.length) {
        setError('Пути должны быть уникальными, размер каждого файла — до 300 000 символов.'); return
      }
      setDraft(sources); setIndex(existing.length); setPractice('')
    } catch (error) { setError(error instanceof Error ? error.message : 'Не удалось прочитать файлы.') }
    finally { setLoading(false) }
  }
  async function loadRemote(result: Promise<Source[]>, project = '') {
    setLoading(true); setError('')
    try {
      const sources = await result
      setDraft(sources); setIndex(0); setPractice(project)
    } catch (error) { setError(message(error)) }
    finally { setLoading(false) }
  }
  return <dialog ref={dialog} className={s.dialog} onCancel={close} aria-labelledby="source-title">
    <div className={s.dialogHead}><h2 id="source-title">Исходники проекта</h2><button aria-label="Закрыть" onClick={close}><X size={18}/></button></div>
    {apply && <><div className={s.fileActions}>
      <button onClick={() => picker.current?.click()} disabled={loading}><Upload size={15}/>Выбрать файлы</button>
      <button onClick={() => folder.current?.click()} disabled={loading}><FolderOpen size={15}/>Выбрать папку</button>
      {externalCatalog && <button onClick={() => catalog.current?.click()} disabled={loading}><Upload size={15}/>
        {draft.some(f => f.path === attachedCatalog) ? 'Заменить каталог Gradle' : 'Приложить каталог Gradle'}</button>}
      <input hidden ref={catalog} type="file" accept=".toml" onChange={e => { void load(e.target.files, true); e.target.value = '' }} />
      <input hidden ref={picker} type="file" multiple accept=".kt,.kts,.gradle,.properties,.yaml,.yml,.lockfile,.toml" onChange={e => void load(e.target.files)} />
      <input hidden ref={folder} type="file" multiple onChange={e => void load(e.target.files)} />
    </div>
    <details><summary>Импорт из GitHub</summary>
      <form onSubmit={e => {
        e.preventDefault()
        void loadRemote(request<Source[]>('sources/github', 'POST', { repository, revision }))
      }}>
        <label>Репозиторий<input type="url" required value={repository} onChange={e => setRepository(e.target.value)} /></label>
        <label>SHA коммита<input type="text" required pattern="[a-fA-F0-9]{40}" title="40 шестнадцатеричных символов"
          value={revision} onChange={e => setRevision(e.target.value.trim())} /></label>
        <button disabled={loading}>Загрузить training-project</button>
      </form>
    </details>
    <label>Учебный проект<select value={practice} disabled={loading} onChange={e =>
      void loadRemote(request<Source[]>('practice/' + e.target.value), e.target.value)}>
      <option value="" disabled>Выбрать учебный проект</option>
      <option value="book-index">Book Index</option>
      <option value="label-studio">Label Studio</option>
      <option value="reading-room">Reading Room</option>
      <option value="parcel-ledger">Parcel Ledger</option>
    </select></label></>}
    {error && <p role="alert">{error}</p>}
    {draft.length > 0 ? <>
      <label><FileCode2 size={15}/> Файл<select value={index} onChange={e => setIndex(Number(e.target.value))}>
        {draft.map((file, i) => <option key={file.path} value={i}>{file.path}</option>)}</select></label>
      <textarea aria-label="Текст учебного файла" spellCheck={false} readOnly={!apply} value={draft[index]?.text ?? ''} onChange={e =>
        setDraft(draft.map((file, i) => i === index ? { ...file, text: e.target.value } : file))} />
    </> : <p className={s.hint}>{apply ? 'Выберите файлы, папку или готовый учебный проект.' : 'В проекте пока нет исходников.'}</p>}
    <div className={s.dialogFoot}><small>Файлов в проекте · {draft.length}</small>
      {apply && <button className={s.primary} disabled={loading} onClick={() => apply(draft)}>Применить</button>}</div>
  </dialog>
}

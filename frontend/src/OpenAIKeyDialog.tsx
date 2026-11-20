import { useEffect, useRef, useState } from 'react'
import { X } from 'lucide-react'
import { message, request, type Profile } from './api'
import s from './studio.module.css'

export function OpenAIKeyDialog({ close, connected }: { close: () => void; connected: (p: Profile) => void }) {
  const dialog = useRef<HTMLDialogElement>(null)
  const input = useRef<HTMLInputElement>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  useEffect(() => { dialog.current?.showModal() }, [])
  return <dialog ref={dialog} onCancel={close} className={s.dialog} aria-labelledby="key-title">
    <div className={s.dialogHead}><h2 id="key-title">Подключить OpenAI</h2>
      <button onClick={close} aria-label="Закрыть"><X size={16}/></button></div>
    <form onSubmit={async event => {
      event.preventDefault()
      if (!input.current || busy) return
      setBusy(true); setError('')
      try {
        const profile = await request<Profile>('connections/openai/key', 'POST', { key: input.current.value })
        input.current.value = ''
        connected(profile); close()
      } catch (e) { setError(message(e)) }
      finally { setBusy(false) }
    }}>
      <label>Ключ OpenAI API<input className={s.keyInput} type="password" autoComplete="off" ref={input} required autoFocus maxLength={4096}/></label>
      <p className={s.hint}>Сервер проверит доступ к списку моделей и сохранит ключ в диспетчере учётных данных Windows.</p>
      {error && <p role="alert" className={s.error}>{error}</p>}
      <div className={s.dialogFoot}><button className={s.primary} disabled={busy}>{busy ? 'Проверяем…' : 'Проверить и подключить'}</button></div>
    </form>
  </dialog>
}

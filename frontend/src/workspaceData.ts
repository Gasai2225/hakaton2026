import { useEffect, useState } from 'react'
import { message, request } from './api'

export type Account = { id: string; name: string; email: string }
export type Project = { id: string; name: string; role: 'owner' | 'editor'; revision: number; updated_at: string }
export const projectUrl = (id: string) => '/projects/' + encodeURIComponent(id)

export function useResource<T>(path: string) {
  const [data, setData] = useState<T>()
  const [error, setError] = useState('')
  const [version, setVersion] = useState(0)
  useEffect(() => {
    const controller = new AbortController()
    setError('')
    request<T>(path, 'GET', undefined, controller.signal).then(value => {
      if (!controller.signal.aborted) setData(value)
    }).catch(err => { if (!controller.signal.aborted) setError(message(err)) })
    return () => controller.abort()
  }, [path, version])
  return { data, setData, error, reload: () => setVersion(v => v + 1) }
}

export function useAction() {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  async function perform(fn: () => Promise<void>) {
    if (busy) return
    setBusy(true); setError('')
    try { await fn() } catch (err) { setError(message(err)) } finally { setBusy(false) }
  }
  return { busy, error, perform }
}

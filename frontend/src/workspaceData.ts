import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiError, message, request } from './api'

export type Account = { id: string; name: string; email: string }
export type SharedRole = 'viewer' | 'editor' | 'reporter'
export type Access = { role: SharedRole; can_run: boolean }
export type Project = { id: string; name: string; role: 'owner' | SharedRole; can_run: boolean; revision: number; updated_at: string }
export const roleNames = { owner: 'Владелец', viewer: 'Наблюдатель', editor: 'Редактор', reporter: 'Только отчёты' }
export function accessLabel({ role, can_run }: Pick<Project, 'role' | 'can_run'>) {
  if (role === 'owner' || role === 'reporter') return roleNames[role]
  return roleNames[role] + (can_run ? ' · с запуском проверок' : ' · без запуска проверок')
}
export const projectUrl = (id: string) => '/projects/' + encodeURIComponent(id)

export function useResource<T>(path: string, refreshMs = 0) {
  const [data, setData] = useState<T>()
  const [error, setError] = useState('')
  const [denied, setDenied] = useState(false)
  const refresh = useRef<() => void>(() => {})
  const reload = useCallback(() => refresh.current(), [])
  useEffect(() => {
    let pending: AbortController | undefined
    let timer: number | undefined
    async function load() {
      pending?.abort()
      window.clearTimeout(timer)
      const controller = new AbortController()
      pending = controller
      try {
        const value = await request<T>(path, 'GET', undefined, controller.signal)
        if (!controller.signal.aborted) { setData(value); setError(''); setDenied(false) }
      } catch (err) {
        if (controller.signal.aborted) return
        if (err instanceof ApiError && [401, 403, 404].includes(err.status)) {
          setData(undefined); setDenied(true)
        }
        setError(message(err))
      } finally {
        if (!controller.signal.aborted && refreshMs && !document.hidden) timer = window.setTimeout(load, refreshMs)
      }
    }
    function whenVisible() {
      window.clearTimeout(timer)
      if (!document.hidden) void load()
    }
    setData(undefined); setError(''); setDenied(false)
    refresh.current = load
    void load()
    if (refreshMs) {
      window.addEventListener('focus', whenVisible)
      document.addEventListener('visibilitychange', whenVisible)
    }
    return () => {
      pending?.abort(); window.clearTimeout(timer); refresh.current = () => {}
      window.removeEventListener('focus', whenVisible)
      document.removeEventListener('visibilitychange', whenVisible)
    }
  }, [path, refreshMs])
  return { data, setData, error, denied, reload }
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

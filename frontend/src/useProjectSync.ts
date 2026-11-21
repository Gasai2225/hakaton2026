import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'
import { ApiError, message, request, type Workflow } from './api'
import type { Project } from './workspaceData'

export type ProjectDetail = Project & { workflow: Workflow }
type Editor = { snapshot: () => Workflow; apply: (workflow: Workflow) => void; saved: () => void; clientId?: () => string | undefined }
type SyncState = { issue: string; conflict: boolean; forbidden: boolean }
const clear: SyncState = { issue: '', conflict: false, forbidden: false }
const projectTag = (detail: ProjectDetail) => '"' + [detail.id, detail.revision, detail.role, Number(detail.can_run)].join('-') + '"'

export function connectProjectSync(id: string, editor: () => Editor, publish: (state: SyncState) => void) {
  const path = 'projects/' + encodeURIComponent(id)
  const controller = new AbortController()
  const { signal } = controller
  let revision = 0
  let tag = ''
  let generation = 0
  let edits = 0
  let savedEdits = 0
  let rejectedEdits = -1
  let lockRejected = false
  let nodeEdit: { serial: number; leaseId: string } | undefined
  let state = clear
  let editBase: Workflow | undefined
  let pending: { serial: number; workflow: Workflow; leaseId?: string } | undefined
  let queue = Promise.resolve()
  let timer: number | undefined

  function notify(next: SyncState) {
    if (signal.aborted || (state.issue === next.issue && state.conflict === next.conflict && state.forbidden === next.forbidden)) return
    state = next
    publish(next)
  }

  function checkActive() {
    if (signal.aborted || !revision) throw new Error('Редактор проекта закрыт')
    if (state.forbidden) throw new Error(state.issue)
  }

  function serialize<T>(job: () => Promise<T>) {
    const result = queue.then(job)
    queue = result.then(() => undefined, () => undefined)
    return result
  }

  function recordError(error: unknown, serial?: number) {
    if (signal.aborted) return
    const status = error instanceof ApiError ? error.status : 0
    if (status === 409 || status === 423 || (status === 403 && serial !== undefined)) {
      pending = undefined
      lockRejected = status === 423
      notify({ issue: message(error), conflict: true, forbidden: false })
    } else if ([401, 403, 404].includes(status)) {
      pending = undefined; editBase = undefined
      notify({ issue: 'Доступ к проекту закрыт. Откройте список доступных проектов.', conflict: false, forbidden: true })
    } else if (status === 422 && serial !== undefined) {
      pending = undefined
      rejectedEdits = serial
      notify({ ...clear, issue: message(error) })
    } else if (!state.conflict && rejectedEdits !== edits) {
      notify({ ...clear, issue: error instanceof ApiError ? error.message : 'Нет связи с проектом. Повторяем синхронизацию.' })
    }
  }

  async function pull() {
    checkActive()
    const initialEdits = edits
    const generationAtStart = generation
    try {
      const response = await fetch('/api/' + path, { signal, cache: 'no-store', headers: { 'If-None-Match': tag } })
      if (response.status !== 304) {
        if (!response.ok) throw new ApiError(response.status, 'Не удалось обновить проект')
        const detail = await response.json() as ProjectDetail
        checkActive()
        if (generation !== generationAtStart) return
        // Edits can arrive while this GET is in flight. Keep their original base for the next PUT.
        if (initialEdits === edits && savedEdits === edits && detail.revision > revision) {
          editor().apply(detail.workflow)
          revision = detail.revision
        }
        if (detail.revision === revision) tag = projectTag(detail)
      }
      if (generation === generationAtStart && !state.conflict && rejectedEdits !== edits) notify(clear)
    } catch (error) {
      if (generation === generationAtStart) recordError(error)
      throw error
    }
  }

  async function save() {
    checkActive()
    if (state.conflict || rejectedEdits === edits) throw new Error(state.issue)
    // A lost response may follow a successful commit. Retry the same snapshot first.
    const sending = pending ?? { serial: edits, workflow: editor().snapshot(), leaseId: nodeEdit?.leaseId }
    const generationAtStart = generation
    pending = sending
    try {
      const identifyTab = editor().clientId
      const clientId = identifyTab?.()
      if (identifyTab && !clientId) throw new Error('Дождитесь подключения к доске')
      const detail = await request<ProjectDetail>(path, 'PUT', {
        base_revision: revision, workflow: sending.workflow, edit_base: editBase, client_id: clientId, lease_id: sending.leaseId,
      }, signal)
      checkActive()
      if (generation !== generationAtStart) return
      revision = detail.revision
      tag = projectTag(detail)
      savedEdits = sending.serial
      if (nodeEdit && nodeEdit.serial <= savedEdits) nodeEdit = undefined
      pending = undefined
      if (edits === sending.serial) {
        editBase = undefined
        editor().apply(detail.workflow)
        editor().saved()
      } else {
        // The visible graph still derives from what was sent, even if the server merged other edits.
        editBase = sending.workflow
      }
      notify(clear)
    } catch (error) {
      if (generation === generationAtStart) recordError(error, sending.serial)
      throw error
    }
  }

  async function tick() {
    try {
      await serialize(async () => {
        if (!revision || state.forbidden || signal.aborted) return
        if (edits !== savedEdits && !state.conflict && edits !== rejectedEdits) await save()
        else await pull()
      })
    } catch { /* save and pull publish the error and retain local edits */ }
    if (!signal.aborted && !state.forbidden) timer = window.setTimeout(tick, 1200)
  }

  function beforeUnload(event: BeforeUnloadEvent) {
    if (edits !== savedEdits && !state.forbidden) { event.preventDefault(); event.returnValue = '' }
  }
  window.addEventListener('beforeunload', beforeUnload)
  timer = window.setTimeout(tick, 1200)

  return {
    init(detail: ProjectDetail) {
      if (detail.id !== id || signal.aborted) return
      generation++
      revision = detail.revision
      tag = projectTag(detail)
      edits = savedEdits = 0
      rejectedEdits = -1
      lockRejected = false
      nodeEdit = undefined
      pending = undefined
      editBase = undefined
      notify(clear)
    },
    touch(leaseId?: string) {
      if (!revision || state.forbidden || signal.aborted) return
      if (edits === rejectedEdits) notify(clear)
      edits++
      if (leaseId) nodeEdit = { serial: edits, leaseId }
    },
    flush(recoveredLease?: string) {
      return serialize(async () => {
        checkActive()
        if (recoveredLease && edits !== savedEdits) {
          // Explicit reacquisition keeps the original merge base and the local draft.
          if (nodeEdit) nodeEdit.leaseId = recoveredLease
          if (pending?.leaseId) pending.leaseId = recoveredLease
          if (lockRejected) { lockRejected = false; notify(clear) }
          // A validation error can be corrected once the fields are enabled again.
          // A content conflict still needs explicit resolution.
          if (rejectedEdits === edits || state.conflict) return revision
        }
        if (edits === savedEdits) await pull()
        while (edits !== savedEdits) await save()
        return revision
      })
    },
    stop() {
      controller.abort()
      window.clearTimeout(timer)
      window.removeEventListener('beforeunload', beforeUnload)
    },
  }
}

export function useProjectSync(projectId: string | undefined, editor: Editor) {
  const currentEditor = useRef(editor)
  useLayoutEffect(() => { currentEditor.current = editor })
  const session = useRef<ReturnType<typeof connectProjectSync> | null>(null)
  const [state, setState] = useState(clear)
  useEffect(() => {
    setState(clear)
    if (!projectId) return
    const connection = connectProjectSync(projectId, () => currentEditor.current, setState)
    session.current = connection
    return () => { connection.stop(); session.current = null }
  }, [projectId])
  const init = useCallback((detail: ProjectDetail) => session.current?.init(detail), [])
  const touch = useCallback((leaseId?: string) => session.current?.touch(leaseId), [])
  const flush = useCallback((recoveredLease?: string) => session.current?.flush(recoveredLease) ?? Promise.reject(new Error('Проект закрыт')), [])
  return { ...state, init, touch, flush }
}

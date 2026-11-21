import type { XYPosition } from '@xyflow/react'
import { ApiError, request } from './api'
import { graphId } from './blocks'

export type Peer = { id: string; name: string; cursor: XYPosition | null }
export type NodeLock = { node_id: string; user_id: string; name: string; mine: boolean; lease_id: string; expires_at: number }
export type PresenceSnapshot = { status: 'connecting' | 'online' | 'offline'; peers: Peer[]; locks: NodeLock[] }

export function connectPresence(projectId: string, publish: (state: PresenceSnapshot) => void) {
  const path = 'projects/' + encodeURIComponent(projectId) + '/presence'
  let source: EventSource | undefined
  let client = ''
  let ready = false
  let cursor: XYPosition | null = null
  let uploaded: XYPosition | null | undefined
  let acknowledgedAt = 0
  let nextUploadAt = 0
  let timer: number | undefined
  let reconnect: number | undefined
  let pending: AbortController | undefined
  let lifetime: AbortController | undefined
  let owned: NodeLock | undefined
  let checkGrant: (() => void) | undefined
  let clockOffset: number | undefined
  let lastActivity: { lease: string; time: number } | undefined
  let lockRequests = 0
  let lockQueue = Promise.resolve()

  function schedule() {
    if (!ready || pending || timer !== undefined) return
    if (uploaded === cursor && Date.now() - acknowledgedAt < 12000) return
    timer = window.setTimeout(upload, Math.max(0, nextUploadAt - Date.now()))
  }

  async function upload() {
    timer = undefined
    const position = cursor
    const controller = new AbortController()
    pending = controller
    nextUploadAt = Date.now() + 75
    try {
      const signal = AbortSignal.any([controller.signal, AbortSignal.timeout(6000)])
      await request(path + '/cursor', 'POST', { client_id: client, cursor: position }, signal)
      if (!controller.signal.aborted) {
        uploaded = position
        acknowledgedAt = Date.now()
      }
    } catch (error) {
      if (!controller.signal.aborted) {
        if (error instanceof ApiError && error.status === 409) lostConnection()
        else nextUploadAt = Date.now() + 1000
      }
    } finally {
      if (pending === controller) { pending = undefined; schedule() }
    }
  }

  function resetUploads() {
    ready = false
    pending?.abort()
    pending = undefined
    window.clearTimeout(timer)
    timer = undefined
    uploaded = undefined
    acknowledgedAt = nextUploadAt = 0
  }

  function disconnect() {
    source?.close()
    source = undefined
    lifetime?.abort()
    lifetime = undefined
    owned = undefined
    clockOffset = undefined
    lastActivity = undefined
    window.clearTimeout(reconnect)
    resetUploads()
  }

  function lostConnection() {
    disconnect()
    publish({ status: 'offline', peers: [], locks: [] })
    if (!document.hidden) reconnect = window.setTimeout(open, 2000)
  }

  function open() {
    if (document.hidden || source) return
    window.clearTimeout(reconnect)
    client = graphId()
    lifetime = new AbortController()
    const stream = new EventSource('/api/' + path + '/stream?client_id=' + client)
    source = stream
    publish({ status: 'connecting', peers: [], locks: [] })
    stream.onmessage = event => {
      if (source !== stream) return
      const snapshot = JSON.parse(event.data) as Pick<PresenceSnapshot, 'peers' | 'locks'> & { server_time: number }
      const offset = clockOffset ??= Date.now() - snapshot.server_time
      const locks = snapshot.locks.map(lock => ({ ...lock, expires_at: lock.expires_at + offset }))
      owned = locks.find(lock => lock.mine)
      checkGrant?.()
      if (document.hidden && !owned && !lockRequests) { leave(); return }
      if (!ready) { ready = true; schedule() }
      publish({ status: 'online', peers: snapshot.peers, locks })
    }
    stream.onerror = () => {
      // A new tab ID fences off requests still in flight from the lost connection.
      if (source === stream) lostConnection()
    }
  }

  function waitForGrant(leaseId: string | null, signal: AbortSignal) {
    signal.throwIfAborted()
    if ((owned?.lease_id ?? null) === leaseId) return
    return new Promise<void>((resolve, reject) => {
      function abort() { checkGrant = undefined; reject(signal.reason) }
      checkGrant = () => {
        if ((owned?.lease_id ?? null) !== leaseId) return
        checkGrant = undefined
        signal.removeEventListener('abort', abort)
        resolve()
      }
      signal.addEventListener('abort', abort, { once: true })
    })
  }

  function getLeaseId() {
    return owned && owned.expires_at > Date.now() ? owned.lease_id : undefined
  }

  function setLock(nodeId: string | null) {
    const signal = lifetime?.signal
    const clientId = client
    if (!ready || !signal) return Promise.reject(new Error('Дождитесь подключения к доске'))
    lockRequests++
    const result = lockQueue.then(async () => {
      signal.throwIfAborted()
      try {
        const deadline = AbortSignal.any([signal, AbortSignal.timeout(8000)])
        const grant = await request<{ lease_id: string | null }>(path + '/lock', 'POST', {
          client_id: clientId, node_id: nodeId, previous_lease_id: getLeaseId() ?? null, return_lease: true,
        }, deadline)
        // POST and SSE use different connections. Finish the switch after both agree on the lease.
        await waitForGrant(grant.lease_id, deadline)
        return grant.lease_id
      } catch (error) {
        if (!signal.aborted && (!(error instanceof ApiError) || error.status === 409)) lostConnection()
        throw error
      }
    }).finally(() => {
      lockRequests--
      if (document.hidden && !lockRequests && !owned && !signal.aborted) leave()
    })
    lockQueue = result.then(() => {}, () => {})
    return result
  }

  async function continueEditing(nodeId: string): Promise<void> {
    const signal = lifetime?.signal
    if (!ready || !signal || owned?.node_id !== nodeId) throw new Error('Блокировка ноды уже снята')
    try {
      await request(path + '/lock/activity', 'POST', { client_id: client, node_id: nodeId, lease_id: owned.lease_id },
        AbortSignal.any([signal, AbortSignal.timeout(6000)]))
    } catch (error) {
      if (!signal.aborted && error instanceof ApiError && error.status === 409) lostConnection()
      throw error
    }
  }

  function noteActivity(nodeId: string) {
    if (owned?.node_id !== nodeId) return
    const time = performance.now()
    if (lastActivity?.lease === owned.lease_id && time - lastActivity.time < 1000) return
    lastActivity = { lease: owned.lease_id, time }
    // Only a fresh edit can renew the lease. A delayed retry could keep an idle node locked.
    void continueEditing(nodeId).catch(() => {})
  }

  function leave() {
    cursor = null
    disconnect()
    publish({ status: 'offline', peers: [], locks: [] })
  }
  function visibilityChanged() {
    if (!document.hidden) open()
    else if (!owned && !lockRequests) leave()
  }
  const heartbeat = window.setInterval(schedule, 6000)
  document.addEventListener('visibilitychange', visibilityChanged)
  window.addEventListener('pagehide', leave)
  window.addEventListener('pageshow', open)
  open()
  return {
    setLock,
    noteActivity,
    continueEditing,
    getLeaseId,
    getClientId: () => ready ? client : undefined,
    setCursor(point: XYPosition | null) {
      if (point?.x === cursor?.x && point?.y === cursor?.y) return
      cursor = point
      schedule()
    },
    stop() {
      disconnect()
      window.clearInterval(heartbeat)
      document.removeEventListener('visibilitychange', visibilityChanged)
      window.removeEventListener('pagehide', leave)
      window.removeEventListener('pageshow', open)
    },
  }
}

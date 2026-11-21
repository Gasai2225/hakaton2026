import { useCallback, useEffect, useRef, useState, type RefObject } from 'react'
import { ApiError, message } from './api'
import type { connectPresence, NodeLock, PresenceSnapshot } from './boardPresence'

export type BoardConnection = ReturnType<typeof connectPresence>
type BoardLocks = Pick<PresenceSnapshot, 'locks' | 'status'>

export function useNodeEditing(connection: RefObject<BoardConnection | null>, flush: (recoveredLease?: string) => Promise<number>,
  onError: (error: string) => void) {
  const [board, setBoard] = useState<BoardLocks>({ status: 'connecting', locks: [] })
  const [granted, setGranted] = useState<string | null>(null)
  const [interrupted, setInterrupted] = useState<string>()
  const [intent, setIntent] = useState<{ node: string | null; recover: boolean }>()
  const confirmed = useRef<string | null>(null)
  const leaving = useRef<string | undefined>(undefined)
  const desired = useRef<string | null>(null)
  const queue = useRef(Promise.resolve())
  const latest = useRef(board)
  const own = board.locks.find(lock => lock.mine)
  const active = own?.lease_id === granted ? own.node_id : null

  const receive = useCallback((status: BoardLocks['status'], locks: NodeLock[]) => {
    const previous = latest.current
    if (status === previous.status && previous.locks.length === locks.length && locks.every((lock, i) => {
      const old = previous.locks[i]
      return old.lease_id === lock.lease_id && old.expires_at === lock.expires_at && old.node_id === lock.node_id &&
        old.user_id === lock.user_id && old.mine === lock.mine && old.name === lock.name
    })) return
    latest.current = { status, locks }
    setBoard(latest.current)
    const oldOwn = previous.locks.find(lock => lock.mine)
    if (oldOwn && !locks.some(lock => lock.mine && lock.lease_id === oldOwn.lease_id)) {
      if (leaving.current !== oldOwn.lease_id) setInterrupted(oldOwn.node_id)
      leaving.current = undefined
      if (confirmed.current === oldOwn.node_id) confirmed.current = null
      setGranted(value => value === oldOwn.lease_id ? null : value)
    }
    if (status !== 'online') {
      confirmed.current = null
      if (previous.status === 'online') {
        desired.current = null
        setIntent(undefined)
      }
      setGranted(null)
    }
  }, [])

  function select(node: string | null) {
    if (node !== null && !intent && active === node && connection.current?.getLeaseId() === granted) {
      desired.current = node; return
    }
    if (intent && desired.current === node) return
    desired.current = node
    setGranted(null)
    if (!intent && !own && (node === null || board.locks.some(lock => lock.node_id === node))) {
      setIntent(undefined)
      return
    }
    setIntent({ node, recover: !!node && node === interrupted && !own })
  }

  // Run after the editor committed its render: a just-created node must be saved before it can be locked.
  useEffect(() => {
    const session = connection.current
    if (!intent || !session || board.status !== 'online') return
    let current = true
    const valid = () => current && desired.current === intent.node && connection.current === session && !!session.getClientId()
    queue.current = queue.current.then(async () => {
      if (!valid()) return
      let flushed = false
      try {
        if (!intent.recover) await flush()
        flushed = true
        if (!valid()) return
        const occupied = latest.current.locks.some(lock => lock.node_id === intent.node && !lock.mine)
        const holding = latest.current.locks.find(lock => lock.mine)
        if (holding && holding.node_id !== intent.node) leaving.current = holding.lease_id
        const lease = await session.setLock(occupied ? null : intent.node)
        if (intent.node && lease && valid()) {
          // The previous owner may have saved just before releasing the node.
          try { await flush(intent.recover ? lease : undefined) }
          catch (error) {
            if (!(intent.recover && error instanceof ApiError && [409, 422].includes(error.status))) throw error
          }
          if (valid()) {
            confirmed.current = intent.node
            setGranted(lease)
            setInterrupted(undefined)
          }
        }
      } catch (err) {
        if (!valid()) return
        leaving.current = undefined
        if (!flushed) {
          // Validation can reject a save. Keep the held block editable so its owner can correct it.
          const stillOwned = latest.current.locks.find(lock => lock.mine && lock.node_id === confirmed.current)
          setGranted(stillOwned?.lease_id ?? null)
          onError(message(err))
        } else if (err instanceof ApiError && err.status === 423) {
          // A rejected switch leaves the old node held by this tab.
          if (!latest.current.locks.some(lock => lock.node_id === intent.node && !lock.mine)) onError(message(err))
          if (latest.current.locks.some(lock => lock.mine)) {
            try { await session.setLock(null) } catch (releaseError) { if (valid()) onError(message(releaseError)) }
          }
        } else onError(message(err))
      } finally {
        if (current) setIntent(undefined)
      }
    })
    return () => { current = false }
  }, [intent, connection, board.status, flush, onError])

  return { ...board, active, own, interrupted, pending: intent?.node, select, receive }
}

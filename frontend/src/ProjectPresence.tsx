import { useEffect, useId, useRef, useState, type RefObject } from 'react'
import { useReactFlow, useStore, useStoreApi, ViewportPortal, type XYPosition } from '@xyflow/react'
import { ChevronDown, MousePointer2 } from 'lucide-react'
import { connectPresence, type NodeLock, type Peer, type PresenceSnapshot } from './boardPresence'
import type { BoardConnection } from './useNodeEditing'
import { participantColor } from './participantColor'
import type { Account } from './workspaceData'
import s from './studio.module.css'

function Avatar({ person }: { person: Pick<Account, 'id' | 'name'> }) {
  const words = person.name.trim().split(/\s+/)
  const first = Array.from(words[0])[0] ?? ''
  const last = words.length > 1 ? Array.from(words[words.length - 1])[0] : ''
  return <span aria-hidden="true" className={s.avatar} style={{ backgroundColor: participantColor(person.id) }}>
    {(first + last).toLocaleUpperCase('ru')}
  </span>
}

function BoardCursors({ peers }: { peers: Peer[] }) {
  const zoom = useStore(state => state.transform[2])
  return <ViewportPortal>{peers.map(peer => peer.cursor && <div key={peer.id} aria-hidden="true"
    data-peer-cursor={peer.id} className={s.remoteCursor}
    style={{ transform: `translate(${peer.cursor.x}px, ${peer.cursor.y}px)` }}>
    <div className={s.cursorGlyph} style={{ transform: `scale(${1 / zoom})`, color: participantColor(peer.id) }}>
      <MousePointer2 size={23} fill="currentColor" stroke="white" strokeWidth={1.6}/>
      <span className={s.cursorName} style={{ backgroundColor: participantColor(peer.id) }}>{peer.name}</span>
    </div>
  </div>)}</ViewportPortal>
}

function Roster({ user, peers, status }: PresenceSnapshot & { user: Account }) {
  const [open, setOpen] = useState(false)
  const panel = useRef<HTMLDivElement>(null)
  const button = useRef<HTMLButtonElement>(null)
  const listId = useId()
  useEffect(() => {
    if (!open) return
    function outside(event: PointerEvent) {
      if (!panel.current?.contains(event.target as Node)) setOpen(false)
    }
    document.addEventListener('pointerdown', outside)
    return () => document.removeEventListener('pointerdown', outside)
  }, [open])

  const people = [user, ...peers]
  const availability = status === 'online' ? 'На доске' : status === 'connecting' ? 'Подключение…' : 'Нет связи'
  return <div className={s.presence} ref={panel}
    onBlur={event => { if (!event.currentTarget.contains(event.relatedTarget)) setOpen(false) }}
    onKeyDown={event => { if (event.key === 'Escape') { setOpen(false); button.current?.focus() } }}>
    <button type="button" ref={button} className={s.rosterButton} aria-expanded={open} aria-controls={listId}
      aria-label={'Сейчас на доске · ' + (status === 'online' ? people.map(p => p.name).join(', ') : availability)}
      onClick={() => setOpen(!open)}>
      <span className={s.avatars}>{people.slice(0, 3).map(p => <Avatar key={p.id} person={p}/>)}
        {people.length > 3 && <span className={s.extraPeers}>+{people.length - 3}</span>}</span>
      <span>{availability}{status === 'online' && ' · ' + people.length}</span><ChevronDown size={13}/>
    </button>
    {open && <ul id={listId} aria-label="Сейчас на доске" className={s.rosterList}>
      {people.map(p => <li key={p.id}><Avatar person={p}/><span>{p.name}</span>{p.id === user.id && <small>Вы</small>}</li>)}
    </ul>}
  </div>
}

export function ProjectPresence({ projectId, user, canvas, connection, onEditState }: {
  projectId: string; user: Account; canvas: RefObject<HTMLDivElement | null>
  connection: RefObject<BoardConnection | null>
  onEditState: (status: PresenceSnapshot['status'], locks: NodeLock[]) => void
}) {
  const [snapshot, setSnapshot] = useState<PresenceSnapshot>({ status: 'connecting', peers: [], locks: [] })
  const { screenToFlowPosition } = useReactFlow()
  const store = useStoreApi()

  useEffect(() => {
    const board = canvas.current
    if (!board) return
    const presence = connectPresence(projectId, state => {
      setSnapshot(state)
      onEditState(state.status, state.locks)
    })
    connection.current = presence
    let pointer: XYPosition | null = null
    function clear() { pointer = null; presence.setCursor(null) }
    function place() {
      if (!pointer || !board) return
      const rect = board.getBoundingClientRect()
      if (pointer.x < rect.left || pointer.x >= rect.right || pointer.y < rect.top || pointer.y >= rect.bottom) clear()
      else presence.setCursor(screenToFlowPosition(pointer, { snapToGrid: false }))
    }
    function move(event: PointerEvent) {
      if (!event.isPrimary || (event.target instanceof Element && event.target.closest('.react-flow__panel'))) { clear(); return }
      pointer = { x: event.clientX, y: event.clientY }
      place()
    }
    function release(event: PointerEvent) { if (event.pointerType === 'touch') clear() }
    function visibility() { if (document.hidden) clear() }
    const unsubscribe = store.subscribe((current, previous) => { if (current.transform !== previous.transform) place() })
    const controller = new AbortController()
    const options = { capture: true, passive: true, signal: controller.signal }
    board.addEventListener('pointermove', move, options)
    board.addEventListener('pointerdown', move, options)
    board.addEventListener('pointerleave', clear, { signal: controller.signal })
    board.addEventListener('pointercancel', clear, options)
    board.addEventListener('pointerup', release, options)
    document.addEventListener('scroll', place, options)
    document.addEventListener('visibilitychange', visibility, options)
    window.addEventListener('blur', clear, options)
    return () => { unsubscribe(); controller.abort(); connection.current = null; presence.stop() }
  }, [canvas, projectId, screenToFlowPosition, store, connection, onEditState])

  return <><Roster user={user} {...snapshot}/><BoardCursors peers={snapshot.peers}/></>
}

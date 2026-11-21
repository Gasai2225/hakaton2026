import { lazy, StrictMode, Suspense, useCallback, useEffect, useRef, useState } from 'react'
import { createRoot } from 'react-dom/client'
import {
  addEdge, Background, BackgroundVariant, Controls, MarkerType, Panel, ReactFlow, ReactFlowProvider,
  useEdgesState, useNodesState, useReactFlow, type Connection, type Edge, type EdgeChange, type NodeChange, type XYPosition,
} from '@xyflow/react'
import { ChevronRight, Circle, FolderCode, GitFork, GripVertical, Layers3, Play, Save, Search, UserRound, Workflow as WorkflowIcon } from 'lucide-react'
import '@xyflow/react/dist/style.css'
import { ApiError, message, request, type Blueprint, type Kind, type Profile, type Run, type Source, type Spec, type Workflow } from './api'
import { blocks, graphId, groups, isTrigger, kinds, newSpec, nodeTypes, StepContext, Tile, type FlowNode } from './blocks'
import { IdleWarning, Inspector } from './Inspector'
import { Results, type Tab } from './Results'
import { SourceDialog } from './SourceDialog'
import { OpenAIKeyDialog } from './OpenAIKeyDialog'
import { TemplatesDialog } from './TemplatesDialog'
import { reportRoute } from './browserReportLinks'
import { Workspace, type Account } from './Workspace'
import type { Project } from './workspaceData'
import { ProjectPresence } from './ProjectPresence'
import { useProjectSync, type ProjectDetail } from './useProjectSync'
import { useNodeEditing, type BoardConnection } from './useNodeEditing'
import s from './studio.module.css'
import workspaceStyles from './workspace.module.css'

const markerEnd = { type: MarkerType.ArrowClosed, color: '#659789', width: 15, height: 15 }
// Keep clicks and drags on opposite sides of the same pointer movement threshold.
const nodeDragDistance = 4
type PendingDrag = { id: string; start: XYPosition; position?: XYPosition; offset?: XYPosition; ended?: boolean }

function anchoredPosition(drag: PendingDrag, current: XYPosition, point: XYPosition): XYPosition {
  drag.offset ??= { x: current.x - drag.start.x, y: current.y - drag.start.y }
  return { x: point.x + drag.offset.x, y: point.y + drag.offset.y }
}

const toFlow = (spec: Spec): FlowNode => ({ id: spec.id, type: 'block', position: { x: spec.x, y: spec.y }, data: { spec } })
const branchLabel = (port?: string | null) => port === 'yes' ? 'Да' : port === 'no' ? 'Нет' : undefined

function downloadDraft(draft: Blueprint | Workflow, filename: string) {
  const file = new Blob([JSON.stringify(draft, null, 2) + '\n'], { type: 'application/json;charset=utf-8' })
  const link = document.createElement('a')
  link.href = URL.createObjectURL(file); link.download = filename; link.click()
  window.setTimeout(() => URL.revokeObjectURL(link.href), 1000)
}

function Studio({ project, user }: { project?: Project; user?: Account }) {
  const projectId = project?.id
  const mayEdit = !project || project.role === 'owner' || project.role === 'editor'
  const mayRun = !project || project.can_run
  const canvas = useRef<HTMLDivElement>(null)
  const connection = useRef<BoardConnection | null>(null)
  const drag = useRef<PendingDrag | null>(null)
  const [nodes, setNodes, onNodesChange] = useNodesState<FlowNode>([])
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([])
  const [name, setName] = useState('')
  const [files, setFiles] = useState<Source[]>([])
  const [profiles, setProfiles] = useState<Profile[]>([])
  const [focusedNode, setFocusedNode] = useState<string>()
  const [query, setQuery] = useState('')
  const [ready, setReady] = useState(false)
  const [dirty, setDirty] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | ApiError>('')
  const missingSources = error instanceof ApiError && error.code === 'missing_sources'
  const [run, setRun] = useState<Run | null>(null)
  const [inspectedDelivery, setInspectedDelivery] = useState<{ runId: string; nodeId: string }>()
  const [pollingRun, setPollingRun] = useState<string>()
  const [overlay, setOverlay] = useState(false)
  const [tab, setTab] = useState<Tab>(() => new URLSearchParams(window.location.search).get('tab') === 'history' ? 'history' : 'findings')
  const [sourceOpen, setSourceOpen] = useState(false)
  const [keyOpen, setKeyOpen] = useState(!projectId && new URLSearchParams(window.location.search).get('connect') === 'openai')
  const [templatesOpen, setTemplatesOpen] = useState(false)
  const [reload, setReload] = useState(0)
  const { screenToFlowPosition, fitView } = useReactFlow<FlowNode>()
  const selectedNode = nodes.find(n => n.selected && n.id === focusedNode) ?? nodes.find(n => n.selected)
  const selected = selectedNode?.data.spec
  const selection = selectedNode?.id
  const manual = nodes.filter(n => n.data.spec.kind === 'manual')
  const trigger = manual.find(n => n.id === selection) ?? manual[0]
  const ciStart = !trigger && nodes.some(n => n.data.spec.kind === 'git_event')
  const runId = run?.id
  const live = run?.status === 'running'
  const loadWorkflow = useCallback((w: Workflow, preserveSelection = false) => {
    const first = w.nodes.find(n => n.kind === 'explain')?.id ?? w.nodes.find(n => !isTrigger(n.kind))?.id ?? w.nodes[0]?.id
    setName(w.name); setFiles(w.files)
    if (w.files.length) setError(previous => previous instanceof ApiError && previous.code === 'missing_sources' ? '' : previous)
    if (!preserveSelection) setFocusedNode(first)
    setNodes(old => w.nodes.map(n => {
      const previous = old.find(item => item.id === n.id)
      return { ...previous, ...toFlow(n), selected: preserveSelection ? previous?.selected : n.id === first }
    }))
    setEdges(w.edges.map(e => ({ ...e, sourceHandle: e.branch, label: branchLabel(e.branch), markerEnd })))
  }, [setNodes, setEdges])
  const sync = useProjectSync(projectId, {
    snapshot: () => ({ ...graph(), files }), apply: canonical => loadWorkflow(canonical, true),
    saved: () => setDirty(false), clientId: () => connection.current?.getClientId(),
  })
  const editing = useNodeEditing(connection, sync.flush, setError)
  const selectedLock = editing.locks.find(lock => lock.node_id === selection)
  const online = editing.status === 'online'
  const canEdit = (id: string) => mayEdit && (!projectId || (editing.active === id &&
    !!editing.own && editing.own.lease_id === connection.current?.getLeaseId()))
  const occupied = (id: string) => editing.locks.some(lock => lock.node_id === id && !lock.mine)
  const protectedEdge = (edge: Pick<Edge, 'source' | 'target'>) => occupied(edge.source) || occupied(edge.target)
  const blockedByNeighbour = !!selection && edges.some(edge =>
    (edge.source === selection && occupied(edge.target)) || (edge.target === selection && occupied(edge.source)))
  const { init: initProject } = sync
  function touch(leaseId?: string) {
    if (projectId) sync.touch(leaseId)
    setDirty(true); setOverlay(false); setInspectedDelivery(undefined); setError('')
  }
  function editedNode(id: string) {
    connection.current?.noteActivity(id)
    return connection.current?.getLeaseId()
  }
  function select(id?: string) {
    setInspectedDelivery(undefined)
    setFocusedNode(id)
    if (projectId && mayEdit) editing.select(id ?? null)
    drag.current = null
  }

  // A drag may start before the server grants the block. Anchor the entire gesture to the
  // freshly synchronized position, including events arriving after the lock was granted.
  useEffect(() => {
    const pending = drag.current
    if (!pending?.position || editing.active !== pending.id) return
    const session = connection.current
    if (!session?.getLeaseId()) return
    const node = nodes.find(n => n.id === pending.id)
    if (!node) return
    const position = anchoredPosition(pending, node.position, pending.position)
    pending.position = undefined
    if (pending.ended) drag.current = null
    if (node.position.x === position.x && node.position.y === position.y) return
    setNodes(list => list.map(n => n.id === pending.id ? { ...n, position } : n))
    session.noteActivity(pending.id)
    sync.touch(session.getLeaseId())
    setDirty(true)
  }, [editing.active, nodes, setNodes, sync.touch])

  function changeNodes(changes: NodeChange<FlowNode>[]) {
    const allowed: NodeChange<FlowNode>[] = []
    for (const change of changes) {
      if (change.type === 'remove' && !canEdit(change.id)) continue
      if (change.type === 'position') {
        const pending = drag.current?.id === change.id ? drag.current : null
        if (!canEdit(change.id)) {
          if (pending && change.position) { pending.position = change.position; pending.ended = !change.dragging }
          continue
        }
        if (pending && change.position) {
          const node = nodes.find(n => n.id === change.id)
          if (!node) continue
          pending.position = undefined
          allowed.push({ ...change, position: anchoredPosition(pending, node.position, change.position) })
          if (!change.dragging) drag.current = null
          continue
        }
      }
      allowed.push(change)
    }
    if (allowed.length) onNodesChange(allowed)
    // An edge click, keyboard action or rectangle selection can deselect the inspected node.
    const toggles = allowed.filter(change => change.type === 'select')
    if (selection && toggles.some(change => change.id === selection && !change.selected)) {
      const remaining = nodes.find(n => n.selected && !toggles.some(change => change.id === n.id))
      select(toggles.find(change => change.selected)?.id ?? remaining?.id)
    }
    const edit = allowed.find(c => c.type === 'remove' || (c.type === 'position' && c.position !== undefined))
    if (edit && 'id' in edit) touch(editedNode(edit.id))
  }

  useEffect(() => {
    let active = true
    const project = projectId ? 'projects/' + projectId : undefined
    const initial = project ? request<ProjectDetail>(project) : request<Workflow>('workflow')
    Promise.all([initial, request<Profile[]>(project ? project + '/connections' : 'connections')])
      .then(([w, connections]) => {
        if (!active) return
        if ('workflow' in w) { initProject(w); loadWorkflow(w.workflow); setDirty(false) }
        else loadWorkflow(w)
        setProfiles(connections)
        setReady(true); setError('')
      }).catch(e => { if (active) setError(message(e)) })
    return () => { active = false }
  }, [loadWorkflow, initProject, projectId, reload])

  useEffect(() => {
    if (!runId || !live) return
    const path = 'runs/' + runId
    const stream = new EventSource('/api/' + path + '/events')
    let active = true
    let timer: number | undefined
    function updateRun(current: Run) {
      if (!active) return
      setRun(previous => previous?.id === current.id ? current : previous)
      if (current.status !== 'running') {
        stream.close()
        setPollingRun(undefined)
      }
    }
    async function poll() {
      try {
        const current = await request<Run>(path)
        updateRun(current)
        if (current.status !== 'running') return
      } catch {
        // Keep retrying while the connection is unavailable.
      }
      if (active) timer = window.setTimeout(poll, 2000)
    }
    setPollingRun(undefined)
    stream.onmessage = event => updateRun(JSON.parse(event.data) as Run)
    stream.onerror = () => {
      stream.close()
      setPollingRun(runId)
      void poll()
    }
    return () => {
      active = false
      stream.close()
      window.clearTimeout(timer)
    }
  }, [runId, live])

  function graph(): Blueprint {
    return { name, nodes: nodes.map(n => ({ ...n.data.spec, ...n.position })),
      edges: edges.map(e => ({ id: e.id, source: e.source, target: e.target,
        branch: e.sourceHandle === 'yes' || e.sourceHandle === 'no' ? e.sourceHandle : null })) }
  }
  function downloadCiGraph() {
    downloadDraft(graph(), 'ci-workflow.json')
  }
  async function commit(start: boolean) {
    if (start ? !mayRun : !mayEdit) return
    setBusy(true); setError('')
    try {
      if (projectId) {
        const revision = await sync.flush()
        if (start && trigger) {
          const current = await request<Run>('projects/' + projectId + '/runs', 'POST', { trigger: trigger.id, revision })
          setRun(current); setOverlay(true); setTab('findings')
        }
        return
      }
      const workflow = start && !dirty ? await request<Workflow>('workflow') : { ...graph(), files }
      if (start && trigger) {
        const triggers = workflow.nodes.filter(n => n.kind === 'manual')
        const selectedTrigger = triggers.find(n => n.id === trigger.id) ?? triggers[0]
        if (!selectedTrigger) throw new Error('В сохранённом сценарии нет ручного запуска')
        if (!dirty) loadWorkflow(workflow)
        const current = await request<Run>('runs', 'POST', { workflow, trigger: selectedTrigger.id })
        setRun(current); setOverlay(true); setTab('findings')
      } else {
        await request('workflow', 'PUT', workflow)
        setDirty(false)
      }
    } catch (e) { setError(e instanceof ApiError ? e : message(e)) }
    finally { setBusy(false) }
  }
  function add(kind: Kind, position?: XYPosition) {
    if (!mayEdit || !ready || busy) return
    const last = nodes.at(-1)?.position ?? { x: 0, y: 0 }
    const point = position ?? { x: last.x + 260, y: last.y }
    const spec = newSpec(kind, point.x, point.y)
    setNodes(current => [...current.map(n => n.selected ? { ...n, selected: false } : n), { ...toFlow(spec), selected: true }])
    select(spec.id); touch()
    if (!position) requestAnimationFrame(() => void fitView({ duration: 220, padding: 0.2, maxZoom: 1 }))
  }
  function connect(link: Connection) {
    if (!valid(link)) return
    setEdges(current => addEdge({ ...link, id: graphId(), label: branchLabel(link.sourceHandle), markerEnd }, current))
    if (editing.active && (link.source === editing.active || link.target === editing.active)) touch(editedNode(editing.active))
    else touch()
  }
  function changeEdges(changes: EdgeChange<Edge>[]) {
    onEdgesChange(changes)
    const removed = new Set(changes.filter(change => change.type === 'remove').map(change => change.id))
    if (!removed.size) return
    const active = editing.active
    const incident = active && edges.some(edge => removed.has(edge.id) && (edge.source === active || edge.target === active))
    touch(incident ? editedNode(active) : undefined)
  }
  function valid(link: Connection | Edge) {
    const target = nodes.find(n => n.id === link.target)
    if (!mayEdit || (projectId && !online) || protectedEdge(link) || !target || link.source === link.target || isTrigger(target.data.spec.kind)) return false
    const pending = [link.target], seen = new Set<string>()
    while (pending.length) {
      const next = pending.pop()!
      if (next === link.source) return false
      if (seen.has(next)) continue
      seen.add(next); pending.push(...edges.filter(e => e.source === next).map(e => e.target))
    }
    return true
  }
  function remove() {
    if (busy || !selection || !canEdit(selection) || blockedByNeighbour || (!mayRun && selected?.kind === 'schedule' && selected.enabled)) return
    setNodes(current => current.filter(n => n.id !== selection))
    setEdges(current => current.filter(e => e.source !== selection && e.target !== selection))
    touch(editedNode(selection)); select()
  }
  function update(patch: Partial<Spec>) {
    if (busy || !selection || !canEdit(selection)) return
    setNodes(current => current.map(n => n.id === selection ? { ...n, data: { spec: { ...n.data.spec, ...patch } } } : n))
    touch(editedNode(selection))
  }
  const shownSteps = overlay ? run?.steps ?? [] : []
  const shownNodes = projectId ? nodes.map(node => {
    const lock = editing.locks.find(item => item.node_id === node.id)
    const available = mayEdit && online && (!lock || lock.mine)
    return { ...node, draggable: available && !busy, connectable: available && !busy,
      deletable: canEdit(node.id) && !busy && (mayRun || node.data.spec.kind !== 'schedule' || !node.data.spec.enabled), data: { ...node.data, lock } }
  }) : nodes
  const inspectedWebhook = run && inspectedDelivery?.runId === run.id
    ? run.steps.find(step => step.node_id === inspectedDelivery.nodeId && step.kind === 'webhook') : undefined
  const activeBranches = new Map(shownSteps.filter(step => step.branch).map(step => [step.node_id, step.branch]))
  const shownEdges = activeBranches.size ? edges.map(edge =>
    edge.sourceHandle && activeBranches.get(edge.source) === edge.sourceHandle
      ? { ...edge, style: { stroke: '#287453', strokeWidth: 3 }, markerEnd: { ...markerEnd, color: '#287453' }, labelStyle: { fontWeight: 700 } }
      : edge) : edges

  if (projectId && sync.forbidden) return <main className={s.studio}><div className={s.workspaceHead}>
    <div><h1>Нет доступа к проекту</h1><a href="/projects">Мои проекты</a></div></div></main>
  return <main className={s.studio}>
    <header className={s.top}><div className={s.brand}><span><GitFork size={22}/></span>Garden</div>
      <span className={s.divider}/><span className={s.productName}>Security Workflow</span><div className={s.headerActions}>
        {projectId && user && ready && <ProjectPresence projectId={projectId} user={user} canvas={canvas}
          connection={connection} onEditState={editing.receive}/>}
        <a className={s.local} href={projectId ? '/profile' : '/projects'} aria-label={projectId ? 'Личный кабинет' : undefined}>
          {projectId ? <><UserRound size={15}/><span>Личный кабинет</span></> : 'Мои проекты'}</a>
      </div></header>
    <div className={s.workspaceHead}><div><div className={s.crumb}><a href="/projects">Мои проекты</a> <ChevronRight size={12}/> {projectId ? name : 'Локальная студия'}</div>
      <h1>{mayEdit ? 'Редактор сценария' : 'Просмотр сценария'}</h1></div>
      <div className={s.controls}>
        {mayEdit && <span className={s.saveState}><Circle size={8} fill="currentColor"/>{dirty ? 'Есть изменения' : ready ? 'Сохранено' : 'Загрузка'}</span>}
        {mayEdit && profiles.some(p => p.id === 'openai' && p.local_key_entry) && <button onClick={() => setKeyOpen(true)}>
          {profiles.find(p => p.id === 'openai')?.configured ? 'Ключ OpenAI' : 'Подключить OpenAI'}</button>}
        {projectId ? <><a className={s.editorLink} href="/templates">Шаблоны</a>
          {mayEdit && <a className={s.editorLink} href={'/projects/' + projectId + '/access'}>Участники</a>}</>
          : <button disabled={!ready || busy || live} onClick={() => setTemplatesOpen(true)}>Шаблоны</button>}
        {mayEdit && <button disabled={!ready || busy || !dirty} onClick={() => void commit(false)}><Save size={16}/>Сохранить</button>}
        {mayRun && <button className={s.primary} disabled={!trigger || busy || live} onClick={() => void commit(true)}
          title={ciStart ? 'Для запуска из редактора добавьте блок «Ручной запуск».' : undefined}>
          <Play size={15} fill="currentColor"/>{live ? 'Выполняется' : ciStart ? 'Запуск из CI' : 'Запустить'}</button>}</div></div>
    {error && <div role="alert" className={s.error}>{error instanceof ApiError ? error.message : error}{' '}
      {missingSources && (mayEdit
        ? <button onClick={() => setSourceOpen(true)}>Добавить исходники</button>
        : 'Попросите редактора проекта добавить файлы.')}
      {!ready && <button onClick={() => setReload(n => n + 1)}>Повторить</button>}
    </div>}
    {projectId && mayEdit && editing.own && <IdleWarning key={editing.own.lease_id} lock={editing.own} renew={async () => {
      try { if (editing.own) await connection.current?.continueEditing(editing.own.node_id) }
      catch (err) { setError(message(err)) }
    }}/>}
    {projectId && sync.issue && <div role="alert" className={s.error}>{sync.issue} {dirty &&
      <button onClick={() => downloadDraft({ ...graph(), files }, 'garden-draft.json')}>Скачать мой черновик</button>} {(sync.conflict || (dirty && editing.interrupted)) &&
      <button onClick={() => { if (window.confirm('Заменить несохранённые правки текущей версией проекта?')) setReload(n => n + 1) }}>
        Загрузить общую версию</button>}</div>}
    {live && pollingRun === runId && <div role="status" className={s.error}>Связь с потоком прервана. Проверяем статус прогона каждые две секунды.</div>}
    <div className={s.workspace} data-viewer={!mayEdit || undefined}>
      {mayEdit && <aside className={s.library}><h2><Layers3 size={16}/>Библиотека блоков</h2>
        <div className={s.search}><Search size={15}/><input aria-label="Найти блок" placeholder="Найти блок" value={query} onChange={e => setQuery(e.target.value)}/></div>
        {groups.map(group => { const items = kinds.filter(k => blocks[k].group === group && blocks[k].name.toLowerCase().includes(query.toLowerCase()))
          return items.length > 0 && <div className={s.group} key={group}><h3>{group}</h3>{items.map(kind =>
            <button key={kind} draggable={ready} disabled={!ready || busy} onClick={() => add(kind)}
              onDragStart={e => { e.dataTransfer.setData('application/garden-block', kind); e.dataTransfer.effectAllowed = 'copy' }}
              title={'Добавить · ' + blocks[kind].name}><Tile kind={kind}/><span>{blocks[kind].name}</span><GripVertical size={13}/></button>)}</div> })}
      </aside>}
      <section className={s.board}>
        <div className={s.boardHead}><span className={s.boardIcon}><WorkflowIcon size={19}/></span>
          <input aria-label="Название сценария" maxLength={100} value={name} disabled={!ready || busy} readOnly={!mayEdit}
            onChange={e => { setName(e.target.value); touch() }} />
          <button disabled={!ready || busy} onClick={() => setSourceOpen(true)}><FolderCode size={15}/>Исходники <b>{files.length}</b></button></div>
        <div className={s.canvas} ref={canvas} onKeyDownCapture={e => {
          if (!(e.target instanceof HTMLElement) || !e.target.matches('.react-flow__node')) return
          const id = e.target.dataset.id
          if (!id) return
          if (e.key === 'Enter' || e.key === ' ') select(id)
          if (projectId && mayEdit && e.key.startsWith('Arrow') && !canEdit(id) && online && !occupied(id)) {
            const node = nodes.find(n => n.id === id && n.selected)
            if (node && drag.current?.id !== id) { select(id); drag.current = { id, start: node.position } }
          }
        }} onDragOver={e => { e.preventDefault(); e.dataTransfer.dropEffect = 'copy' }}
          onDrop={e => { e.preventDefault(); const kind = e.dataTransfer.getData('application/garden-block') as Kind
            if (kinds.includes(kind)) add(kind, screenToFlowPosition({ x: e.clientX, y: e.clientY })) }}>
          {ready && <StepContext.Provider value={shownSteps}><ReactFlow<FlowNode> nodes={shownNodes} edges={shownEdges} nodeTypes={nodeTypes}
            onNodesChange={changeNodes} onEdgesChange={changeEdges}
            onBeforeDelete={async ({ nodes, edges }) => !projectId ||
              (mayEdit && online && nodes.every(n => canEdit(n.id) && (mayRun || n.data.spec.kind !== 'schedule' || !n.data.spec.enabled)) && edges.every(edge => !protectedEdge(edge)))}
            nodeDragThreshold={nodeDragDistance} nodeClickDistance={nodeDragDistance}
            onNodeClick={(event, n) => {
              if ((event.ctrlKey || event.metaKey) && n.selected) return
              select(n.id)
            }} onPaneClick={() => select()}
            onNodeDragStart={(_, n) => {
              select(n.id)
              if (projectId && !canEdit(n.id) && !occupied(n.id)) drag.current = { id: n.id, start: n.position }
            }}
            onConnect={connect} isValidConnection={valid} fitView fitViewOptions={{ padding: 0.24, maxZoom: 1.05 }}
            nodesDraggable={mayEdit && !busy} nodesConnectable={mayEdit && !busy} deleteKeyCode={busy || !mayEdit ? null : ['Backspace', 'Delete']}
            defaultEdgeOptions={{ type: 'smoothstep', markerEnd }} minZoom={0.17} maxZoom={1.8} onlyRenderVisibleElements={false}>
            <Background variant={BackgroundVariant.Dots} gap={20} size={1.25} color="#c9d4cf"/>
            <Controls showInteractive={false}/>
            <Panel position="top-left"><span className={s.counter}><Layers3 size={13}/>Блоки · {nodes.length} / Связи · {edges.length}</span></Panel>
          </ReactFlow></StepContext.Provider>}
        </div>
      </section>
      <Inspector node={selected} profiles={profiles} step={shownSteps.find(n => n.node_id === selection)} findings={run?.findings ?? []}
        sharedProject={Boolean(projectId)}
        runId={runId} inspectedWebhook={inspectedWebhook} closeWebhook={() => setInspectedDelivery(undefined)} update={update} remove={remove}
        readOnly={!mayEdit} mayRun={mayRun} editing={projectId && selected ? { lock: selectedLock, editable: canEdit(selected.id) && !busy,
          interrupted: editing.interrupted === selected.id,
          pending: editing.pending === selected.id, online, start: () => select(selected.id), finish: () => editing.select(null) } : undefined}
        removeBlocked={blockedByNeighbour}
        downloadCiGraph={downloadCiGraph} connectOpenAI={() => setKeyOpen(true)}/>
    </div>
    <Results run={run} projectId={projectId} tab={tab} setTab={setTab} inspectWebhook={(runId, nodeId) => {
      setInspectedDelivery({ runId, nodeId })
      requestAnimationFrame(() => document.getElementById('block-inspector')?.focus())
    }} open={current => {
      setRun(current); setOverlay(false); setTab('steps')
    }}/>
    {sourceOpen && <SourceDialog files={files} close={() => setSourceOpen(false)}
      apply={mayEdit ? next => { setFiles(next); setSourceOpen(false); touch() } : undefined}/>}
    {keyOpen && ready && <OpenAIKeyDialog close={() => {
      setKeyOpen(false)
      const url = new URL(window.location.href); url.searchParams.delete('connect'); window.history.replaceState(null, '', url)
    }} connected={profile => setProfiles(list => list.map(p => p.id === profile.id ? profile : p))}/>}
    {templatesOpen && <TemplatesDialog profiles={profiles} current={graph()}
      close={() => setTemplatesOpen(false)} apply={(draft, source, focus) => {
        const selectedId = focus ?? draft.nodes.find(n => n.kind === 'explain')?.id ?? draft.nodes[0]?.id
        setName(draft.name); if (source) setFiles(source)
        setNodes(draft.nodes.map(n => ({ ...toFlow({ ...n, enabled: false }), selected: n.id === selectedId })))
        setEdges(draft.edges.map(e => ({ ...e, sourceHandle: e.branch, label: branchLabel(e.branch), markerEnd })))
        setFocusedNode(selectedId)
        setTemplatesOpen(false); setRun(null); touch()
        requestAnimationFrame(() => void fitView({ duration: 200, padding: 0.18, maxZoom: 1 }))
      }}/>}
  </main>
}

const location = window.location
const localReport = new URLSearchParams(location.search).get('local') === '1' && reportRoute.exec(location.pathname)
const BrowserReportPage = lazy(() => import('./BrowserReportPage'))
const BrowserNotification = lazy(() => import('./BrowserNotification'))
const legacy = location.pathname === '/local' || (location.pathname === '/' && !location.hash &&
  (new URLSearchParams(location.search).get('tab') === 'history' || new URLSearchParams(location.search).get('connect') === 'openai'))
function editor(project?: Project, user?: Account) {
  return <ReactFlowProvider key={project ? project.id + '/' + project.role : 'local'}><Studio project={project} user={user}/></ReactFlowProvider>
}
createRoot(document.getElementById('root')!).render(<StrictMode>
  {localReport ? <div className={workspaceStyles.workspace}><Suspense fallback={<p role="status">Загружаем отчёт…</p>}>
    <BrowserReportPage runId={localReport[1]} nodeId={localReport[2]} local/>
  </Suspense></div> : legacy ? <>{editor()}<Suspense fallback={null}><BrowserNotification local/></Suspense></>
    : <Workspace renderEditor={editor} />}
</StrictMode>)

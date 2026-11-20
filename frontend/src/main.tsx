import { StrictMode, useCallback, useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import {
  addEdge, Background, BackgroundVariant, Controls, MarkerType, Panel, ReactFlow, ReactFlowProvider,
  useEdgesState, useNodesState, useReactFlow, type Connection, type Edge, type XYPosition,
} from '@xyflow/react'
import { ChevronRight, Circle, FolderCode, GitFork, GripVertical, Layers3, Play, Save, Search, Workflow as WorkflowIcon } from 'lucide-react'
import '@xyflow/react/dist/style.css'
import { message, request, type Kind, type Profile, type Run, type Source, type Spec, type Summary, type Workflow } from './api'
import { blocks, groups, isTrigger, kinds, newSpec, nodeTypes, StepContext, Tile, type FlowNode } from './blocks'
import { Inspector } from './Inspector'
import { Results, type Tab } from './Results'
import { SourceDialog } from './SourceDialog'
import { OpenAIKeyDialog } from './OpenAIKeyDialog'
import { TemplatesDialog } from './TemplatesDialog'
import s from './studio.module.css'

const markerEnd = { type: MarkerType.ArrowClosed, color: '#659789', width: 15, height: 15 }
const toFlow = (spec: Spec): FlowNode => ({ id: spec.id, type: 'block', position: { x: spec.x, y: spec.y }, data: { spec } })
const branchLabel = (port?: string | null) => port === 'yes' ? 'Да' : port === 'no' ? 'Нет' : undefined

function Studio() {
  const [nodes, setNodes, onNodesChange] = useNodesState<FlowNode>([])
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([])
  const [name, setName] = useState('')
  const [files, setFiles] = useState<Source[]>([])
  const [profiles, setProfiles] = useState<Profile[]>([])
  const [selection, setSelection] = useState<string>()
  const [query, setQuery] = useState('')
  const [ready, setReady] = useState(false)
  const [dirty, setDirty] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [run, setRun] = useState<Run | null>(null)
  const [overlay, setOverlay] = useState(false)
  const [history, setHistory] = useState<Summary[]>([])
  const [tab, setTab] = useState<Tab>('findings')
  const [sourceOpen, setSourceOpen] = useState(false)
  const [keyOpen, setKeyOpen] = useState(new URLSearchParams(window.location.search).get('connect') === 'openai')
  const [templatesOpen, setTemplatesOpen] = useState(false)
  const [reload, setReload] = useState(0)
  const { screenToFlowPosition, fitView } = useReactFlow<FlowNode>()
  const selected = nodes.find(n => n.id === selection)?.data.spec
  const manual = nodes.filter(n => n.data.spec.kind === 'manual')
  const trigger = manual.find(n => n.id === selection) ?? manual[0]
  const runId = run?.id
  const live = run?.status === 'running'
  const touch = useCallback(() => { setDirty(true); setOverlay(false); setError('') }, [])
  const loadWorkflow = useCallback((w: Workflow) => {
    const first = w.nodes.find(n => n.kind === 'explain')?.id ?? w.nodes.find(n => !isTrigger(n.kind))?.id ?? w.nodes[0]?.id
    setName(w.name); setFiles(w.files); setSelection(first)
    setNodes(w.nodes.map(n => ({ ...toFlow(n), selected: n.id === first })))
    setEdges(w.edges.map(e => ({ ...e, sourceHandle: e.branch, label: branchLabel(e.branch), markerEnd })))
  }, [setNodes, setEdges])

  useEffect(() => {
    let active = true
    Promise.all([request<Workflow>('workflow'), request<Profile[]>('connections'), request<Summary[]>('runs')])
      .then(([w, connections, recent]) => {
        if (!active) return
        loadWorkflow(w)
        setProfiles(connections); setHistory(recent)
        setReady(true); setError('')
      }).catch(e => { if (active) setError(message(e)) })
    return () => { active = false }
  }, [loadWorkflow, reload])

  useEffect(() => {
    if (!runId || !live) return
    const stream = new EventSource('/api/runs/' + runId + '/events')
    stream.onmessage = event => {
      const current = JSON.parse(event.data) as Run
      setRun(current)
      if (current.status !== 'running') {
        stream.close()
        request<Summary[]>('runs').then(setHistory).catch(e => setError(message(e)))
      }
    }
    return () => stream.close()
  }, [runId, live])

  useEffect(() => {
    if (tab !== 'history' || !ready) return
    let active = true
    const refresh = () => request<Summary[]>('runs').then(rows => { if (active) setHistory(rows) })
      .catch(e => { if (active) setError(message(e)) })
    void refresh()
    const timer = window.setInterval(refresh, 5000)
    return () => { active = false; clearInterval(timer) }
  }, [tab, ready])

  function graph(): Workflow {
    return { name, files, nodes: nodes.map(n => ({ ...n.data.spec, ...n.position })),
      edges: edges.map(e => ({ id: e.id, source: e.source, target: e.target,
        branch: e.sourceHandle === 'yes' || e.sourceHandle === 'no' ? e.sourceHandle : null })) }
  }
  async function commit(start: boolean) {
    setBusy(true); setError('')
    try {
      const workflow = start && !dirty ? await request<Workflow>('workflow') : graph()
      if (start && trigger) {
        const triggers = workflow.nodes.filter(n => n.kind === 'manual')
        const selectedTrigger = triggers.find(n => n.id === trigger.id) ?? triggers[0]
        if (!selectedTrigger) throw new Error('В сохранённом сценарии нет ручного запуска')
        if (!dirty) loadWorkflow(workflow)
        const current = await request<Run>('runs', 'POST', { workflow, trigger: selectedTrigger.id })
        setRun(current); setOverlay(true); setTab('findings')
      } else await request('workflow', 'PUT', workflow)
      setDirty(false)
    } catch (e) { setError(message(e)) }
    finally { setBusy(false) }
  }
  function add(kind: Kind, position?: XYPosition) {
    if (!ready || busy) return
    const last = nodes.at(-1)?.position ?? { x: 0, y: 0 }
    const point = position ?? { x: last.x + 260, y: last.y }
    const spec = newSpec(kind, point.x, point.y)
    setNodes(current => [...current, toFlow(spec)]); setSelection(spec.id); touch()
    if (!position) requestAnimationFrame(() => void fitView({ duration: 220, padding: 0.2, maxZoom: 1 }))
  }
  function connect(link: Connection) {
    setEdges(current => addEdge({ ...link, id: crypto.randomUUID(), label: branchLabel(link.sourceHandle), markerEnd }, current)); touch()
  }
  function valid(link: Connection | Edge) {
    if (link.source === link.target || isTrigger(nodes.find(n => n.id === link.target)!.data.spec.kind)) return false
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
    if (busy) return
    setNodes(current => current.filter(n => n.id !== selection))
    setEdges(current => current.filter(e => e.source !== selection && e.target !== selection))
    setSelection(undefined); touch()
  }
  function update(patch: Partial<Spec>) {
    if (busy) return
    setNodes(current => current.map(n => n.id === selection ? { ...n, data: { spec: { ...n.data.spec, ...patch } } } : n)); touch()
  }
  const shownSteps = overlay ? run?.steps ?? [] : []

  return <main className={s.studio}>
    <header className={s.top}><div className={s.brand}><span><GitFork size={22}/></span>Garden</div>
      <span className={s.divider}/><span>Security Workflow</span><span className={s.local}><i/>Локальная среда</span></header>
    <div className={s.workspaceHead}><div><div className={s.crumb}>Рабочая область <ChevronRight size={12}/> Сценарии</div>
      <h1>Редактор сценария</h1></div>
      <div className={s.controls}><span className={s.saveState}><Circle size={8} fill="currentColor"/>{dirty ? 'Есть изменения' : ready ? 'Сохранено' : 'Загрузка'}</span>
        {profiles.some(p => p.id === 'openai' && p.local_key_entry) && <button onClick={() => setKeyOpen(true)}>
          {profiles.find(p => p.id === 'openai')?.configured ? 'Ключ OpenAI' : 'Подключить OpenAI'}</button>}
        <button disabled={!ready || busy || live} onClick={() => setTemplatesOpen(true)}>Шаблоны</button>
        <button disabled={!ready || busy || !dirty} onClick={() => void commit(false)}><Save size={16}/>Сохранить</button>
        <button className={s.primary} disabled={!trigger || busy || live} onClick={() => void commit(true)}>
          <Play size={15} fill="currentColor"/>{live ? 'Выполняется' : 'Запустить'}</button></div></div>
    {error && <div role="alert" className={s.error}>{error} {!ready && <button onClick={() => setReload(n => n + 1)}>Повторить</button>}</div>}
    <div className={s.workspace}>
      <aside className={s.library}><h2><Layers3 size={16}/>Библиотека блоков</h2>
        <div className={s.search}><Search size={15}/><input aria-label="Найти блок" placeholder="Найти блок" value={query} onChange={e => setQuery(e.target.value)}/></div>
        {groups.map(group => { const items = kinds.filter(k => blocks[k].group === group && blocks[k].name.toLowerCase().includes(query.toLowerCase()))
          return items.length > 0 && <div className={s.group} key={group}><h3>{group}</h3>{items.map(kind =>
            <button key={kind} draggable={ready} disabled={!ready || busy} onClick={() => add(kind)}
              onDragStart={e => { e.dataTransfer.setData('application/garden-block', kind); e.dataTransfer.effectAllowed = 'copy' }}
              title={'Добавить · ' + blocks[kind].name}><Tile kind={kind}/><span>{blocks[kind].name}</span><GripVertical size={13}/></button>)}</div> })}
      </aside>
      <section className={s.board}>
        <div className={s.boardHead}><span className={s.boardIcon}><WorkflowIcon size={19}/></span>
          <input aria-label="Название сценария" maxLength={100} value={name} disabled={!ready || busy}
            onChange={e => { setName(e.target.value); touch() }} />
          <button disabled={!ready || busy} onClick={() => setSourceOpen(true)}><FolderCode size={15}/>Исходники <b>{files.length}</b></button></div>
        <div className={s.canvas} onDragOver={e => { e.preventDefault(); e.dataTransfer.dropEffect = 'copy' }}
          onDrop={e => { e.preventDefault(); const kind = e.dataTransfer.getData('application/garden-block') as Kind
            if (kinds.includes(kind)) add(kind, screenToFlowPosition({ x: e.clientX, y: e.clientY })) }}>
          {ready && <StepContext.Provider value={shownSteps}><ReactFlow<FlowNode> nodes={nodes} edges={edges} nodeTypes={nodeTypes}
            onNodesChange={changes => {
              onNodesChange(changes)
              if (changes.some(c => c.type === 'remove' || (c.type === 'position' && c.dragging))) touch()
            }} onEdgesChange={changes => { onEdgesChange(changes); if (changes.some(c => c.type === 'remove')) touch() }}
            onNodeClick={(_, n) => setSelection(n.id)} onPaneClick={() => setSelection(undefined)}
            onConnect={connect} isValidConnection={valid} fitView fitViewOptions={{ padding: 0.24, maxZoom: 1.05 }}
            nodesDraggable={!busy} nodesConnectable={!busy} deleteKeyCode={busy ? null : ['Backspace', 'Delete']}
            defaultEdgeOptions={{ type: 'smoothstep', markerEnd }} minZoom={0.17} maxZoom={1.8} onlyRenderVisibleElements={false}>
            <Background variant={BackgroundVariant.Dots} gap={20} size={1.25} color="#c9d4cf"/>
            <Controls showInteractive={false}/>
            <Panel position="top-left"><span className={s.counter}><Layers3 size={13}/>Блоки · {nodes.length} / Связи · {edges.length}</span></Panel>
          </ReactFlow></StepContext.Provider>}
        </div>
      </section>
      <Inspector node={selected} profiles={profiles} step={shownSteps.find(n => n.node_id === selection)} update={update} remove={remove}
        connectOpenAI={() => setKeyOpen(true)}/>
    </div>
    <Results run={run} history={history} tab={tab} setTab={setTab} open={async key => {
      try { setRun(await request<Run>('runs/' + key)); setOverlay(false); setTab('steps') }
      catch (e) { setError(message(e)) }
    }}/>
    {sourceOpen && <SourceDialog files={files} close={() => setSourceOpen(false)}
      apply={next => { setFiles(next); setSourceOpen(false); touch() }}/>}
    {keyOpen && ready && <OpenAIKeyDialog close={() => {
      setKeyOpen(false)
      const url = new URL(window.location.href); url.searchParams.delete('connect'); window.history.replaceState(null, '', url)
    }} connected={profile => setProfiles(list => list.map(p => p.id === profile.id ? profile : p))}/>}
    {templatesOpen && <TemplatesDialog profiles={profiles} current={{ name, nodes: graph().nodes, edges: graph().edges }}
      close={() => setTemplatesOpen(false)} apply={(draft, source) => {
        setName(draft.name); if (source) setFiles(source)
        setNodes(draft.nodes.map(n => toFlow({ ...n, enabled: false })))
        setEdges(draft.edges.map(e => ({ ...e, sourceHandle: e.branch, label: branchLabel(e.branch), markerEnd })))
        setSelection(draft.nodes.find(n => n.kind === 'explain')?.id ?? draft.nodes[0]?.id)
        setTemplatesOpen(false); setRun(null); touch()
        requestAnimationFrame(() => void fitView({ duration: 200, padding: 0.18, maxZoom: 1 }))
      }}/>}
  </main>
}

createRoot(document.getElementById('root')!).render(<StrictMode><ReactFlowProvider><Studio/></ReactFlowProvider></StrictMode>)

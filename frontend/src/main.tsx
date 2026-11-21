import { lazy, StrictMode, Suspense, useCallback, useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import {
  addEdge, Background, BackgroundVariant, Controls, MarkerType, Panel, ReactFlow, ReactFlowProvider,
  useEdgesState, useNodesState, useReactFlow, type Connection, type Edge, type XYPosition,
} from '@xyflow/react'
import { ChevronRight, Circle, FolderCode, GitFork, GripVertical, Layers3, Play, Save, Search, Workflow as WorkflowIcon } from 'lucide-react'
import '@xyflow/react/dist/style.css'
import { message, request, type Blueprint, type Kind, type Profile, type Run, type Source, type Spec, type Workflow } from './api'
import { blocks, graphId, groups, isTrigger, kinds, newSpec, nodeTypes, StepContext, Tile, type FlowNode } from './blocks'
import { Inspector } from './Inspector'
import { Results, type Tab } from './Results'
import { SourceDialog } from './SourceDialog'
import { OpenAIKeyDialog } from './OpenAIKeyDialog'
import { TemplatesDialog } from './TemplatesDialog'
import { Workspace } from './Workspace'
import { reportRoute } from './browserReportLinks'
import { ProjectPresence } from './ProjectPresence'
import { useProjectSync, type ProjectDetail } from './useProjectSync'
import s from './studio.module.css'
import workspaceStyles from './workspace.module.css'

const markerEnd = { type: MarkerType.ArrowClosed, color: '#659789', width: 15, height: 15 }
const toFlow = (spec: Spec): FlowNode => ({ id: spec.id, type: 'block', position: { x: spec.x, y: spec.y }, data: { spec } })
const branchLabel = (port?: string | null) => port === 'yes' ? 'Да' : port === 'no' ? 'Нет' : undefined

function downloadDraft(draft: Blueprint | Workflow, filename: string) {
  const file = new Blob([JSON.stringify(draft, null, 2) + '\n'], { type: 'application/json;charset=utf-8' })
  const link = document.createElement('a')
  link.href = URL.createObjectURL(file); link.download = filename; link.click()
  window.setTimeout(() => URL.revokeObjectURL(link.href), 1000)
}

function Studio({ projectId }: { projectId?: string }) {
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
  const [inspectedDelivery, setInspectedDelivery] = useState<{ runId: string; nodeId: string }>()
  const [pollingRun, setPollingRun] = useState<string>()
  const [overlay, setOverlay] = useState(false)
  const [tab, setTab] = useState<Tab>(() => new URLSearchParams(window.location.search).get('tab') === 'history' ? 'history' : 'findings')
  const [sourceOpen, setSourceOpen] = useState(false)
  const [keyOpen, setKeyOpen] = useState(!projectId && new URLSearchParams(window.location.search).get('connect') === 'openai')
  const [templatesOpen, setTemplatesOpen] = useState(false)
  const [reload, setReload] = useState(0)
  const { screenToFlowPosition, fitView } = useReactFlow<FlowNode>()
  const selected = nodes.find(n => n.id === selection)?.data.spec
  const manual = nodes.filter(n => n.data.spec.kind === 'manual')
  const trigger = manual.find(n => n.id === selection) ?? manual[0]
  const ciStart = !trigger && nodes.some(n => n.data.spec.kind === 'git_event')
  const runId = run?.id
  const live = run?.status === 'running'
  const loadWorkflow = useCallback((w: Workflow, preserveSelection = false) => {
    const first = w.nodes.find(n => n.kind === 'explain')?.id ?? w.nodes.find(n => !isTrigger(n.kind))?.id ?? w.nodes[0]?.id
    setName(w.name); setFiles(w.files)
    setSelection(old => preserveSelection ? w.nodes.some(n => n.id === old) ? old : undefined : first)
    setNodes(old => w.nodes.map(n => ({ ...old.find(item => item.id === n.id), ...toFlow(n),
      selected: preserveSelection ? old.find(item => item.id === n.id)?.selected : n.id === first })))
    setEdges(w.edges.map(e => ({ ...e, sourceHandle: e.branch, label: branchLabel(e.branch), markerEnd })))
  }, [setNodes, setEdges])
  const sync = useProjectSync(projectId, {
    snapshot: () => ({ ...graph(), files }), apply: canonical => loadWorkflow(canonical, true),
    saved: () => setDirty(false),
  })
  const { init: initProject } = sync
  function touch() {
    if (projectId) sync.touch()
    setDirty(true); setOverlay(false); setInspectedDelivery(undefined); setError('')
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
    setEdges(current => addEdge({ ...link, id: graphId(), label: branchLabel(link.sourceHandle), markerEnd }, current)); touch()
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
      <span className={s.divider}/><span>Security Workflow</span><a className={s.local} href={projectId ? '/profile' : '/projects'}>
        {projectId ? 'Личный кабинет' : 'Мои проекты'}</a></header>
    <div className={s.workspaceHead}><div><div className={s.crumb}><a href="/projects">Мои проекты</a> <ChevronRight size={12}/> {projectId ? name : 'Локальная студия'}</div>
      <h1>Редактор сценария</h1></div>
      <div className={s.controls}>{projectId && ready && <ProjectPresence projectId={projectId}/>}
        <span className={s.saveState}><Circle size={8} fill="currentColor"/>{dirty ? 'Есть изменения' : ready ? 'Сохранено' : 'Загрузка'}</span>
        {profiles.some(p => p.id === 'openai' && p.local_key_entry) && <button onClick={() => setKeyOpen(true)}>
          {profiles.find(p => p.id === 'openai')?.configured ? 'Ключ OpenAI' : 'Подключить OpenAI'}</button>}
        {projectId ? <><a className={s.editorLink} href="/templates">Шаблоны</a>
          <a className={s.editorLink} href={'/projects/' + projectId + '/access'}>Участники</a></>
          : <button disabled={!ready || busy || live} onClick={() => setTemplatesOpen(true)}>Шаблоны</button>}
        <button disabled={!ready || busy || !dirty} onClick={() => void commit(false)}><Save size={16}/>Сохранить</button>
        <button className={s.primary} disabled={!trigger || busy || live} onClick={() => void commit(true)}
          title={ciStart ? 'Для запуска из редактора добавьте блок «Ручной запуск».' : undefined}>
          <Play size={15} fill="currentColor"/>{live ? 'Выполняется' : ciStart ? 'Запуск из CI' : 'Запустить'}</button></div></div>
    {error && <div role="alert" className={s.error}>{error} {!ready && <button onClick={() => setReload(n => n + 1)}>Повторить</button>}</div>}
    {projectId && sync.issue && <div role="alert" className={s.error}>{sync.issue} {sync.conflict && <>
      <button onClick={() => downloadDraft({ ...graph(), files }, 'garden-draft.json')}>Скачать мой черновик</button>
      <button onClick={() => { if (window.confirm('Заменить несохранённые правки текущей версией проекта?')) setReload(n => n + 1) }}>
        Загрузить общую версию</button></>}</div>}
    {live && pollingRun === runId && <div role="status" className={s.error}>Связь с потоком прервана. Проверяем статус прогона каждые две секунды.</div>}
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
          {ready && <StepContext.Provider value={shownSteps}><ReactFlow<FlowNode> nodes={nodes} edges={shownEdges} nodeTypes={nodeTypes}
            onNodesChange={changes => {
              onNodesChange(changes)
              if (changes.some(c => c.type === 'remove' || (c.type === 'position' && c.dragging))) touch()
            }} onEdgesChange={changes => { onEdgesChange(changes); if (changes.some(c => c.type === 'remove')) touch() }}
            onNodeClick={(_, n) => { setInspectedDelivery(undefined); setSelection(n.id) }}
            onPaneClick={() => { setInspectedDelivery(undefined); setSelection(undefined) }}
            onConnect={connect} isValidConnection={valid} fitView fitViewOptions={{ padding: 0.24, maxZoom: 1.05 }}
            nodesDraggable={!busy} nodesConnectable={!busy} deleteKeyCode={busy ? null : ['Backspace', 'Delete']}
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
        downloadCiGraph={downloadCiGraph} connectOpenAI={() => setKeyOpen(true)}/>
    </div>
    <Results run={run} projectId={projectId} tab={tab} setTab={setTab} inspectWebhook={(runId, nodeId) => {
      setInspectedDelivery({ runId, nodeId })
      requestAnimationFrame(() => document.getElementById('block-inspector')?.focus())
    }} open={current => {
      setRun(current); setOverlay(false); setTab('steps')
    }}/>
    {sourceOpen && <SourceDialog files={files} close={() => setSourceOpen(false)}
      apply={next => { setFiles(next); setSourceOpen(false); touch() }}/>}
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
        setSelection(selectedId)
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
function editor(projectId?: string) {
  return <ReactFlowProvider><Studio key={projectId ?? 'local'} projectId={projectId}/></ReactFlowProvider>
}
createRoot(document.getElementById('root')!).render(<StrictMode>
  {localReport ? <div className={workspaceStyles.workspace}><Suspense fallback={<p role="status">Загружаем отчёт…</p>}>
    <BrowserReportPage runId={localReport[1]} nodeId={localReport[2]}/>
  </Suspense></div> : legacy ? <>{editor()}<Suspense fallback={null}><BrowserNotification local/></Suspense></>
    : <Workspace renderEditor={id => editor(id)} />}
</StrictMode>)

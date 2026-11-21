import { createContext, useContext } from 'react'
import { Handle, Position, type Node, type NodeProps } from '@xyflow/react'
import { AudioLines, Box, Braces, Clock3, Fingerprint, GitBranch, GitPullRequest, MousePointer2, Radio, type LucideIcon } from 'lucide-react'
import type { Kind, Run, Spec, Step } from './api'
import s from './studio.module.css'

export const groups = ['Запуск', 'Анализ кода', 'Обработка'] as const
type BlockInfo = { name: string; icon: LucideIcon; group: typeof groups[number]; note: string }
export const blocks: Record<Kind, BlockInfo> = {
  manual: { name: 'Ручной запуск', icon: MousePointer2, group: 'Запуск', note: 'По кнопке' },
  schedule: { name: 'Расписание', icon: Clock3, group: 'Запуск', note: 'По времени' },
  git_event: { name: 'Git-событие', icon: GitPullRequest, group: 'Запуск', note: 'GitHub Actions' },
  secrets: { name: 'Поиск секретов', icon: Fingerprint, group: 'Анализ кода', note: 'Ключи и пароли' },
  sca: { name: 'Зависимости', icon: Box, group: 'Анализ кода', note: 'Gradle · SCA' },
  sast: { name: 'Статический анализ', icon: Braces, group: 'Анализ кода', note: 'Kotlin · SAST' },
  condition: { name: 'Условие', icon: GitBranch, group: 'Обработка', note: 'Ветвление' },
  explain: { name: 'AI-объяснение', icon: AudioLines, group: 'Обработка', note: 'Языковая модель' },
  webhook: { name: 'Уведомление', icon: Radio, group: 'Обработка', note: 'HTTP webhook' },
}
export const kinds = Object.keys(blocks) as Kind[]
export const labels: Record<Run['status'], string> = {
  pending: 'Ожидает', running: 'В работе', succeeded: 'Завершён', failed: 'Ошибка',
  skipped: 'Пропущен', warning: 'С замечанием',
}
export const StepContext = createContext<Step[]>([])
export type FlowNode = Node<{ spec: Spec }, 'block'>
export const isTrigger = (kind: Kind) => blocks[kind].group === 'Запуск'
export const defaultGitEvents = ['push', 'pull_request'] as const
export const eventNames = { push: 'Push', pull_request: 'Pull request' }

export function Tile({ kind }: { kind: Kind }) {
  const { icon: Icon, group } = blocks[kind]
  return <span className={s.tile} data-group={groups.indexOf(group)}><Icon size={19} strokeWidth={1.8} /></span>
}

function Block({ id, data, selected }: NodeProps<FlowNode>) {
  const { kind } = data.spec
  const info = blocks[kind]
  const step = useContext(StepContext).find(item => item.node_id === id)
  return <div className={s.block} data-selected={selected} data-state={step?.status}>
    {!isTrigger(kind) && <Handle type="target" position={Position.Left} />}
    <div className={s.blockBody}><Tile kind={kind} /><div><strong>{info.name}</strong>
      <small>{kind === 'git_event' ? (data.spec.git_events ?? defaultGitEvents).map(e => eventNames[e]).join(' / ') : info.note}</small></div></div>
    {step && <span className={s.nodeStatus} data-state={step.status}><i />{labels[step.status]}</span>}
    {kind === 'condition' ? <>
      <Handle id="yes" type="source" position={Position.Right} style={{ top: '32%' }} title="Да" />
      <Handle id="no" type="source" position={Position.Right} style={{ top: '72%' }} title="Нет" />
      <span className={s.ports}>Да<br />Нет</span>
    </> : <Handle type="source" position={Position.Right} />}
  </div>
}

export const nodeTypes = { block: Block }

export function graphId() {
  return Array.from(crypto.getRandomValues(new Uint32Array(4)), n => n.toString(16).padStart(8, '0')).join('')
}

export function newSpec(kind: Kind, x: number, y: number): Spec {
  return { id: graphId(), kind, x, y, pattern: '*', cron: '0 9 * * *', enabled: false,
    git_events: kind === 'git_event' ? [...defaultGitEvents] : undefined,
    extended_sca: kind === 'sca' ? true : null, online_cve: kind === 'sca',
    predicate: 'count_gte', value: '1', connection: 'ollama', model: '', destination: 'inbox' }
}

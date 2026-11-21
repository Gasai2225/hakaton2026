import { lazy, Suspense } from 'react'
import { Download, Settings2, Trash2 } from 'lucide-react'
import { blocks, defaultGitEvents, eventNames, labels, Tile } from './blocks'
import type { Profile, Run, Spec, Step, Target } from './api'
import { StepFindings } from './Results'
import s from './studio.module.css'

const WebhookDelivery = lazy(() => import('./WebhookDelivery'))

type Props = {
  node?: Spec; step?: Step; profiles: Profile[]; findings: NonNullable<Run['findings']>
  runId?: string; inspectedWebhook?: Step; closeWebhook: () => void
  sharedProject: boolean
  downloadCiGraph: () => void
  update: (patch: Partial<Spec>) => void; remove: () => void; connectOpenAI: () => void
}

const mavenModes = {
  extended: { label: 'Расширенный', hint: 'Прямые и транзитивные · база и OSV онлайн' },
  local: { label: 'По локальной базе', hint: 'Прямые зависимости · база организаторов' },
}

const notificationChannels: Record<Exclude<Spec['destination'], 'https'>, { label: string; hint?: string }> = {
  browser: { label: 'В браузере' },
  inbox: { label: 'Локальный журнал' },
  configured: { label: 'Серверный вебхук', hint: 'Адрес из GARDEN_WEBHOOK_URL' },
  telegram: { label: 'Telegram', hint: 'Чат из GARDEN_TELEGRAM_CHAT_ID' },
  email: { label: 'Email', hint: 'Получатель из GARDEN_EMAIL_TO' },
}

function StepDetails({ step, runId, findings }: Pick<Props, 'runId' | 'findings'> & { step: Step }) {
  return <div className={s.detail}><strong>{labels[step.status]}</strong>{step.message && <p>{step.message}</p>}
    {step.kind === 'webhook' && runId ? <>
      <small>На входе · {step.input_ids?.length ?? 0} · на выходе · {step.output_ids?.length ?? 0}</small>
      <Suspense fallback={<p role="status">Загрузка отправки…</p>}>
        <WebhookDelivery key={[runId, step.node_id, step.status, step.webhook_attempted === true].join('/')}
          runId={runId} nodeId={step.node_id}/>
      </Suspense>
    </> : <StepFindings step={step} findings={findings} />}
  </div>
}

export function Inspector({ node, step, profiles, findings, runId, inspectedWebhook, closeWebhook, downloadCiGraph, update, remove, connectOpenAI, sharedProject }: Props) {
  if (inspectedWebhook && runId) return <aside className={s.inspector} id="block-inspector" tabIndex={-1}>
    <h2>Доставка уведомления</h2>
    <p className={s.hint}>Прогон <code>{runId}</code><br />Блок <code>{inspectedWebhook.node_id}</code></p>
    <StepDetails step={inspectedWebhook} runId={runId} findings={findings}/>
    <button onClick={closeWebhook}>К параметрам блока</button>
  </aside>
  const mavenMode = node?.extended_sca === false ? 'local' : 'extended'
  const targets = node?.targets?.length ? node.targets : [{ connection: node?.connection || 'ollama', model: node?.model || '' }]
  const gitEvents = node?.git_events ?? defaultGitEvents
  const destination = node?.destination === 'https' || (sharedProject && node?.destination === 'configured')
    ? 'browser' : node?.destination ?? 'browser'
  const change = (i: number, patch: Partial<Target>) => update({ targets: targets.map((t, j) => i === j ? { ...t, ...patch } : t) })
  return <aside className={s.inspector} id="block-inspector" tabIndex={-1}>
    <h2><Settings2 size={16} />Параметры блока</h2>
    {!node ? <p className={s.hint}>Выберите блок на схеме.</p> : <>
      <div className={s.inspectorTitle}><Tile kind={node.kind} /><strong>{blocks[node.kind].name}</strong></div>
      {['secrets', 'sast', 'sca'].includes(node.kind) && <label>Маска пути<input value={node.pattern}
        onChange={e => update({ pattern: e.target.value })} placeholder="*.kt" /></label>}
      {node.kind === 'sca' && <>
        <label>Справочник Maven<select value={mavenMode} aria-describedby="maven-mode-hint"
          onChange={e => {
            const extended = e.target.value === 'extended'
            update({ extended_sca: extended, online_cve: extended })
          }}>
          {Object.entries(mavenModes).map(([value, mode]) => <option key={value} value={value}>{mode.label}</option>)}
        </select></label>
        <small id="maven-mode-hint" className={s.mavenHint}
          title={mavenMode === 'extended' ? 'При каждом запуске OSV получит Maven-координаты и версии зависимостей.' : undefined}>
          {mavenModes[mavenMode].hint}
        </small>
      </>}
      {node.kind === 'manual' && <p className={s.hint}>Кнопка «Запустить» начинает проверку с этого блока.</p>}
      {node.kind === 'git_event' && <>
        <fieldset className={s.target}><legend>События запуска</legend>
          {defaultGitEvents.map(event => <label className={s.checkbox} key={event}>
            <input type="checkbox" checked={gitEvents.includes(event)} disabled={gitEvents.length === 1 && gitEvents[0] === event}
              onChange={e => update({ git_events: defaultGitEvents.filter(v => v === event ? e.target.checked : gitEvents.includes(v)) })} />
            {eventNames[event]}{event === 'pull_request' && ' (открытие и обновление)'}
          </label>)}
        </fieldset>
        <p className={s.hint}>Скачайте граф в <code>samples/ci-workflow.json</code> репозитория с Garden Actions,
          сделайте коммит и push. Результат появится в GitHub Actions и в проверках pull request.</p>
        <button onClick={downloadCiGraph}><Download size={14} />Скачать ci-workflow.json</button>
        <p className={s.hint}>CI проверяет изменённые учебные проекты. В ветке CI используйте локальную SCA.
          Блоки AI и webhook можно подключить к отдельному ручному триггеру.</p>
      </>}
      {node.kind === 'schedule' && <>
        <label>Расписание cron<input value={node.cron} onChange={e => update({ cron: e.target.value })} /></label>
        <small>Часовой пояс · Москва</small>
        <label className={s.checkbox}><input type="checkbox" checked={node.enabled}
          onChange={e => update({ enabled: e.target.checked })} />Включить после сохранения</label>
      </>}
      {node.kind === 'condition' && <>
        <label>Проверка<select value={node.predicate} onChange={e => {
          const predicate = e.target.value as Spec['predicate']
          update({ predicate, value: { count_gte: '1', severity_eq: 'high', rule_regex: '.*' }[predicate] })
        }}><option value="count_gte">Число находок ≥</option><option value="severity_eq">Есть находка уровня</option>
          <option value="rule_regex">ID правила соответствует regex</option></select></label>
        <label>Значение{node.predicate === 'severity_eq'
          ? <select value={node.value} onChange={e => update({ value: e.target.value })}>
            {['low','medium','high','critical'].map(v => <option key={v}>{v}</option>)}</select>
          : <input value={node.value} onChange={e => update({ value: e.target.value })} />}</label>
      </>}
      {node.kind === 'explain' && <>
        <p className={s.hint}>Каждая модель отдельно предложит исправления для тех же находок.</p>
        {targets.map((target, i) => {
          const profile = profiles.find(p => p.id === target.connection)
          return <fieldset className={s.target} key={i}><legend>Модель {i + 1}</legend>
            <label>Провайдер<select value={target.connection} onChange={e => change(i, { connection: e.target.value, model: '' })}>
              {profiles.map(p => <option key={p.id} value={p.id}>{p.label}</option>)}</select></label>
            <label>Имя модели<input value={target.model} placeholder={profile?.model || 'ID модели'}
              onChange={e => change(i, { model: e.target.value })}/></label>
            {profile && !profile.configured && <small>Требуются учётные данные. </small>}
            {profile?.local_key_entry && <button type="button" onClick={connectOpenAI}>{profile.configured ? 'Заменить ключ' : 'Подключить OpenAI'}</button>}
            {targets.length > 1 && <button aria-label={'Убрать модель ' + (i + 1)} onClick={() => update({ targets: targets.filter((_, j) => j !== i) })}>
              <Trash2 size={13}/>Убрать</button>}
          </fieldset>
        })}
        <button disabled={targets.length >= 8} onClick={() => update({ targets: [...targets,
          { connection: profiles.find(p => !targets.some(t => t.connection === p.id))?.id || targets[0].connection, model: '' }] })}>Добавить модель</button>
      </>}
      {node.kind === 'webhook' && <label>Канал доставки<select
        value={destination}
        onChange={e => update({ destination: e.target.value as Spec['destination'] })}>
        {Object.entries(notificationChannels).filter(([value]) => value !== 'configured' || destination === 'configured')
          .map(([value, { label }]) => <option key={value} value={value}>{label}</option>)}</select>
        {destination === 'browser' && <small>Показывает окно с кнопкой «Открыть отчёт» после выполнения блока.</small>}
        {!['inbox', 'browser'].includes(destination) && <small>{sharedProject
          ? 'Получателя задаёт владелец проекта в разделе «Уведомления» личного кабинета.'
          : notificationChannels[destination].hint}</small>}</label>}
      {step && <StepDetails step={step} runId={runId} findings={findings}/>}
      <button className={s.delete} onClick={remove}><Trash2 size={14} />Удалить блок</button>
    </>}
  </aside>
}

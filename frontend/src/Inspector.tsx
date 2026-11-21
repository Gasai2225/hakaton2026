import { lazy, Suspense, useEffect, useState } from 'react'
import { Download, Settings2, Trash2 } from 'lucide-react'
import { blocks, defaultGitEvents, eventNames, labels, Tile } from './blocks'
import type { Profile, Run, Spec, Step, Target } from './api'
import type { NodeLock } from './boardPresence'
import { ConditionSettings } from './ConditionSettings'
import { StepFindings } from './Results'
import s from './studio.module.css'

const WebhookDelivery = lazy(() => import('./WebhookDelivery'))

type Props = {
  node?: Spec; step?: Step; profiles: Profile[]; findings: NonNullable<Run['findings']>
  runId?: string; inspectedWebhook?: Step; closeWebhook: () => void
  sharedProject: boolean
  downloadCiGraph: () => void
  update: (patch: Partial<Spec>) => void; remove: () => void; connectOpenAI: () => void
  editing?: { lock?: NodeLock; editable: boolean; pending: boolean; interrupted: boolean; online: boolean; start: () => void; finish: () => void }
  removeBlocked?: boolean
  readOnly?: boolean; mayRun?: boolean
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

function useSecondsLeft(deadline: number, showFrom = Infinity) {
  const [now, setNow] = useState(Date.now)
  useEffect(() => {
    let timer: number
    function tick() {
      window.clearTimeout(timer)
      const time = Date.now()
      setNow(time)
      const remaining = deadline - time
      if (remaining > 0) timer = window.setTimeout(tick,
        remaining > showFrom ? remaining - showFrom : remaining % 1000 || 1000)
    }
    tick()
    document.addEventListener('visibilitychange', tick)
    return () => { window.clearTimeout(timer); document.removeEventListener('visibilitychange', tick) }
  }, [deadline, showFrom])
  return Math.max(0, Math.ceil((deadline - now) / 1000))
}

function RemoteLock({ lock }: { lock: NodeLock }) {
  const seconds = useSecondsLeft(lock.expires_at)
  const time = Math.floor(seconds / 60) + ':' + String(seconds % 60).padStart(2, '0')
  return <><p role="status">Редактирует <strong>{lock.name}</strong></p>
    <small>{seconds > 0 ? <>Если участник отойдёт, блок освободится через <span role="timer">{time}</span></>
      : 'Проверяем, свободен ли блок…'}</small></>
}

export function IdleWarning({ lock, renew }: { lock: NodeLock; renew: () => Promise<void> }) {
  const seconds = useSecondsLeft(lock.expires_at, 30_000)
  const [sending, setSending] = useState(false)
  if (seconds > 30 || !seconds) return null
  return <div className={s.idleWarning}>
    <span role="status">Блок скоро освободится.</span> <span role="timer">{seconds} с</span>
    <button disabled={sending} onClick={async () => {
      setSending(true)
      try { await renew() } finally { setSending(false) }
    }}>Продолжить редактирование</button>
  </div>
}

function StepDetails({ step, runId, findings, sharedProject }: Pick<Props, 'runId' | 'findings' | 'sharedProject'> & { step: Step }) {
  return <div className={s.detail}><strong>{labels[step.status]}</strong>{step.message && <p>{step.message}</p>}
    {step.kind === 'webhook' && runId ? <>
      <small>На входе · {step.input_ids?.length ?? 0} · на выходе · {step.output_ids?.length ?? 0}</small>
      <Suspense fallback={<p role="status">Загрузка отправки…</p>}>
        <WebhookDelivery key={[runId, step.node_id, step.status, step.webhook_attempted === true].join('/')}
          runId={runId} nodeId={step.node_id} local={!sharedProject}/>
      </Suspense>
    </> : <StepFindings step={step} findings={findings} />}
  </div>
}

export function Inspector({ node, step, profiles, findings, runId, inspectedWebhook, closeWebhook, downloadCiGraph,
  update, remove, connectOpenAI, sharedProject, editing, removeBlocked, readOnly, mayRun = true }: Props) {
  if (inspectedWebhook && runId) return <aside className={s.inspector} id="block-inspector" tabIndex={-1}>
    <h2>Доставка уведомления</h2>
    <p className={s.hint}>Прогон <code>{runId}</code><br />Блок <code>{inspectedWebhook.node_id}</code></p>
    <StepDetails step={inspectedWebhook} runId={runId} findings={findings} sharedProject={sharedProject}/>
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
      {editing && (!readOnly || editing.lock) && <div className={s.editState}>
        {editing.interrupted && <p role="status">Редактирование прервано. Чтобы продолжить, снова откройте блок.</p>}
        {editing.lock && (!editing.lock.mine || readOnly)
          ? <RemoteLock lock={editing.lock} />
          : editing.lock?.mine
            ? <button disabled={editing.pending} onClick={editing.finish}>Завершить редактирование</button>
            : <button disabled={!editing.online || editing.pending} onClick={editing.start}>
              {editing.pending ? 'Открываем блок…' : editing.online ? 'Редактировать' : 'Ожидаем связь с доской'}</button>}
      </div>}
      <fieldset className={s.blockFields} disabled={readOnly || (editing && !editing.editable)}>
      {['secrets', 'sast', 'sca'].includes(node.kind) && <>
        <label>Маска пути<input value={node.pattern} aria-describedby="path-pattern-hint"
          onChange={e => update({ pattern: e.target.value })} placeholder="*" /></label>
        <small id="path-pattern-hint"><code>*</code> — все поддерживаемые файлы. Разделяйте маски запятыми.
          {' '}Поставьте <code>!</code> перед маской, чтобы исключить путь.<br />
          {node.kind === 'sca'
            ? <><code>build.gradle.kts, app/*</code> — файл сборки в корне и файлы модуля app.</>
            : <><code>*.kt, *.kts, !**/test/**</code> — файлы Kotlin и Kotlin-скрипты вне папок test.</>}
        </small>
      </>}
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
        <p className={s.hint}>CI проверяет изменённые учебные проекты. В ветке CI используйте локальную SCA.
          Блоки AI и webhook можно подключить к отдельному ручному триггеру.</p>
      </>}
      {node.kind === 'schedule' && <>
        <label>Расписание cron<input value={node.cron} disabled={!mayRun && node.enabled} onChange={e => update({ cron: e.target.value })} /></label>
        <small>Часовой пояс · Москва</small>
        <label className={s.checkbox}><input type="checkbox" checked={node.enabled} disabled={!mayRun}
          onChange={e => update({ enabled: e.target.checked })} />Включить после сохранения</label>
        {!mayRun && !readOnly && <small>Для управления действующим расписанием нужно право запуска проверок.</small>}
      </>}
      {node.kind === 'condition' && <ConditionSettings predicate={node.predicate} value={node.value} update={update}/>}
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
      </fieldset>
      {node.kind === 'git_event' && <button onClick={downloadCiGraph}><Download size={14} />Скачать ci-workflow.json</button>}
      {step && <StepDetails step={step} runId={runId} findings={findings} sharedProject={sharedProject}/>}
      {!readOnly && <button className={s.delete} onClick={remove} disabled={removeBlocked || (editing && !editing.editable) || (!mayRun && node.kind === 'schedule' && node.enabled)}
        title={removeBlocked ? 'У связанного блока сейчас есть редактор' : undefined}><Trash2 size={14} />Удалить блок</button>}
    </>}
  </aside>
}

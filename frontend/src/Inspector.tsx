import { Settings2, Trash2 } from 'lucide-react'
import { blocks, labels, Tile } from './blocks'
import type { Profile, Spec, Step, Target } from './api'
import s from './studio.module.css'

type Props = {
  node?: Spec; step?: Step; profiles: Profile[]
  update: (patch: Partial<Spec>) => void; remove: () => void; connectOpenAI: () => void
}

export function Inspector({ node, step, profiles, update, remove, connectOpenAI }: Props) {
  const targets = node?.targets?.length ? node.targets : [{ connection: node?.connection || 'ollama', model: node?.model || '' }]
  const change = (i: number, patch: Partial<Target>) => update({ targets: targets.map((t, j) => i === j ? { ...t, ...patch } : t) })
  return <aside className={s.inspector}>
    <h2><Settings2 size={16} />Параметры блока</h2>
    {!node ? <p className={s.hint}>Выберите блок на схеме.</p> : <>
      <div className={s.inspectorTitle}><Tile kind={node.kind} /><strong>{blocks[node.kind].name}</strong></div>
      {['secrets', 'sast', 'sca'].includes(node.kind) && <label>Маска пути<input value={node.pattern}
        onChange={e => update({ pattern: e.target.value })} placeholder="*.kt" /></label>}
      {node.kind === 'manual' && <p className={s.hint}>Кнопка «Запустить» начинает проверку с этого блока.</p>}
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
      {node.kind === 'webhook' && <label>Получатель<select value={node.destination} onChange={e => update({ destination: e.target.value as Spec['destination'] })}>
        <option value="inbox">Локальный журнал</option><option value="configured">Серверный webhook</option></select>
        {node.destination === 'configured' && <small>Адрес из GARDEN_WEBHOOK_URL</small>}</label>}
      {step && <div className={s.detail}><strong>{labels[step.status]}</strong><p>{step.message}</p>
        <small>Находок на входе {step.input_ids?.length ?? 0} · на выходе {step.output_ids?.length ?? 0}</small></div>}
      <button className={s.delete} onClick={remove}><Trash2 size={14} />Удалить блок</button>
    </>}
  </aside>
}

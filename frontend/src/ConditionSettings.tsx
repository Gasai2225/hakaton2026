import type { Spec } from './api'
import { severity } from './Results'

type Predicate = Spec['predicate']
type Choice = [value: string, label: string]
type Check = { label: string; initial: string; hint?: string } &
  ({ choices: Choice[] } | { input: 'number' | 'text'; placeholder?: string })

const levels = Object.entries(severity)
const checks: Record<Predicate, Check> = {
  count_gte: { label: 'Число находок ≥', initial: '1', input: 'number' },
  count_eq: { label: 'Число находок =', initial: '0', input: 'number' },
  count_lte: { label: 'Число находок ≤', initial: '0', input: 'number' },
  severity_eq: { label: 'Есть находка точного уровня', initial: 'high', choices: levels },
  severity_gte: { label: 'Есть находка уровня или выше', initial: 'high', choices: levels },
  category_eq: { label: 'Есть находка категории', initial: 'SECRET',
    choices: [['SECRET', 'Секреты'], ['SAST', 'Статический анализ'], ['SCA', 'Зависимости']] },
  path_matches: { label: 'Есть находка в файле по маске', initial: '*.kt', input: 'text',
    placeholder: '*.kt, !**/test/**', hint: 'Разделяйте маски запятыми. Символ ! перед маской исключает путь.' },
  rule_regex: { label: 'ID правила соответствует regex', initial: '.*', input: 'text', placeholder: '^SECRET-' },
  analysis_status_eq: { label: 'Полнота анализа', initial: 'complete',
    choices: [['complete', 'Полный'], ['partial', 'Неполный'], ['not_run', 'Анализ не запускался']],
    hint: 'Учитываются блоки анализа, результаты которых пришли на вход условия.' },
}

type Props = Pick<Spec, 'predicate' | 'value'> & { update: (patch: Partial<Spec>) => void }

export function ConditionSettings({ predicate, value, update }: Props) {
  const check = checks[predicate]
  const hint = check.hint ? 'condition-hint' : undefined
  const changeValue = (value: string) => update({ value })
  return <>
    <label>Проверка<select value={predicate} onChange={event => {
      const next = event.target.value as Predicate
      update({ predicate: next, value: checks[next].initial })
    }}>
      {Object.entries(checks).map(([key, item]) => <option key={key} value={key}>{item.label}</option>)}
    </select></label>
    <label>Значение{'choices' in check
      ? <select value={value} aria-describedby={hint} onChange={event => changeValue(event.target.value)}>
        {check.choices.map(([key, label]) => <option key={key} value={key}>{label}</option>)}
      </select>
      : <input type={check.input} min={check.input === 'number' ? 0 : undefined} maxLength={160}
        value={value} aria-describedby={hint} placeholder={check.placeholder}
        onChange={event => changeValue(event.target.value)} />}</label>
    {check.hint && <small id={hint}>{check.hint}</small>}
  </>
}

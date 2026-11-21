import { useState } from 'react'
import { request } from './api'
import { useAction, useResource } from './workspaceData'
import s from './workspace.module.css'

const path = 'auth/notifications'

type Settings = {
  email_recipient: string | null
  email_mode: 'garden' | 'personal'
  email_sender: string | null
  email_host: string | null
  email_port: number | null
  email_security: 'starttls' | 'ssl' | null
  email_available: boolean
  telegram_linked: boolean
  telegram_available: boolean
}

type EmailUpdate = { mode: 'garden'; recipient: string } |
  { mode: 'personal'; recipient: string; sender: string; host: string; port?: number; security: string; password?: string }

function EmailForm({ settings, email, busy, save, disable, changed }: {
  settings: Settings; email: string; busy: boolean
  save: (config: EmailUpdate, form: HTMLFormElement) => void; disable: () => void; changed: () => void
}) {
  const [mode, setMode] = useState(settings.email_mode)
  return <form className={s.form + ' ' + s.emailSettings} onChange={changed} onSubmit={event => {
    event.preventDefault()
    const form = event.currentTarget
    const fields = new FormData(form)
    const text = (name: string) => String(fields.get(name) ?? '')
    const recipient = text('recipient').trim()
    save(mode === 'garden' ? { mode, recipient } : {
      mode, recipient, sender: text('sender').trim(), host: text('host').trim(),
      port: text('port') ? Number(text('port')) : undefined, security: text('security'), password: text('password') || undefined,
    }, form)
  }}>
    <label>Куда отправлять отчёт<input name="recipient" type="email" defaultValue={settings.email_recipient ?? email}
      maxLength={254} required /></label>
    <label>Отправитель<select value={mode} onChange={event => setMode(event.target.value as Settings['email_mode'])}>
      <option value="garden">Почта Garden</option><option value="personal">Своя почта</option>
    </select></label>
    {mode === 'garden' && !settings.email_available && <p className={s.note}>Общий SMTP ещё не настроен администратором.</p>}
    {mode === 'garden' && settings.email_available && <p className={s.note}>Достаточно указать получателя. После сохранения выберите «Email» в блоке «Уведомление».</p>}
    {mode === 'personal' && <>
      <label>Адрес своей почты<input name="sender" type="email" defaultValue={settings.email_sender ?? email}
        maxLength={254} required /></label>
      <label>SMTP-сервер<input name="host" defaultValue={settings.email_host ?? ''} placeholder="smtp.example.org"
        maxLength={253} required /></label>
      <label>Шифрование<select name="security" defaultValue={settings.email_security ?? 'starttls'}>
        <option value="starttls">STARTTLS</option><option value="ssl">SSL/TLS</option>
      </select></label>
      <label>Порт SMTP<input name="port" type="number" min={1} max={65535} defaultValue={settings.email_port ?? ''}
        placeholder="587 для STARTTLS, 465 для SSL/TLS" /></label>
      <label>Пароль приложения<input name="password" type="password" autoComplete="new-password" maxLength={512}
        required={!settings.email_sender} placeholder={settings.email_sender ? 'Оставьте пустым, чтобы сохранить текущий' : undefined} /></label>
    </>}
    <div className={s.actions}>
      <button className={s.primary} disabled={busy}>Сохранить почту</button>
      {settings.email_recipient && <button type="button" disabled={busy} onClick={disable}>Отключить</button>}
    </div>
  </form>
}

export default function NotificationSettings({ email }: { email: string }) {
  const resource = useResource<Settings>(path)
  const action = useAction()
  const [emailSaved, setEmailSaved] = useState(false)
  const [telegramLink, setTelegramLink] = useState('')
  const settings = resource.data

  function disconnect(channel: 'email' | 'telegram') {
    void action.perform(async () => {
      resource.setData(await request<Settings>(path + '/' + channel, 'DELETE'))
      if (channel === 'email') setEmailSaved(false)
      if (channel === 'telegram') setTelegramLink('')
    })
  }

  return <section id="notifications" className={s.section + ' ' + s.profile} aria-labelledby="notifications-title">
    <h2 id="notifications-title">Уведомления</h2>
    {resource.error && <div role="alert" className={s.error}>{resource.error} <button type="button" onClick={resource.reload}>Повторить</button></div>}
    {!settings && !resource.error && <p role="status">Загрузка настроек…</p>}
    {settings && <div className={s.panel + ' ' + s.notificationSettings}>
      <p className={s.note}>Получатели для проектов, которыми вы владеете. Выберите канал в блоке «Уведомление».</p>
      <section aria-labelledby="notification-email">
        <h3 id="notification-email">Email</h3>
        <EmailForm key={JSON.stringify([settings.email_recipient, settings.email_mode, settings.email_sender,
          settings.email_host, settings.email_port, settings.email_security])} settings={settings} email={email} busy={action.busy}
          changed={() => setEmailSaved(false)} disable={() => disconnect('email')} save={(config, form) => void action.perform(async () => {
            setEmailSaved(false)
            const saved = await request<Settings>(path + '/email', 'PUT', config)
            const password = form.elements.namedItem('password')
            if (password instanceof HTMLInputElement) password.value = ''
            resource.setData(saved)
            setEmailSaved(true)
          })}/>
        {emailSaved && <small role="status">Настройки почты сохранены</small>}
      </section>
      <section aria-labelledby="notification-telegram">
        <h3 id="notification-telegram">Telegram</h3>
        {settings.telegram_linked ? <div className={s.actions}><span role="status">Чат подключён</span>
          <button type="button" disabled={action.busy} onClick={() => disconnect('telegram')}>Отключить</button>
        </div> : settings.telegram_available ? <>
          <div className={s.actions}>
            <button type="button" disabled={action.busy} onClick={() => void action.perform(async () => {
              const link = await request<{ url: string }>(path + '/telegram/link', 'POST')
              setTelegramLink(link.url)
            })}>{telegramLink ? 'Обновить ссылку' : 'Подключить Telegram'}</button>
            {telegramLink && <a href={telegramLink} className={s.button} target="_blank" rel="noreferrer">Открыть бота</a>}
          </div>
          {telegramLink && <>
            <p className={s.note}>Откройте бота и нажмите «Запустить». Затем проверьте привязку.</p>
            <button type="button" onClick={resource.reload}>Проверить привязку</button>
          </>}
        </> : <p className={s.note}>Общий бот ещё не настроен администратором.</p>}
      </section>
      {action.error && <p role="alert" className={s.error}>{action.error}</p>}
    </div>}
  </section>
}

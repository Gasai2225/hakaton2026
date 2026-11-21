import type { components } from './schema'

type Schema = components['schemas']
export type Spec = Schema['Node']
export type Kind = Spec['kind']
export type Source = Schema['Source']
export type Workflow = Schema['Workflow']
export type Run = Schema['Run']
export type Step = Schema['Step']
export type Profile = Schema['PublicConnection']
export type Target = Schema['Target']
export type Blueprint = Schema['Blueprint']
export type Template = Schema['Template']
export type Summary = Schema['RunSummary']
export type Delivery = Schema['WebhookDelivery']

export class ApiError extends Error {
  constructor(readonly status: number, detail: string) { super(detail) }
}

export async function request<T>(path: string, method = 'GET', body?: unknown, signal?: AbortSignal): Promise<T> {
  const response = await fetch('/api/' + path, {
    method, signal,
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (!response.ok) {
    const result = await response.json().catch(() => ({}))
    throw new ApiError(response.status, typeof result.detail === 'string' ? result.detail : 'Ошибка сервера · HTTP ' + response.status)
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

export function message(error: unknown) {
  return error instanceof Error ? error.message : 'Не удалось выполнить запрос'
}

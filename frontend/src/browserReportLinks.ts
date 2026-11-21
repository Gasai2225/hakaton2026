export const reportRoute = /^\/reports\/([\w-]+)\/([\w-]+)$/

export function reportHref(runId: string, nodeId: string, local = false) {
  return '/reports/' + encodeURIComponent(runId) + '/' + encodeURIComponent(nodeId) + (local ? '?local=1' : '')
}

export function formatReportTime(value: string) {
  return new Intl.DateTimeFormat('ru-RU', { dateStyle: 'long', timeStyle: 'medium' }).format(new Date(value))
}

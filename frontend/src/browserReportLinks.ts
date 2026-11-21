export const reportRoute = /^\/reports\/([\w-]+)\/([\w-]+)$/

export function reportHref(runId: string, nodeId: string, local = false) {
  return '/reports/' + encodeURIComponent(runId) + '/' + encodeURIComponent(nodeId) + (local ? '?local=1' : '')
}

export function reportPath(runId: string, nodeId: string) {
  return 'runs/' + encodeURIComponent(runId) + '/steps/' + encodeURIComponent(nodeId) + '/report'
}

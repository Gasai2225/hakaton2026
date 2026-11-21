export const reportRoute = /^\/reports\/([\w-]+)\/([\w-]+)$/

export function reportHref(runId: string, nodeId: string) {
  return '/api/runs/' + encodeURIComponent(runId) + '/steps/' + encodeURIComponent(nodeId) + '/report.json'
}

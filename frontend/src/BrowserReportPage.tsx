import { useEffect } from 'react'
import { reportHref } from './browserReportLinks'

export default function BrowserReportPage({ runId, nodeId }: { runId: string; nodeId: string }) {
  useEffect(() => { window.location.replace(reportHref(runId, nodeId)) }, [runId, nodeId])
  return null
}

import { useEffect, useState } from 'react'
import { request } from './api'

type Peer = { id: string; name: string }

export function ProjectPresence({ projectId }: { projectId: string }) {
  const [peers, setPeers] = useState<Peer[]>([])

  useEffect(() => {
    const lifetime = new AbortController()
    let pending = false
    async function heartbeat() {
      if (document.hidden || pending) return
      pending = true
      try {
        const signal = AbortSignal.any([lifetime.signal, AbortSignal.timeout(8000)])
        const data = await request<{ peers: Peer[] }>('projects/' + encodeURIComponent(projectId) + '/presence',
          'POST', undefined, signal)
        if (!lifetime.signal.aborted && !document.hidden) setPeers(data.peers)
      } catch {
        if (!lifetime.signal.aborted) setPeers([])
      } finally {
        pending = false
      }
    }
    function visibilityChanged() {
      if (document.hidden) setPeers([])
      else void heartbeat()
    }
    setPeers([])
    void heartbeat()
    const timer = window.setInterval(heartbeat, 12000)
    document.addEventListener('visibilitychange', visibilityChanged)
    return () => {
      window.clearInterval(timer)
      document.removeEventListener('visibilitychange', visibilityChanged)
      lifetime.abort()
    }
  }, [projectId])

  if (!peers.length) return null
  const names = peers.map(peer => peer.name)
  const compact = names.slice(0, 2).map(name => name.length > 20 ? name.slice(0, 19) + '…' : name)
  return <small title={names.join(', ')} aria-label={'Сейчас в графе с вами ' + names.join(', ')}>
    В графе с вами {compact.join(', ')}{peers.length > 2 && ' +' + (peers.length - 2)}
  </small>
}

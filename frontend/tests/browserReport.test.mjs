import assert from 'node:assert/strict'
import { test } from 'node:test'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { createServer } from 'vite'

test('report preview shows model failures alongside any available recommendations', async t => {
  const vite = await createServer({ configFile: false, optimizeDeps: { noDiscovery: true },
    server: { middlewareMode: true, watch: null, hmr: false, ws: false } })
  t.after(() => vite.close())
  const { ReportPreview } = await vite.ssrLoadModule('/src/BrowserReportPage.tsx')
  const preview = (reviews, reports = []) => renderToStaticMarkup(createElement(ReportPreview, {
    name: 'Garden', created_at: '2026-11-21T09:00:00Z',
    payload: { analysis_status: 'complete', findings: [], reviews, reports },
  }))
  const failed = { label: 'Модель А', status: 'failed', message: 'Истекло время ожидания' }
  const report = { groups: [{ finding_ids: [], risk: 'Описание риска', fix: 'Способ исправления' }] }
  const succeeded = { label: 'Модель Б', status: 'succeeded', report }

  const failedOnly = preview([failed])
  assert.match(failedOnly, /Ошибка модели Модель А/)
  assert.match(failedOnly, /Истекло время ожидания/)

  const mixed = preview([failed, succeeded], [report])
  assert.match(mixed, /Истекло время ожидания/)
  assert.match(mixed, /Модель Б/)
  assert.match(mixed, /Способ исправления/)

  const legacy = preview(undefined, [report])
  assert.doesNotMatch(legacy, /Ошибка модели/)
  assert.match(legacy, /Способ исправления/)
})

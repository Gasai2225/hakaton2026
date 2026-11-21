import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig(({ mode }) => ({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    proxy: { '/api': { target: loadEnv(mode, '.', 'GARDEN_DEV_API_URL').GARDEN_DEV_API_URL || 'http://127.0.0.1:8000', changeOrigin: false } },
  },
}))

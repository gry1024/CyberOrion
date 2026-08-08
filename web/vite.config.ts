import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  // 生产部署到子目录 /cyberorion/（nginx 静态托管），开发环境 VITE_BASE 覆盖为 /
  base: process.env.VITE_BASE ?? '/cyberorion/',
})

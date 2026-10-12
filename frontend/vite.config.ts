import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

// https://vite.dev/config/ -- defineConfig comes from 'vitest/config' (not
// plain 'vite') specifically so the `test` block below type-checks; it
// re-exports the same Vite config shape with Vitest's `test` key merged in.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
  },
})

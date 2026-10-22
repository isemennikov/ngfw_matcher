/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: ['class', '[data-theme="dark"]'],
  content: ["./web/templates/**/*.html"],
  theme: {
    extend: {
      fontSize: {
        // Приподнятая базовая шкала — интерфейс для многочасовых сессий анализа,
        // мелкий шрифт (12px) в исходном Tailwind напрягает глаза.
        xs: ['13px', { lineHeight: '18px' }],
        sm: ['15px', { lineHeight: '22px' }],
      },
      colors: {
        // surfaces
        bg: 'var(--bg)',
        surface: {
          DEFAULT: 'var(--surface)',
          2: 'var(--surface-2)',
          muted: 'var(--surface-muted)',
        },
        // text
        body: 'var(--text)',
        secondary: 'var(--text-secondary)',
        muted: 'var(--text-muted)',
        subtle: 'var(--text-subtle)',
        // lines
        border: {
          DEFAULT: 'var(--border)',
          subtle: 'var(--border-subtle)',
        },
        // primary action (graphite)
        primary: {
          DEFAULT: 'var(--primary)',
          hover: 'var(--primary-hover)',
          on: 'var(--on-primary)',
        },
        // semantic states
        allow: {
          DEFAULT: 'var(--allow)',
          bg: 'var(--allow-bg)',
          border: 'var(--allow-border)',
        },
        deny: {
          DEFAULT: 'var(--deny)',
          bg: 'var(--deny-bg)',
          border: 'var(--deny-border)',
        },
        warn: {
          DEFAULT: 'var(--warn)',
          bg: 'var(--warn-bg)',
          border: 'var(--warn-border)',
        },
      },
    },
  },
  plugins: [],
}

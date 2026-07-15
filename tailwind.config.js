/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./web/templates/**/*.html"],
  theme: {
    extend: {
      fontSize: {
        // Приподнятая базовая шкала — интерфейс для многочасовых сессий анализа,
        // мелкий шрифт (12px) в исходном Tailwind напрягает глаза.
        xs: ['13px', { lineHeight: '18px' }],
        sm: ['15px', { lineHeight: '22px' }],
      },
    },
  },
  plugins: [],
}

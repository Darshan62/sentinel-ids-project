/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "#0c1324",
        surface: "#0c1324",
        "surface-container": "#191f31",
        "surface-low": "#151b2d",
        "surface-high": "#23293c",
        "surface-highest": "#2e3447",
        primary: "#7bd0ff",
        "primary-container": "#001a27",
        error: "#ffb4ab",
        tertiary: "#ffb3ad",
        "text-primary": "#dce1fb",
        "text-secondary": "#c6c6cd",
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
        mono: ['Space Grotesk', 'monospace'],
      },
    },
  },
  plugins: [],
};

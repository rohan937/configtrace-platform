import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "system-ui", "-apple-system", "sans-serif"],
        mono: ["JetBrains Mono", "Fira Code", "Menlo", "monospace"],
      },
      colors: {
        background: "#0e0f11",
        surface1: "#13151a",
        surface2: "#1c1e26",
        surface3: "#22252f",
        border: "#2a2d38",
        textPrimary: "#e8eaf0",
        textSecondary: "#8b90a0",
        textTertiary: "#565b6e",
        accentBlue: "#4f80f7",
        accentHover: "#6b9cf8",
        healthy: "#3ccf7e",
        riskCritical: "#e84040",
        riskHigh: "#f5632a",
        riskMedium: "#f5a623",
        riskLow: "#6b9cf8",
      },
    },
  },
  plugins: [],
};

export default config;

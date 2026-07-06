/** @type {import('tailwindcss').Config} */
// Standalone Tailwind v3 config (Node-free CLI). `content` scans the Rust
// sources + index.html so only used utility classes land in the output CSS.
module.exports = {
  content: ["./index.html", "./src/**/*.rs"],
  theme: {
    extend: {},
  },
  plugins: [],
};

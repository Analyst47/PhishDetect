# PhishDetect (GitHub Pages) — Client-side Phishing URL Analyzer

PhishDetect is a small educational phishing URL analyzer that runs entirely in the browser. It's a static site hosted with GitHub Pages — no server, no cloud functions, and no external API required.

## How it works
- Loads in your browser and analyzes URLs using local heuristics.
- Classifies a URL as **Safe**, **Suspicious**, or **Malicious** and explains why.
- Useful for demonstrations, interviews, and portfolio showcases.

## To publish (quick)
1. Create a repository (e.g., `PhishDetect-GH`).
2. Add these files to the repo root: `index.html`, `styles.css`, `script.js`, `README.md`.
3. Create an `assets/` folder and upload `demo.png`.
4. In GitHub repo → Settings → Pages → Source: `main` branch / `root` → Save.
5. Visit your site at `https://YOUR_USERNAME.github.io/REPO_NAME/`.

## Notes
This is a heuristic tool for learning and portfolio demos. For production use or enterprise detection, integrate threat intelligence APIs and server-side analysis.

Made by **Fahim Abrar** — B.S. Computing & Informatics (Cybersecurity), Rowan University.

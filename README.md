# 🛡️ PhishDetect SOC Dashboard

<a href="https://github.com/fahimabrar/PhishDetect-GH"><img src="https://img.shields.io/badge/GitHub-000000?style=for-the-badge&logo=github&logoColor=white" /></a>
<a href="https://YOUR_USERNAME.github.io/PhishDetect-GH/"><img src="https://img.shields.io/badge/Live-Dashboard-00fff6?style=for-the-badge" /></a>

---

## **Overview**

PhishDetect SOC Dashboard is a **professional, cyber-themed phishing URL analysis tool** built with **HTML, CSS, and JavaScript**.  
It’s designed to mimic a **SOC analyst interface**, providing detailed URL classification, live stats, and interactive visualizations — all **client-side**, fully static, and hosted on **GitHub Pages**.

This dashboard is perfect for showcasing **cybersecurity projects** in portfolios and LinkedIn profiles.

---

## **Features**

- **Real-time URL classification**: Safe, Suspicious, Malicious  
- **Heuristic analysis** with detailed explanations  
- **Interactive statistics**: Total URLs, Safe/Suspicious/Malicious counts  
- **Dynamic charts** with Chart.js  
- **Neon/cyber theme** with animated background and glowing cards  
- **Expandable result section** with recommendations  
- **Responsive design** for desktops and tablets  

---

## **Code Snippets**

### **HTML (input section)**

```html
<section class="input-section card">
  <h2>Analyze a URL</h2>
  <input id="url" placeholder="Enter URL here (https://example.com)" />
  <button id="checkBtn">Analyze</button>
  <div id="result" class="result hidden"></div>
</section>


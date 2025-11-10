// Simple client-side heuristic phishing detector
const checkBtn = document.getElementById('checkBtn');
const urlInput = document.getElementById('url');
const resultEl = document.getElementById('result');

function isIPAddress(host) {
  // IPv4 regex
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
}

function analyzeURL(input) {
  try {
    const u = new URL(input);
    const host = u.hostname.toLowerCase();
    const path = u.pathname + u.search;
    let score = 0;
    const reasons = [];

    // Feature: https
    if (!u.protocol.includes('https')) { score += 2; reasons.push('No HTTPS'); }

    // Feature: IP address as host
    if (isIPAddress(host)) { score += 3; reasons.push('IP address used in host'); }

    // Feature: length
    if (input.length > 75) { score += 2; reasons.push('Very long URL'); }
    else if (input.length > 40) { score += 1; }

    // Feature: dots (many subdomains)
    const dots = host.split('.').length - 1;
    if (dots >= 3) { score += 1; reasons.push('Multiple subdomains'); }

    // Feature: hyphen in domain
    if (host.includes('-')) { score += 1; reasons.push('Hyphen in domain'); }

    // Feature: @ symbol (redirect)
    if (input.includes('@')) { score += 3; reasons.push('@ symbol present'); }

    // Feature: suspicious tokens
    const suspiciousTokens = ['login','signin','secure','update','confirm','account','bank','verify','webscr'];
    for (const t of suspiciousTokens) {
      if (input.toLowerCase().includes(t)) {
        score += 2;
        reasons.push(`Contains token "${t}"`);
        break;
      }
    }

    // Feature: many path segments
    const pathParts = path.split('/').filter(Boolean).length;
    if (pathParts >= 6) { score += 1; reasons.push('Deep path structure'); }

    // Basic TLD check (rare TLDs)
    const rareTLDs = ['zip','review','country','gq','tk','ml','cf'];
    const tld = host.split('.').pop();
    if (rareTLDs.includes(tld)) { score += 1; reasons.push(`Rare TLD .${tld}`); }

    // Final classification
    let label = 'Safe';
    if (score >= 6) label = 'Malicious';
    else if (score >= 3) label = 'Suspicious';

    return { score, label, reasons, host, length: input.length };
  } catch (e) {
    return { error: 'Invalid URL' };
  }
}

checkBtn.addEventListener('click', () => {
  const url = urlInput.value.trim();
  resultEl.classList.add('hidden');
  resultEl.innerHTML = '';

  if (!url) {
    alert('Please enter a URL.');
    return;
  }

  // Try to normalize common inputs
  let testUrl = url;
  if (!testUrl.startsWith('http://') && !testUrl.startsWith('https://')) {
    testUrl = 'http://' + testUrl;
  }

  const out = analyzeURL(testUrl);
  if (out.error) {
    resultEl.classList.remove('hidden');
    resultEl.innerHTML = `<div class="score">❌ Invalid URL</div>`;
    return;
  }

  const cls = out.label === 'Safe' ? 'safe' : out.label === 'Suspicious' ? 'suspicious' : 'malicious';
  resultEl.classList.remove('hidden');
  resultEl.innerHTML = `
    <div class="score ${cls}">Classification: <strong>${out.label}</strong> (score: ${out.score})</div>
    <div><strong>Host:</strong> ${out.host}</div>
    <div><strong>URL length:</strong> ${out.length} chars</div>
    <div style="margin-top:8px"><strong>Reasons:</strong></div>
    <ul>
      ${out.reasons.length ? out.reasons.map(r=>`<li>${r}</li>`).join('') : '<li class="muted">No obvious heuristics triggered</li>'}
    </ul>
    <div class="muted" style="margin-top:8px">This tool uses heuristics for demonstration and is not a replacement for professional threat intelligence.</div>
  `;
});


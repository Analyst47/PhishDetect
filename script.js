const checkBtn = document.getElementById('checkBtn');
const urlInput = document.getElementById('url');
const resultEl = document.getElementById('result');

let total=0, safe=0, suspicious=0, malicious=0;

const totalEl = document.getElementById('totalUrls');
const safeEl = document.getElementById('safeUrls');
const suspiciousEl = document.getElementById('suspiciousUrls');
const maliciousEl = document.getElementById('maliciousUrls');

// Initialize Chart
const ctx = document.getElementById('distributionChart').getContext('2d');
const distributionChart = new Chart(ctx, {
  type: 'bar',
  data: {
    labels: ['Safe','Suspicious','Malicious'],
    datasets: [{
      label: 'URL Distribution',
      data: [0,0,0],
      backgroundColor: ['#8ef56a','#ffd166','#ff6b6b'],
      borderRadius: 6
    }]
  },
  options: {
    responsive:true,
    plugins:{legend:{display:false}},
    scales:{y:{beginAtZero:true,ticks:{precision:0}}}
  }
});

// URL classification function
function classifyURL(url){
  let score=0, reasons=[];
  try{
    const u = new URL(url);
    const host = u.hostname.toLowerCase();
    if(!u.protocol.includes('https')){score+=2; reasons.push('No HTTPS');}
    if(/\d{1,3}(\.\d{1,3}){3}/.test(host)){score+=3; reasons.push('IP as host');}
    if(url.length>75){score+=2; reasons.push('Very long URL');} else if(url.length>40){score+=1;}
    const dots = host.split('.').length-1; if(dots>=3){score+=1; reasons.push('Multiple subdomains');}
    if(host.includes('-')){score+=1; reasons.push('Hyphen in domain');}
    if(url.includes('@')){score+=3; reasons.push('@ symbol present');}
    const tokens=['login','signin','secure','update','confirm','account','bank','verify','webscr'];
    for(const t of tokens){if(url.toLowerCase().includes(t)){score+=2; reasons.push(`Contains ${t}`); break;}}
    const pathParts=(u.pathname+u.search).split('/').filter(Boolean).length;
    if(pathParts>=6){score+=1; reasons.push('Deep path');}

    let label='Safe';
    if(score>=6) label='Malicious';
    else if(score>=3) label='Suspicious';

    return {score,label,reasons,host,length:url.length};
  }catch(e){
    return {error:'Invalid URL'};
  }
}

// Event listener
checkBtn.addEventListener('click',()=>{
  let url = urlInput.value.trim();
  if(!url){alert('Please enter a URL'); return;}
  if(!url.startsWith('http')) url='http://'+url;

  const out = classifyURL(url);
  resultEl.classList.remove('hidden');

  if(out.error){resultEl.innerHTML=`<div class="score">❌ Invalid URL</div>`; return;}

  total++;
  if(out.label==='Safe') safe++;
  else if(out.label==='Suspicious') suspicious++;
  else if(out.label==='Malicious') malicious++;

  // Update Stats
  totalEl.textContent = total;
  safeEl.textContent = safe;
  suspiciousEl.textContent = suspicious;
  maliciousEl.textContent = malicious;

  // Update Chart
  distributionChart.data.datasets[0].data = [safe, suspicious, malicious];
  distributionChart.update();

  // Display result
  const cls = out.label==='Safe'?'safe':out.label==='Suspicious'?'suspicious':'malicious';
  resultEl.innerHTML = `
    <div class="score ${cls}">Classification: <strong>${out.label}</strong> (score: ${out.score})</div>
    <div><strong>Host:</strong> ${out.host}</div>
    <div><strong>URL length:</strong> ${out.length} chars</div>
    <ul>${out.reasons.length ? out.reasons.map(r=>`<li>${r}</li>`).join('') : '<li class="muted">No heuristics triggered</li>'}</ul>
    <p><em>Recommendation:</em> ${out.label==='Malicious' ? 'Do NOT visit this URL. Report to security team.' : out.label==='Suspicious' ? 'Be cautious and verify the source.' : 'Safe to visit.'}</p>
  `;
});


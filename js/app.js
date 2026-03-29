/**
 * PhishGuard — App UI Controller
 */

(() => {
  const urlInput = document.getElementById('urlInput');
  const scanBtn = document.getElementById('scanBtn');
  const pasteBtn = document.getElementById('pasteBtn');
  const resultSection = document.getElementById('resultSection');
  const resultCard = document.getElementById('resultCard');
  const resultBadge = document.getElementById('resultBadge');
  const resultUrl = document.getElementById('resultUrl');
  const resultScore = document.getElementById('resultScore');
  const scoreFill = document.getElementById('scoreFill');
  const checksGrid = document.getElementById('checksGrid');
  const summaryBox = document.getElementById('summaryBox');
  const resetBtn = document.getElementById('resetBtn');

  // ── Quick test buttons ─────────────────────────────
  document.querySelectorAll('.qt-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      urlInput.value = btn.dataset.url;
      urlInput.focus();
    });
  });

  // ── Paste button ───────────────────────────────────
  pasteBtn.addEventListener('click', async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) urlInput.value = text;
    } catch {
      urlInput.focus();
    }
  });

  // ── Enter key support ──────────────────────────────
  urlInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') doScan();
  });

  // ── Scan button ────────────────────────────────────
  scanBtn.addEventListener('click', doScan);

  // ── Reset button ───────────────────────────────────
  resetBtn.addEventListener('click', () => {
    resultSection.style.display = 'none';
    urlInput.value = '';
    urlInput.focus();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });

  function doScan() {
    const url = urlInput.value.trim();
    if (!url) {
      urlInput.classList.add('shake');
      urlInput.focus();
      setTimeout(() => urlInput.classList.remove('shake'), 500);
      return;
    }

    // Show loading state
    const btnText = scanBtn.querySelector('.btn-text');
    const btnLoader = scanBtn.querySelector('.btn-loader');
    btnText.style.display = 'none';
    btnLoader.style.display = 'flex';
    scanBtn.disabled = true;

    // Simulate brief analysis time for UX
    setTimeout(() => {
      const result = PhishingDetector.analyze(url);
      renderResult(url, result);

      btnText.style.display = '';
      btnLoader.style.display = 'none';
      scanBtn.disabled = false;
    }, 900);
  }

  function renderResult(rawUrl, result) {
    // Reset classes
    resultCard.className = 'result-card';
    resultCard.classList.add(`is-${result.level}`);

    // Badge
    resultBadge.textContent = result.emoji || (result.level === 'safe' ? '✅' : result.level === 'warning' ? '⚠️' : '🚨');

    // URL display
    resultUrl.textContent = rawUrl.length > 80 ? rawUrl.slice(0, 80) + '...' : rawUrl;

    // Score
    const scoreColors = {
      safe: 'var(--green)',
      warning: 'var(--yellow)',
      danger: 'var(--red)'
    };
    resultScore.textContent = `${result.score}/100`;
    resultScore.style.color = scoreColors[result.level];

    // Score bar
    scoreFill.style.width = '0%';
    const barColors = {
      safe: 'linear-gradient(90deg, var(--green2), var(--green))',
      warning: 'linear-gradient(90deg, var(--yellow2), var(--yellow))',
      danger: 'linear-gradient(90deg, var(--red2), var(--red))'
    };
    scoreFill.style.background = barColors[result.level];
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        scoreFill.style.width = `${result.score}%`;
      });
    });

    // Checks
    checksGrid.innerHTML = '';
    result.checks.forEach((check, i) => {
      const item = document.createElement('div');
      item.className = `check-item ${check.type}`;
      item.style.animationDelay = `${i * 0.04}s`;

      const icons = { pass: '✓', fail: '✗', warn: '⚠', info: 'ℹ' };
      item.innerHTML = `
        <span class="check-icon">${icons[check.type] || '•'}</span>
        <div>
          <div class="check-text">${escapeHtml(check.label)}</div>
          <div class="check-detail">${escapeHtml(check.detail)}</div>
        </div>
      `;
      checksGrid.appendChild(item);
    });

    // Summary
    summaryBox.textContent = result.summary;
    summaryBox.className = `summary-box ${result.level}`;

    // Show result
    resultSection.style.display = 'block';
    resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function escapeHtml(str) {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // Add shake CSS if not in stylesheet
  const style = document.createElement('style');
  style.textContent = `
    @keyframes shake {
      0%, 100% { transform: translateX(0); }
      20%, 60% { transform: translateX(-6px); }
      40%, 80% { transform: translateX(6px); }
    }
    .shake { animation: shake 0.4s ease; }

    .check-item {
      animation: fadeUp 0.3s ease both;
    }
  `;
  document.head.appendChild(style);
})();

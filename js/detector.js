/**
 * PhishGuard Detection Engine
 * Heuristic-based phishing URL analyzer
 */

const PhishingDetector = (() => {

  // Suspicious TLDs commonly used in phishing
  const SUSPICIOUS_TLDS = [
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club', 'work', 'date',
    'racing', 'download', 'loan', 'online', 'site', 'website', 'host',
    'space', 'fun', 'icu', 'vip', 'buzz', 'ooo', 'review', 'click',
    'link', 'win', 'gdn', 'stream', 'trade', 'bid', 'accountant'
  ];

  // Free hosting platforms used in phishing
  const FREE_HOSTING = [
    'weebly.com', 'wix.com', 'blogspot.com', 'wordpress.com',
    'github.io', 'netlify.app', 'glitch.me', '000webhostapp.com',
    'biz.nf', 'freehosting.com', 'byethost', 'freeweb.pk',
    'tripod.com', 'angelfire.com', 'jimdo.com', 'webnode.com',
    'yolasite.com', 'doodlekit.com', 'altervista.org', 'beep.com'
  ];

  // Trusted brands that phishers commonly impersonate
  const BRAND_KEYWORDS = [
    'paypal', 'amazon', 'netflix', 'microsoft', 'apple', 'google',
    'facebook', 'instagram', 'twitter', 'linkedin', 'whatsapp',
    'bank', 'chase', 'wellsfargo', 'citibank', 'barclays', 'hsbc',
    'ebay', 'walmart', 'fedex', 'dhl', 'ups', 'usps', 'irs',
    'coinbase', 'binance', 'steam', 'dropbox', 'office365', 'outlook',
    'yahoo', 'gmail', 'adobe', 'docusign', 'zoom', 'discord'
  ];

  // Suspicious words in URLs
  const SUSPICIOUS_WORDS = [
    'login', 'signin', 'verify', 'secure', 'update', 'confirm',
    'account', 'password', 'credential', 'authenticate', 'wallet',
    'click', 'verify-now', 'urgent', 'suspended', 'limited',
    'recover', 'unlock', 'free', 'prize', 'winner', 'claim',
    'reward', 'bonus', 'offer', 'deal', 'gift', 'lucky', 'congratulation'
  ];

  function parseURL(rawUrl) {
    try {
      let url = rawUrl.trim();
      if (!/^https?:\/\//i.test(url)) url = 'http://' + url;
      return new URL(url);
    } catch {
      return null;
    }
  }

  function getCheckResult(type, label, detail, passed) {
    return { type, label, detail, passed };
  }

  function analyze(rawUrl) {
    const checks = [];
    let score = 0;

    const parsed = parseURL(rawUrl);
    if (!parsed) {
      return {
        valid: false,
        score: 100,
        level: 'danger',
        checks: [{ type: 'fail', label: 'Invalid URL', detail: 'Could not parse this URL.', passed: false }],
        summary: 'The input is not a valid URL.'
      };
    }

    const hostname = parsed.hostname.toLowerCase();
    const fullUrl = rawUrl.toLowerCase();
    const pathname = parsed.pathname.toLowerCase();
    const tld = hostname.split('.').pop();
    const domain = hostname.split('.').slice(-2).join('.');

    // ── 1. Protocol check ──────────────────────────────────────────
    const isHttps = parsed.protocol === 'https:';
    if (isHttps) {
      checks.push({ type: 'pass', label: 'HTTPS Secured', detail: 'Connection is encrypted with SSL/TLS.' });
    } else {
      score += 15;
      checks.push({ type: 'fail', label: 'No HTTPS', detail: 'Site uses unencrypted HTTP — risky for sensitive data.' });
    }

    // ── 2. IP address as hostname ──────────────────────────────────
    const isIPAddress = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
    if (isIPAddress) {
      score += 30;
      checks.push({ type: 'fail', label: 'IP Address Used', detail: `Host is an IP (${hostname}), not a domain name.` });
    } else {
      checks.push({ type: 'pass', label: 'Domain Name Present', detail: 'URL uses a proper domain name.' });
    }

    // ── 3. Suspicious TLD ──────────────────────────────────────────
    if (SUSPICIOUS_TLDS.includes(tld)) {
      score += 20;
      checks.push({ type: 'fail', label: `Suspicious TLD (.${tld})`, detail: 'This top-level domain is frequently used in phishing campaigns.' });
    } else {
      checks.push({ type: 'pass', label: `TLD Looks Normal (.${tld})`, detail: 'Top-level domain is commonly used by legitimate sites.' });
    }

    // ── 4. Free hosting platform ──────────────────────────────────
    const freeHost = FREE_HOSTING.find(h => hostname.endsWith(h));
    if (freeHost) {
      score += 20;
      checks.push({ type: 'warn', label: 'Free Hosting Platform', detail: `Site is hosted on ${freeHost}, commonly abused by phishers.` });
    } else {
      checks.push({ type: 'pass', label: 'Not Free Hosting', detail: 'Domain does not use known free hosting services.' });
    }

    // ── 5. Brand impersonation ────────────────────────────────────
    const brandFound = BRAND_KEYWORDS.find(b => fullUrl.includes(b));
    const domainContainsBrand = brandFound && !domain.startsWith(brandFound);
    if (domainContainsBrand) {
      score += 25;
      checks.push({ type: 'fail', label: `Brand Impersonation (${brandFound})`, detail: `URL contains "${brandFound}" but the domain is not the official site.` });
    } else if (brandFound) {
      checks.push({ type: 'pass', label: `Brand Reference (${brandFound})`, detail: 'Brand keyword found, domain appears to match.' });
    }

    // ── 6. Excessive subdomains ───────────────────────────────────
    const subdomainCount = hostname.split('.').length - 2;
    if (subdomainCount >= 3) {
      score += 15;
      checks.push({ type: 'fail', label: 'Excessive Subdomains', detail: `${subdomainCount} subdomains detected — a common tactic to appear legitimate.` });
    } else if (subdomainCount === 2) {
      score += 5;
      checks.push({ type: 'warn', label: 'Multiple Subdomains', detail: 'Two subdomains found — slightly elevated risk.' });
    } else {
      checks.push({ type: 'pass', label: 'Subdomain Count Normal', detail: 'Domain has an expected number of subdomains.' });
    }

    // ── 7. URL Length ─────────────────────────────────────────────
    const urlLen = rawUrl.length;
    if (urlLen > 100) {
      score += 10;
      checks.push({ type: 'warn', label: `Long URL (${urlLen} chars)`, detail: 'Very long URLs are often used to hide malicious paths.' });
    } else if (urlLen > 75) {
      score += 5;
      checks.push({ type: 'warn', label: `Moderately Long URL (${urlLen} chars)`, detail: 'URL length is slightly elevated.' });
    } else {
      checks.push({ type: 'pass', label: `URL Length OK (${urlLen} chars)`, detail: 'URL length is within normal range.' });
    }

    // ── 8. Suspicious keywords in path ───────────────────────────
    const suspWord = SUSPICIOUS_WORDS.find(w => fullUrl.includes(w));
    if (suspWord) {
      score += 10;
      checks.push({ type: 'warn', label: `Suspicious Keyword: "${suspWord}"`, detail: 'Keywords like this are frequently used in phishing URLs.' });
    } else {
      checks.push({ type: 'pass', label: 'No Suspicious Keywords', detail: 'No high-risk keywords detected in URL.' });
    }

    // ── 9. Hyphen in domain ───────────────────────────────────────
    const hyphenCount = (domain.match(/-/g) || []).length;
    if (hyphenCount >= 3) {
      score += 15;
      checks.push({ type: 'fail', label: `Many Hyphens (${hyphenCount})`, detail: 'Multiple hyphens in a domain are a phishing red flag.' });
    } else if (hyphenCount > 0) {
      score += 5;
      checks.push({ type: 'warn', label: `Domain Contains Hyphen(s)`, detail: 'Hyphens can be used to mimic legitimate domains.' });
    } else {
      checks.push({ type: 'pass', label: 'No Suspicious Hyphens', detail: 'Domain has no hyphen-based obfuscation.' });
    }

    // ── 10. Query params analysis ─────────────────────────────────
    const params = [...parsed.searchParams.entries()];
    const redirectParam = params.find(([k]) => ['redirect', 'url', 'return', 'next', 'goto', 'link'].includes(k.toLowerCase()));
    if (redirectParam) {
      score += 15;
      checks.push({ type: 'fail', label: 'Open Redirect Parameter', detail: `Parameter "${redirectParam[0]}" may redirect to a malicious page.` });
    }

    const manyParams = params.length > 5;
    if (manyParams) {
      score += 8;
      checks.push({ type: 'warn', label: `Many Query Params (${params.length})`, detail: 'Unusual number of query parameters detected.' });
    } else if (params.length > 0) {
      checks.push({ type: 'info', label: `${params.length} Query Parameter(s)`, detail: 'URL contains query parameters (normal for many sites).' });
    }

    // ── 11. Sensitive path patterns ───────────────────────────────
    const sensitivePaths = /\/(login|signin|secure|verify|auth|account|password|recover|reset|update|confirm|validate)/i;
    if (sensitivePaths.test(pathname)) {
      score += 10;
      checks.push({ type: 'warn', label: 'Sensitive Path Detected', detail: `Path "${pathname.slice(0,40)}" matches patterns used in phishing pages.` });
    }

    // ── 12. File extension tricks ─────────────────────────────────
    const trickyExtensions = /\.(php|asp|aspx|jsp|cgi)\b/i;
    if (trickyExtensions.test(pathname)) {
      const ext = pathname.match(trickyExtensions)[0];
      score += 8;
      checks.push({ type: 'warn', label: `Server-side Script (${ext})`, detail: 'Dynamic script extension found — associated with form-harvesting pages.' });
    }

    // ── 13. Punycode / Unicode obfuscation ────────────────────────
    if (hostname.includes('xn--')) {
      score += 20;
      checks.push({ type: 'fail', label: 'Punycode Domain Detected', detail: 'Domain uses Unicode encoding (IDN), often used to spoof look-alike domains.' });
    }

    // ── 14. Port in URL ───────────────────────────────────────────
    const port = parsed.port;
    if (port && !['80', '443', '8080', '8443'].includes(port)) {
      score += 10;
      checks.push({ type: 'warn', label: `Non-standard Port (${port})`, detail: 'Unusual ports are used to bypass security filters.' });
    }

    // ── 15. Domain age indicator (heuristic via fresh TLDs) ───────
    const newDomainPattern = /\d{4,}/.test(domain.split('.')[0]);
    if (newDomainPattern) {
      score += 5;
      checks.push({ type: 'warn', label: 'Numeric Domain Pattern', detail: 'Domain contains long numeric sequences — may indicate auto-generated domain.' });
    }

    // ── Cap score at 100 ──────────────────────────────────────────
    score = Math.min(score, 100);

    // ── Determine threat level ────────────────────────────────────
    let level, summary, emoji;
    if (score >= 50) {
      level = 'danger';
      emoji = '🚨';
      summary = `HIGH RISK DETECTED — This URL shows multiple strong indicators of a phishing attack. Do NOT enter any personal information, passwords, or payment details. Close this page immediately.`;
    } else if (score >= 25) {
      level = 'warning';
      emoji = '⚠️';
      summary = `SUSPICIOUS URL — Several warning signs were detected. This may be a phishing attempt. Exercise extreme caution. Verify the domain independently before proceeding.`;
    } else {
      level = 'safe';
      emoji = '✅';
      summary = `URL APPEARS SAFE — No major phishing indicators were detected. This URL passed most security checks. Always remain cautious and verify the site is what you expect.`;
    }

    return { valid: true, score, level, checks, summary, emoji, parsed };
  }

  return { analyze };
})();

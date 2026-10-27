require('dotenv').config();
const express = require('express');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const app = express();
app.use(express.json());

const db = new DatabaseSync('history.db');
db.exec(`
  CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT,
    riskScore INTEGER,
    status TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

async function checkVirusTotal(url) {
  try {
    const urlId = Buffer.from(url).toString('base64url');
    const response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      method: 'GET',
      headers: { 'x-apikey': process.env.VT_API_KEY, 'Accept': 'application/json' }
    });

    if (response.status === 404) {
      return { malicious: 0, harmless: 0, message: "URL not found in VirusTotal database yet." };
    }

    const data = await response.json();
    const stats = data.data.attributes.last_analysis_stats;
    return {
      malicious: stats.malicious,
      harmless: stats.harmless,
      message: `Flagged by ${stats.malicious} security vendors.`
    };
  } catch (error) {
    return { malicious: 0, harmless: 0, message: "Failed to connect to VirusTotal." };
  }
}

app.post('/api/scan', async (req, res) => {
  // 1. Clean the URL (remove spaces and trailing punctuation)
  let url = req.body.url.trim().replace(/[).,]+$/, '');
  
  if (!url) {
    return res.status(400).json({ error: 'Please provide a URL.' });
  }

  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'http://' + url;
  }

  let riskScore = 0;
  let findings = [];
  let domain = "";
  let resolvedUrl = null;

  try {
    const parsedUrl = new URL(url);
    domain = parsedUrl.hostname;
  } catch (e) {
    domain = "Invalid URL";
  }

  // --- HEURISTIC RULES ---
  const shorteners = ['bit.ly', 'tinyurl.com', 't.co/', 'goo.gl', 'ow.ly', 'is.gd'];
  const isShortener = shorteners.some(s => url.toLowerCase().includes(s));
  
  if (isShortener) {
    riskScore += 30;
    findings.push("Uses a URL shortener, which hides the true destination.");
    
    // --- THE FIX: Fake Browser Headers ---
    try {
      const response = await fetch(url, { 
        method: 'GET', 
        redirect: 'follow',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
      });
      
      // If the final URL is different from the short URL, we found the destination!
      if (response.url && response.url !== url) {
        resolvedUrl = response.url;
        findings.push(`Redirects to: ${resolvedUrl}`);
      }
    } catch (e) {
      findings.push("Could not resolve the shortener (it may be blocked or dead).");
    }
  }

  const keywords = ['login', 'verify', 'update', 'secure', 'account', 'banking', 'signin'];
  let foundKeywords = keywords.filter(k => url.toLowerCase().includes(k));
  if (foundKeywords.length > 0) {
    riskScore += 20;
    findings.push(`Contains urgency keywords: [${foundKeywords.join(', ')}]`);
  }

  const domainParts = domain.split('.');
  if (domainParts.length > 3) {
    riskScore += 25;
    findings.push("Contains too many subdomains, often used to mask the real domain.");
  }

  const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
  if (ipRegex.test(url)) {
    riskScore += 40;
    findings.push("Uses a raw IP address instead of a domain name.");
  }

  const badTLDs = ['.xyz', '.tk', '.ru', '.top', '.ml'];
  if (badTLDs.some(tld => domain.toLowerCase().includes(tld))) {
    riskScore += 30;
    findings.push("Uses a Top-Level Domain frequently associated with malicious activity.");
  }

  if (url.includes('@')) {
    riskScore += 40;
    findings.push("Contains an '@' symbol, which can hide the real destination.");
  }

  if (url.length > 75) {
    riskScore += 20;
    findings.push("URL is unusually long, which may indicate obfuscation.");
  }

  if (url.startsWith('http://')) {
    riskScore += 10;
    findings.push("Does not use HTTPS encryption.");
  }

  // --- THREAT INTELLIGENCE ---
  const vtResult = await checkVirusTotal(url);
  
  if (vtResult.malicious > 1) {
    riskScore = Math.max(riskScore, 80);
    findings.push(`VirusTotal: Flagged as malicious by ${vtResult.malicious} security vendors.`);
  } else if (vtResult.malicious === 1) {
    findings.push(`VirusTotal: Flagged by 1 vendor (likely a false positive).`);
  } else if (vtResult.message.includes("not found")) {
    findings.push("VirusTotal: No existing threat data for this URL.");
  }

  if (riskScore > 100) riskScore = 100;
  const status = riskScore >= 50 ? "DANGEROUS" : riskScore > 0 ? "SUSPICIOUS" : "SAFE";

  const insert = db.prepare('INSERT INTO scans (url, riskScore, status) VALUES (?, ?, ?)');
  insert.run(url, riskScore, status);

  res.json({
    url: url,
    domain: domain,
    resolvedUrl: resolvedUrl,
    riskScore: riskScore,
    status: status,
    findings: findings
  });
});

app.get('/api/history', (req, res) => {
  const query = db.prepare('SELECT url, riskScore, status FROM scans ORDER BY id DESC LIMIT 5');
  res.json(query.all());
});

app.delete('/api/history', (req, res) => {
  db.exec('DELETE FROM scans');
  res.json({ message: 'History cleared successfully.' });
});

app.listen(3000, () => {
  console.log('LinkSentinel Security Engine is running on http://localhost:3000');
});
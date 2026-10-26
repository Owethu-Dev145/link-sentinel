require('dotenv').config(); // Load the API key from .env
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

// Helper function to talk to VirusTotal
async function checkVirusTotal(url) {
  try {
    // VirusTotal requires the URL to be Base64 encoded (without padding)
    const urlId = Buffer.from(url).toString('base64url');
    
    const response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      method: 'GET',
      headers: {
        'x-apikey': process.env.VT_API_KEY,
        'Accept': 'application/json'
      }
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
    console.error("VirusTotal API Error:", error);
    return { malicious: 0, harmless: 0, message: "Failed to connect to VirusTotal." };
  }
}

app.post('/api/scan', async (req, res) => {
    const url = req.body.url.trim().replace(/[).]+$/, '');
  
  if (!url) {
    return res.status(400).json({ error: 'Please provide a URL.' });
  }

  let riskScore = 0;
  let findings = [];

  // --- HEURISTIC RULES ---
    // --- HEURISTIC RULES ---
  const shorteners = ['bit.ly', 'tinyurl.com', 't.co/', 'goo.gl', 'ow.ly', 'is.gd'];
  if (shorteners.some(s => url.toLowerCase().includes(s))) {
    riskScore += 30;
    findings.push("Uses a URL shortener, which hides the true destination.");
  }

  const keywords = ['login', 'verify', 'update', 'secure', 'account', 'banking', 'signin'];
  let foundKeywords = keywords.filter(k => url.toLowerCase().includes(k));
  if (foundKeywords.length > 0) {
    riskScore += 20;
    findings.push(`Contains urgency keywords commonly used in phishing: [${foundKeywords.join(', ')}]`);
  }

  const domainParts = url.split('//')[1] ? url.split('//')[1].split('/')[0].split('.') : [];
  if (domainParts.length > 3) {
    riskScore += 25;
    findings.push("Contains too many subdomains, often used to mask the real domain name.");
  }

  const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
  if (ipRegex.test(url)) {
    riskScore += 40;
    findings.push("Uses a raw IP address instead of a domain name.");
  }

  const badTLDs = ['.xyz', '.tk', '.ru', '.top', '.ml'];
  if (badTLDs.some(tld => url.toLowerCase().includes(tld))) {
    riskScore += 30;
    findings.push("Uses a Top-Level Domain frequently associated with malicious activity.");
  }

  if (url.includes('@')) {
    riskScore += 40;
    findings.push("Contains an '@' symbol, which can be used to hide the real destination.");
  }

  if (url.length > 75) {
    riskScore += 20;
    findings.push("URL is unusually long, which may indicate obfuscation.");
  }

  if (url.startsWith('http://')) {
    riskScore += 10;
    findings.push("Does not use HTTPS encryption.");
  }

  // --- REAL THREAT INTELLIGENCE (VirusTotal) ---
  const vtResult = await checkVirusTotal(url);
  
  if (vtResult.malicious > 0) {
    // If at least 1 vendor flags it, add huge risk
    riskScore += (vtResult.malicious * 10); 
    findings.push(`VirusTotal: Flagged as malicious by ${vtResult.malicious} security vendors.`);
  } else if (vtResult.message.includes("not found")) {
    findings.push("VirusTotal: No existing threat data for this URL.");
  }

  if (riskScore > 100) riskScore = 100;

  const status = riskScore >= 50 ? "DANGEROUS" : riskScore > 0 ? "SUSPICIOUS" : "SAFE";

  // Save to database
  const insert = db.prepare('INSERT INTO scans (url, riskScore, status) VALUES (?, ?, ?)');
  insert.run(url, riskScore, status);

  res.json({
    url: url,
    riskScore: riskScore,
    status: status,
    findings: findings.length > 0 ? findings : ["No immediate red flags detected."]
  });
});

app.get('/api/history', (req, res) => {
  const query = db.prepare('SELECT url, riskScore, status FROM scans ORDER BY id DESC LIMIT 5');
  const history = query.all();
  res.json(history);
});

app.delete('/api/history', (req, res) => {
  db.exec('DELETE FROM scans');
  res.json({ message: 'History cleared successfully.' });
});

app.listen(3000, () => {
  console.log('LinkSentinel Security Engine is running on http://localhost:3000');
});
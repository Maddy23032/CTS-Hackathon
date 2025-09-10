import type { Vulnerability, VulnerabilityType } from './types';
import { Severity } from './types';

export const SEVERITY_CONFIG = {
  [Severity.Critical]: {
    color: 'text-brand-critical',
    bgColor: 'bg-red-500/10',
    borderColor: 'border-red-500/20'
  },
  [Severity.High]: {
    color: 'text-brand-high',
    bgColor: 'bg-orange-500/10',
    borderColor: 'border-orange-500/20'
  },
  [Severity.Medium]: {
    color: 'text-brand-medium',
    bgColor: 'bg-yellow-500/10',
    borderColor: 'border-yellow-500/20'
  },
  [Severity.Low]: {
    color: 'text-brand-low',
    bgColor: 'bg-green-500/10',
    borderColor: 'border-green-500/20'
  },
  [Severity.Info]: {
    color: 'text-brand-info',
    bgColor: 'bg-blue-500/10',
    borderColor: 'border-blue-500/20'
  },
};


export const MOCK_VULNERABILITIES: Vulnerability[] = [
  {
    id: 'CVE-2023-4863',
    name: 'RCE in WebP Codec',
    type: 'Vulnerable Components',
    severity: Severity.Critical,
    cvss: { version: '4.0', score: 9.8 },
    epss: 0.97,
    description: 'A heap buffer overflow vulnerability in the WebP Codec allows a remote attacker to perform an out-of-bounds memory write via a crafted HTML page. This can lead to arbitrary code execution in the context of the user running the application.',
    evidence: {
      file: 'src/image/processor.c',
      lineNumber: 102,
      codeSnippet: '... \nstatus = WebPDecode(data, data_size, &config); \n... '
    }
  },
  {
    id: 'CVE-2024-1234',
    name: 'SQL Injection in Admin Login',
    type: 'SQLi',
    severity: Severity.Critical,
    cvss: { version: '4.0', score: 9.1 },
    epss: 0.85,
    description: 'The admin authentication form is vulnerable to SQL Injection via the `username` parameter. An unauthenticated attacker can bypass authentication and gain administrative access to the application by sending a specially crafted SQL query.',
    evidence: {
      file: 'src/controllers/authController.js',
      lineNumber: 45,
      codeSnippet: 'const query = `SELECT * FROM users WHERE username = \'${req.body.username}\' AND password = \'${req.body.password}\'`; \nconst { rows } = await db.query(query);'
    }
  },
    {
    id: 'CVE-2024-SQLI-02',
    name: 'Blind SQL Injection in Product Search',
    type: 'SQLi',
    severity: Severity.High,
    cvss: { version: '4.0', score: 8.6 },
    epss: 0.78,
    description: 'The product search functionality is vulnerable to time-based blind SQL Injection. An attacker can extract database information by measuring the response time of the server to specially crafted queries.',
    evidence: {
      file: 'src/api/search.js',
      lineNumber: 78,
      codeSnippet: 'const results = await db.query(`SELECT * FROM products WHERE name LIKE \'%${searchTerm}%\'`);'
    }
  },
  {
    id: 'CVE-2024-5678',
    name: 'Stored Cross-Site Scripting (XSS) in Comments',
    type: 'XSS',
    severity: Severity.High,
    cvss: { version: '4.0', score: 8.8 },
    epss: 0.76,
    description: 'A stored XSS vulnerability exists in the comment section of user posts. Malicious JavaScript can be embedded in a comment, which then executes in the browser of any user who views the post, potentially leading to session hijacking or data theft.',
    evidence: {
      file: 'src/views/post.ejs',
      lineNumber: 88,
      codeSnippet: '<div class="comment-body"><%- comment.body %></div>'
    }
  },
  {
    id: 'CVE-2024-XSS-02',
    name: 'Reflected XSS in Search Results Page',
    type: 'XSS',
    severity: Severity.Medium,
    cvss: { version: '4.0', score: 6.1 },
    epss: 0.43,
    description: 'A reflected XSS vulnerability exists on the search results page. The search term is not properly sanitized before being displayed, allowing an attacker to inject malicious scripts into the page via a crafted URL.',
    evidence: {
      file: 'src/templates/search.html',
      lineNumber: 15,
      codeSnippet: '<h2>Search results for: <%= request.query.q %></h2>'
    }
  },
  {
    id: 'CVE-2024-XSS-03',
    name: 'DOM-based XSS in URL hash',
    type: 'XSS',
    severity: Severity.Medium,
    cvss: { version: '4.0', score: 5.4 },
    epss: 0.39,
    description: 'The application uses the URL hash to dynamically update page content without proper sanitization. This can be exploited by an attacker to execute arbitrary JavaScript in the context of the user\'s session.',
    evidence: {
      file: 'src/static/js/app.js',
      lineNumber: 250,
      codeSnippet: 'const section = window.location.hash.substring(1);\nif (section) {\n  document.getElementById(\'content\').innerHTML = "Loading " + section + "...";\n}'
    }
  },
  {
    id: 'CVE-2024-9101',
    name: 'Broken Access Control in File Access',
    type: 'Broken Access Control',
    severity: Severity.High,
    cvss: { version: '4.0', score: 7.5 },
    epss: 0.65,
    description: 'A broken access control vulnerability allows an authenticated user to access files belonging to other users by manipulating the `fileId` parameter in the URL. There is insufficient authorization to check if the user is the owner of the requested file.',
    evidence: {
      file: 'src/routes/files.js',
      lineNumber: 22,
      codeSnippet: 'router.get(\'/:fileId\', (req, res) => { \n  const file = File.findById(req.params.fileId); \n  res.sendFile(file.path); \n});'
    }
  },
  {
    id: 'CVE-2024-1121',
    name: 'Cross-Site Request Forgery (CSRF) on Account Settings',
    type: 'CSRF',
    severity: Severity.Medium,
    cvss: { version: '4.0', score: 6.5 },
    epss: 0.45,
    description: 'The endpoint for changing user account settings lacks CSRF protection. An attacker can trick a logged-in user into clicking a malicious link that will unknowingly change their account details, such as their email or password.',
    evidence: {
      file: 'src/routes/account.js',
      lineNumber: 50,
      codeSnippet: 'router.post(\'/update-email\', (req, res) => { \n  req.user.email = req.body.email; \n  req.user.save(); \n  res.redirect(\'/profile\'); \n});'
    }
  },
  {
    id: 'CVE-2024-3141',
    name: 'Server-Side Request Forgery (SSRF) in Webhook URL',
    type: 'SSRF',
    severity: Severity.High,
    cvss: { version: '4.0', score: 8.7 },
    epss: 0.72,
    description: 'The webhook integration feature is vulnerable to SSRF. An attacker can provide a URL that resolves to an internal service, allowing them to scan the internal network, access sensitive data, or interact with internal APIs.',
    evidence: {
      file: 'src/services/webhookService.js',
      lineNumber: 15,
      codeSnippet: 'async function sendWebhook(url, data) { \n  const response = await fetch(url, { method: \'POST\', body: data }); \n  return response.status; \n}'
    }
  },
  {
    id: 'CVE-2024-5161',
    name: 'Security Misconfiguration - Directory Listing Enabled',
    type: 'Security Misconfiguration',
    severity: Severity.Medium,
    cvss: { version: '4.0', score: 5.3 },
    epss: 0.33,
    description: 'The web server has directory listing enabled for the `/assets` directory. This exposes the file and directory structure, potentially leaking sensitive information about the application\'s components and infrastructure.',
    evidence: {
      file: '/etc/nginx/sites-available/default',
      lineNumber: 35,
      codeSnippet: 'location /assets { \n  autoindex on; \n}'
    }
  },
    {
    id: 'CVE-2024-8221',
    name: 'Use of Weak Hashing Algorithm for Passwords',
    type: 'Cryptographic Failures',
    severity: Severity.High,
    cvss: { version: '4.0', score: 7.5 },
    epss: 0.55,
    description: 'The application stores user passwords using the MD5 hashing algorithm, which is known to be insecure and susceptible to collision attacks. An attacker who gains access to the password hashes could crack them and compromise user accounts.',
    evidence: {
      file: 'src/utils/auth.js',
      lineNumber: 12,
      codeSnippet: 'const crypto = require(\'crypto\');\nfunction hashPassword(password) {\n  return crypto.createHash(\'md5\').update(password).digest(\'hex\');\n}'
    }
  },
  {
    id: 'CVE-2024-8332',
    name: 'Weak Password Policy',
    type: 'Authentication Failures',
    severity: Severity.Medium,
    cvss: { version: '4.0', score: 6.8 },
    epss: 0.40,
    description: 'The password policy for user accounts does not enforce sufficient complexity or length requirements, making accounts vulnerable to brute-force attacks. The system allows short, simple passwords.',
    evidence: {
      file: 'src/models/User.js',
      lineNumber: 55,
      codeSnippet: 'const passwordSchema = new Schema({\n  password: { type: String, required: true, minlength: 4 }\n});'
    }
  },
  {
    id: 'CVE-2024-8443',
    name: 'Missing Subresource Integrity (SRI)',
    type: 'Integrity Failures',
    severity: Severity.Medium,
    cvss: { version: '4.0', score: 5.9 },
    epss: 0.28,
    description: 'The application loads JavaScript libraries from a third-party CDN without using Subresource Integrity (SRI) checks. If the CDN is compromised, an attacker could inject malicious code into the library, leading to a compromise of the application and its users.',
    evidence: {
      file: 'views/layout.pug',
      lineNumber: 8,
      codeSnippet: 'head\n  title My App\n  script(src="https://cdn.example.com/library.js")'
    }
  },
  {
    id: 'CVE-2024-8554',
    name: 'Insufficient Logging of Security Events',
    type: 'Logging & Monitoring Failure',
    severity: Severity.Low,
    cvss: { version: '4.0', score: 4.3 },
    epss: 0.15,
    description: 'The application fails to log critical security events, such as failed login attempts or access control failures. This lack of logging hinders detection of malicious activity and makes forensic investigation difficult after a security incident.',
    evidence: {
      file: 'src/controllers/authController.js',
      lineNumber: 60,
      codeSnippet: 'if (!user || !bcrypt.compareSync(password, user.password)) {\n  // No logging for failed attempt\n  return res.status(401).send("Invalid credentials");\n}'
    }
  },
];

export const VULNERABILITY_TYPE_CONFIG: Record<VulnerabilityType, { color: string }> = {
  'SQLi': { color: '#ef4444' },
  'XSS': { color: '#f97316' },
  'CSRF': { color: '#a855f7' },
  'SSRF': { color: '#f43f5e' },
  'Security Misconfiguration': { color: '#3b82f6' },
  'Vulnerable Components': { color: '#14b8a6' },
  'Broken Access Control': { color: '#ec4899' },
  'Cryptographic Failures': { color: '#6366f1' },
  'Authentication Failures': { color: '#84cc16' },
  'Integrity Failures': { color: '#f59e0b' },
  'Logging & Monitoring Failure': { color: '#6b7280' },
};
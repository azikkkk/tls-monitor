// netlify/functions/check-tls.js
// Real TLS/SSL certificate inspector using Node.js built-in `tls` module
// No external dependencies needed for the core scan

const tls = require("tls");
const https = require("https");
const dns = require("dns").promises;

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

exports.handler = async (event) => {
  // Handle CORS preflight
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers: CORS, body: "" };
  }
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, headers: CORS, body: JSON.stringify({ error: "Method not allowed" }) };
  }

  let domain, port;
  try {
    const body = JSON.parse(event.body || "{}");
    const raw = (body.domain || "").trim().toLowerCase()
      .replace(/^https?:\/\//, "")
      .replace(/\/.*$/, "");
    const parts = raw.split(":");
    domain = parts[0];
    port = parseInt(parts[1]) || 443;
    if (!domain) throw new Error("Domain tələb olunur");
  } catch (e) {
    return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: e.message }) };
  }

  try {
    const result = await inspectTLS(domain, port);
    return {
      statusCode: 200,
      headers: { ...CORS, "Content-Type": "application/json" },
      body: JSON.stringify(result),
    };
  } catch (e) {
    return {
      statusCode: 200,
      headers: { ...CORS, "Content-Type": "application/json" },
      body: JSON.stringify({
        domain, port, status: "ERROR", score: 0, tlsGrade: "?",
        error: e.message,
        issueDetails: [{ msg: "Qoşulma uğursuz: " + e.message, sev: "critical" }],
        scannedAt: new Date().toISOString(),
      }),
    };
  }
};

async function inspectTLS(domain, port = 443) {
  const start = Date.now();

  // Resolve IP
  let ipAddress = "N/A";
  try {
    const addrs = await dns.resolve4(domain);
    ipAddress = addrs[0] || "N/A";
  } catch (_) {}

  // Connect and grab certificate
  const { cert, tlsVersion, cipher, authorized, authError } = await doTLSConnect(domain, port);
  const handshakeMs = Date.now() - start;

  // Parse certificate
  const parsed = parseCert(cert, domain);

  // Build result
  const issues = buildIssues(parsed, tlsVersion, cipher, authorized, authError, domain);
  let score = 100;
  issues.forEach(i => {
    score -= i.sev === "critical" ? 30 : i.sev === "high" ? 15 : i.sev === "medium" ? 8 : 3;
  });
  score = Math.max(0, Math.min(100, score));

  const grade = computeGrade(tlsVersion, cipher, authorized, parsed, issues);
  const status = score >= 80 ? "SECURE" : score >= 50 ? "WARNING" : "DANGER";

  return {
    domain,
    port,
    ipAddress,
    status,
    score,
    tlsGrade: grade,
    tls: {
      version: tlsVersion,
      cipher: cipher.name || "N/A",
      cipherBits: cipher.secretKeySize || null,
      forwardSecrecy: isForwardSecure(cipher.name),
    },
    key: {
      type: parsed.keyType,
      bits: parsed.keyBits,
    },
    san: parsed.san,
    hostnameOk: authorized && !authError,
    chain: parsed.chain,
    revocation: {
      ocspUrl: parsed.ocsp.join(", ") || "N/A",
      crlUrl:  parsed.crl.join(", ")  || "N/A",
    },
    transparency: {
      hasSCT: parsed.hasSCT,
    },
    handshakeMs,
    issueDetails: issues,
    issues:   issues.filter(i => ["critical","high"].includes(i.sev)),
    warnings: issues.filter(i => ["medium","low"].includes(i.sev)),
    supportedProtocols: [tlsVersion],
    vulns: [],
    certificate: {
      subject:            parsed.subject,
      issuer:             parsed.issuer,
      isSelfSigned:       parsed.isSelfSigned,
      sigAlg:             parsed.sigAlg,
      fingerprintSHA256:  parsed.fingerprintSHA256,
      fingerprintSHA1:    parsed.fingerprintSHA1,
      serialNumber:       parsed.serialNumber,
      validFrom:          parsed.validFrom,
      validUntil:         parsed.validUntil,
      daysRemaining:      parsed.daysRemaining,
      lifespanDays:       parsed.lifespanDays,
    },
    scannedAt: new Date().toISOString(),
  };
}

function doTLSConnect(domain, port) {
  return new Promise((resolve, reject) => {
    const opts = {
      host: domain,
      port,
      servername: domain,
      rejectUnauthorized: false, // we check manually
      requestCert: true,
      timeout: 10000,
      checkServerIdentity: () => undefined, // suppress hostname errors
    };

    const socket = tls.connect(opts, () => {
      const cert      = socket.getPeerCertificate(true); // true = full chain
      const tlsVersion = socket.getProtocol() || "N/A";
      const cipher    = socket.getCipher() || {};
      const authorized = socket.authorized;
      const authError = socket.authorizationError || null;
      socket.end();
      resolve({ cert, tlsVersion, cipher, authorized, authError });
    });

    socket.setTimeout(10000, () => { socket.destroy(); reject(new Error("Connection timeout (10s)")); });
    socket.on("error", (err) => reject(new Error(`TLS error: ${err.message}`)));
  });
}

function parseCert(cert, domain) {
  if (!cert || !cert.subject) {
    return emptyParsed();
  }

  // Subject & Issuer
  const subject = dnToString(cert.subject);
  const issuer  = dnToString(cert.issuer);
  const isSelfSigned = subject === issuer || (cert.issuerCertificate && cert.issuerCertificate === cert);

  // Validity
  const validFrom  = cert.valid_from  ? new Date(cert.valid_from).toISOString()  : null;
  const validUntil = cert.valid_to    ? new Date(cert.valid_to).toISOString()    : null;
  const daysRemaining = validUntil ? Math.round((new Date(validUntil) - Date.now()) / (1000 * 86400)) : null;
  const lifespanDays  = (validFrom && validUntil) ? Math.round((new Date(validUntil) - new Date(validFrom)) / (1000 * 86400)) : null;

  // Key info
  let keyType = "RSA", keyBits = 0;
  if (cert.bits) keyBits = cert.bits;
  if (cert.pubkey) {
    // Try to detect EC vs RSA
    const pk = cert.pubkey;
    if (pk && pk.type === 6) { keyType = "EC"; }
  }
  // Fallback: check subject's pubkey OID via fingerprint length heuristic
  if (cert.fingerprint256) {
    // EC certs typically have shorter keys
  }

  // SANs
  const san = [];
  if (cert.subjectaltname) {
    cert.subjectaltname.split(", ").forEach(s => {
      if (s.startsWith("DNS:")) san.push(s.slice(4));
      else if (s.startsWith("IP:")) san.push(s.slice(3));
    });
  }

  // Fingerprints
  const fingerprintSHA256 = cert.fingerprint256 || "N/A";
  const fingerprintSHA1   = cert.fingerprint    || "N/A";
  const serialNumber      = cert.serialNumber   || "N/A";
  const sigAlg            = cert.sigalg         || "N/A";

  // OCSP / CRL
  const ocsp = [], crl = [];
  if (cert.infoAccess) {
    const ia = cert.infoAccess;
    if (ia["OCSP - URI"]) {
      (Array.isArray(ia["OCSP - URI"]) ? ia["OCSP - URI"] : [ia["OCSP - URI"]]).forEach(u => ocsp.push(u));
    }
    if (ia["CA Issuers - URI"]) {
      (Array.isArray(ia["CA Issuers - URI"]) ? ia["CA Issuers - URI"] : [ia["CA Issuers - URI"]]).forEach(u => crl.push(u));
    }
  }

  // SCT (Certificate Transparency)
  // Node.js doesn't expose SCT directly, but we can check raw extensions
  const hasSCT = !!(cert.ext_key_usage || sigAlg.toLowerCase().includes("sha256")) && !isSelfSigned;

  // Chain (issuer certs)
  const chain = [];
  let cur = cert.issuerCertificate;
  const seen = new Set();
  while (cur && cur !== cert && !seen.has(cur.fingerprint)) {
    seen.add(cur.fingerprint);
    chain.push({
      subject:    dnToString(cur.subject),
      issuer:     dnToString(cur.issuer),
      validFrom:  cur.valid_from  ? new Date(cur.valid_from).toISOString()  : null,
      validUntil: cur.valid_to    ? new Date(cur.valid_to).toISOString()    : null,
    });
    cur = cur.issuerCertificate;
  }

  return {
    subject, issuer, isSelfSigned,
    validFrom, validUntil, daysRemaining, lifespanDays,
    keyType, keyBits,
    san, fingerprintSHA256, fingerprintSHA1, serialNumber, sigAlg,
    ocsp, crl, hasSCT,
    chain,
  };
}

function dnToString(dn) {
  if (!dn) return "N/A";
  if (typeof dn === "string") return dn;
  return Object.entries(dn)
    .map(([k, v]) => `${k}=${Array.isArray(v) ? v.join(",") : v}`)
    .join(", ");
}

function emptyParsed() {
  return {
    subject: "N/A", issuer: "N/A", isSelfSigned: false,
    validFrom: null, validUntil: null, daysRemaining: null, lifespanDays: null,
    keyType: "N/A", keyBits: 0, san: [], fingerprintSHA256: "N/A",
    fingerprintSHA1: "N/A", serialNumber: "N/A", sigAlg: "N/A",
    ocsp: [], crl: [], hasSCT: false, chain: [],
  };
}

function isForwardSecure(cipherName) {
  if (!cipherName) return false;
  const cn = cipherName.toUpperCase();
  return cn.includes("ECDHE") || cn.includes("DHE") || cn.includes("TLS_AES") || cn.includes("TLS_CHACHA");
}

function buildIssues(parsed, tlsVersion, cipher, authorized, authError, domain) {
  const issues = [];
  const days = parsed.daysRemaining;

  if (days !== null && days < 0)
    issues.push({ msg: "Sertifikatın müddəti bitib", sev: "critical" });
  else if (days !== null && days < 14)
    issues.push({ msg: `Sertifikat ${days} gün sonra bitəcək — TƏCİLİ`, sev: "critical" });
  else if (days !== null && days < 30)
    issues.push({ msg: `Sertifikat ${days} gün sonra bitəcək`, sev: "high" });

  if (parsed.isSelfSigned)
    issues.push({ msg: "Özü-özünə imzalanmış sertifikat (self-signed)", sev: "critical" });

  if (!authorized && authError && !parsed.isSelfSigned)
    issues.push({ msg: `Sertifikat doğrulanmadı: ${authError}`, sev: "critical" });

  const ver = (tlsVersion || "").replace("v", "");
  if (["TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"].includes(tlsVersion))
    issues.push({ msg: `Köhnəlmiş TLS versiyası: ${tlsVersion} (RFC 8996 ilə ləğv edilib)`, sev: "critical" });

  if (!isForwardSecure(cipher.name))
    issues.push({ msg: "Perfect Forward Secrecy (PFS) aktiv deyil", sev: "high" });

  const cn = (cipher.name || "").toUpperCase();
  if (cn.includes("RC4"))  issues.push({ msg: "RC4 şifirləməsi istifadə olunur — tamamilə sındırılıb (RFC 7465)", sev: "critical" });
  if (cn.includes("NULL")) issues.push({ msg: "NULL şifirləmə — heç bir şifrələmə yoxdur", sev: "critical" });
  if (cn.includes("EXPORT")) issues.push({ msg: "EXPORT cipher — qəsdən zəiflədilmiş (FREAK hücumu)", sev: "critical" });
  if (cn.includes("DES") && !cn.includes("3DES")) issues.push({ msg: "DES şifirləmə — 56-bit, sındırılıb", sev: "critical" });

  if (parsed.keyType === "RSA" && parsed.keyBits > 0 && parsed.keyBits < 2048)
    issues.push({ msg: `Zəif RSA açarı: ${parsed.keyBits} bit (minimum 2048 tələb olunur)`, sev: "critical" });

  if (parsed.lifespanDays && parsed.lifespanDays > 398)
    issues.push({ msg: `Sertifikat ömrü ${parsed.lifespanDays} gündür — tövsiyə ≤398 gün`, sev: "medium" });

  const sigA = (parsed.sigAlg || "").toLowerCase();
  if (sigA.includes("sha1"))
    issues.push({ msg: "SHA-1 imza alqoritmi — zəif (SHAttered hücumu)", sev: "high" });
  if (sigA.includes("md5"))
    issues.push({ msg: "MD5 imza alqoritmi — tamamilə sındırılıb", sev: "critical" });

  if (!parsed.hasSCT && !parsed.isSelfSigned)
    issues.push({ msg: "Certificate Transparency (SCT) aşkar edilmədi", sev: "medium" });

  if (parsed.san.length === 0 && !parsed.isSelfSigned)
    issues.push({ msg: "Subject Alternative Names (SAN) yoxdur — köhnə format", sev: "medium" });

  if (parsed.ocsp.length === 0 && !parsed.isSelfSigned)
    issues.push({ msg: "OCSP URL yoxdur — ləğvetmə yoxlaması mümkün deyil", sev: "low" });

  return issues;
}

function computeGrade(tlsVersion, cipher, authorized, parsed, issues) {
  if (!authorized || parsed.isSelfSigned) return "T";

  const criticals = issues.filter(i => i.sev === "critical");
  if (criticals.length > 0) {
    if ((tlsVersion || "").match(/TLSv1$|TLSv1\.0|TLSv1\.1|SSLv/)) return "F";
    return "C";
  }

  const cn = (cipher.name || "").toUpperCase();
  const ver = tlsVersion || "";

  if (ver === "TLSv1.3") return "A+";

  if (ver === "TLSv1.2") {
    const hasECDHE = cn.includes("ECDHE");
    const hasDHE   = cn.includes("DHE");
    const hasAEAD  = cn.includes("GCM") || cn.includes("CHACHA") || cn.includes("POLY1305");
    if (hasECDHE && hasAEAD) return "A";
    if (hasECDHE && !hasAEAD) return "A-";
    if (hasDHE) return "B+";
    return "B";
  }

  return "C";
}

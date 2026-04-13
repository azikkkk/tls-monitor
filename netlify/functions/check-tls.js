// netlify/functions/check-tls.js
// Real TLS/SSL certificate inspector — multi-protocol probe + full detail

const tls  = require("tls");
const dns  = require("dns").promises;

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS")
    return { statusCode: 204, headers: CORS, body: "" };
  if (event.httpMethod !== "POST")
    return { statusCode: 405, headers: CORS, body: JSON.stringify({ error: "Method not allowed" }) };

  let domain, port;
  try {
    const body = JSON.parse(event.body || "{}");
    const raw  = (body.domain || "").trim().toLowerCase()
      .replace(/^https?:\/\//, "").replace(/\/.*$/, "");
    const parts = raw.split(":");
    domain = parts[0];
    port   = parseInt(parts[1]) || 443;
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
        issueDetails: [{ msg: "Qoşulma uğursuz oldu: " + e.message, sev: "critical" }],
        scannedAt: new Date().toISOString(),
      }),
    };
  }
};

/* ── MAIN ── */
async function inspectTLS(domain, port = 443) {
  const start = Date.now();

  // IP resolve
  let ipAddress = "N/A";
  try { 
    const addresses = await dns.resolve4(domain);
    ipAddress = addresses[0] || "N/A"; 
  } catch (_) {}

  // Primary connection (server's preferred version)
  const primary = await doTLSConnect(domain, port);
  const handshakeMs = Date.now() - start;

  // Multi-version probe — run sequentially for stability
  const probeResults = await probeProtocols(domain, port);

  const parsed = parseCert(primary.cert, domain);
  const issues = buildIssues(parsed, primary.tlsVersion, primary.cipher,
                             primary.authorized, primary.authError, domain, probeResults);

  let score = 100;
  issues.forEach(i => {
    score -= i.sev === "critical" ? 30 : i.sev === "high" ? 15 : i.sev === "medium" ? 8 : 3;
  });
  score = Math.max(0, Math.min(100, score));

  const grade  = computeGrade(primary.tlsVersion, primary.cipher, primary.authorized, parsed, issues);
  const status = score >= 80 ? "SECURE" : score >= 50 ? "WARNING" : "DANGER";

  return {
    domain, port, ipAddress, status, score, tlsGrade: grade,
    tls: {
      version:       primary.tlsVersion,
      cipher:        primary.cipher.name || "N/A",
      cipherBits:    primary.cipher.secretKeySize || null,
      forwardSecrecy: isForwardSecure(primary.cipher.name),
    },
    key: { type: parsed.keyType, bits: parsed.keyBits },
    san: parsed.san,
    hostnameOk: primary.authorized && !primary.authError,
    chain: parsed.chain,
    revocation: {
      ocspUrl: parsed.ocsp.join(", ") || "N/A",
      crlUrl:  parsed.crl.join(", ")  || "N/A",
    },
    transparency: { hasSCT: parsed.hasSCT },
    handshakeMs,
    protocolSupport: probeResults,
    issueDetails: issues,
    issues:   issues.filter(i => ["critical","high"].includes(i.sev)),
    warnings: issues.filter(i => ["medium","low"].includes(i.sev)),
    certificate: {
      subject:           parsed.subject,
      issuer:            parsed.issuer,
      isSelfSigned:      parsed.isSelfSigned,
      sigAlg:            parsed.sigAlg,
      fingerprintSHA256: parsed.fingerprintSHA256,
      fingerprintSHA1:   parsed.fingerprintSHA1,
      serialNumber:      parsed.serialNumber,
      validFrom:         parsed.validFrom,
      validUntil:        parsed.validUntil,
      daysRemaining:     parsed.daysRemaining,
      lifespanDays:      parsed.lifespanDays,
    },
    scannedAt: new Date().toISOString(),
  };
}

/* ── MULTI-PROTOCOL PROBE ── */
// Ardıcıl yoxlama + retry mexanizmi
async function probeProtocols(domain, port) {
  const versions = [
    { label: "TLSv1.3", min: "TLSv1.3", max: "TLSv1.3" },
    { label: "TLSv1.2", min: "TLSv1.2", max: "TLSv1.2" },
    { label: "TLSv1.1", min: "TLSv1.1", max: "TLSv1.1" },
    { label: "TLSv1.0", min: "TLSv1",   max: "TLSv1" },
  ];

  const results = {};
  
  for (const v of versions) {
    try {
      let r = await tryConnect(domain, port, v.min, v.max, 5000);
      results[v.label] = {
        supported: true,
        negotiated: r.tlsVersion,
        cipher: r.cipher.name || "N/A",
        cipherBits: r.cipher.secretKeySize || null,
        forwardSecrecy: isForwardSecure(r.cipher.name),
        error: null
      };
    } catch (e) {
      // Bir cəhd daha (retry)
      try {
        await new Promise(r => setTimeout(r, 100));
        let r = await tryConnect(domain, port, v.min, v.max, 6000);
        results[v.label] = {
          supported: true,
          negotiated: r.tlsVersion,
          cipher: r.cipher.name || "N/A",
          cipherBits: r.cipher.secretKeySize || null,
          forwardSecrecy: isForwardSecure(r.cipher.name),
          error: null
        };
      } catch (e2) {
        const errMsg = e2.message || "";
        const isExplicitlyDisabled = 
          errMsg.includes("no protocols available") ||
          errMsg.includes("wrong version number") ||
          errMsg.includes("protocol version") ||
          errMsg.includes("handshake failure");
        
        results[v.label] = {
          supported: false,
          negotiated: null,
          cipher: null,
          cipherBits: null,
          forwardSecrecy: false,
          error: isExplicitlyDisabled ? "Rədd edildi (dəstəklənmir)" : "Qoşulma uğursuz oldu"
        };
      }
    }
  }
  
  return results;
}

function tryConnect(domain, port, minVersion, maxVersion, timeoutMs) {
  return new Promise((resolve, reject) => {
    const opts = {
      host: domain,
      port: port,
      servername: domain,
      rejectUnauthorized: false,
      requestCert: true,
      checkServerIdentity: () => undefined,
    };
    
    if (minVersion) opts.minVersion = minVersion;
    if (maxVersion) opts.maxVersion = maxVersion;

    const socket = tls.connect(opts, () => {
      const tlsVersion = socket.getProtocol();
      const cipher = socket.getCipher() || {};
      socket.end();
      resolve({ tlsVersion, cipher });
    });

    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      reject(new Error("Timeout"));
    });

    socket.on("error", (err) => {
      reject(err);
    });
  });
}

/* ── TLS CONNECT (server chooses version) ── */
function doTLSConnect(domain, port) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: domain, 
      port: port, 
      servername: domain,
      rejectUnauthorized: false,
      requestCert: true, 
      timeout: 15000,
      checkServerIdentity: () => undefined,
    }, () => {
      const cert = socket.getPeerCertificate(true);
      const tlsVersion = socket.getProtocol() || "N/A";
      const cipher = socket.getCipher() || {};
      const authorized = socket.authorized;
      const authError = socket.authorizationError || null;
      socket.end();
      resolve({ cert, tlsVersion, cipher, authorized, authError });
    });
    
    socket.setTimeout(15000, () => { 
      socket.destroy(); 
      reject(new Error("Connection timeout")); 
    });
    
    socket.on("error", err => reject(new Error("TLS error: " + err.message)));
  });
}

/* ── CERT PARSE ── */
function parseCert(cert, domain) {
  if (!cert || !cert.subject) return emptyParsed();

  const subject = dnToString(cert.subject);
  const issuer = dnToString(cert.issuer);
  const isSelfSigned = subject === issuer ||
    (cert.issuerCertificate && cert.issuerCertificate === cert);

  const validFrom = cert.valid_from ? new Date(cert.valid_from).toISOString() : null;
  const validUntil = cert.valid_to ? new Date(cert.valid_to).toISOString() : null;
  const daysRemaining = validUntil
    ? Math.round((new Date(validUntil) - Date.now()) / 86400000) : null;
  const lifespanDays = (validFrom && validUntil)
    ? Math.round((new Date(validUntil) - new Date(validFrom)) / 86400000) : null;

  let keyType = "RSA", keyBits = cert.bits || 0;
  if (cert.pubkey && cert.pubkey.type === 6) keyType = "EC";

  const san = [];
  if (cert.subjectaltname) {
    cert.subjectaltname.split(", ").forEach(s => {
      if (s.startsWith("DNS:")) san.push(s.slice(4));
      else if (s.startsWith("IP:")) san.push(s.slice(3));
    });
  }

  const fingerprintSHA256 = cert.fingerprint256 || "N/A";
  const fingerprintSHA1 = cert.fingerprint || "N/A";
  const serialNumber = cert.serialNumber || "N/A";
  const sigAlg = cert.sigalg || "N/A";

  const ocsp = [], crl = [];
  if (cert.infoAccess) {
    const ia = cert.infoAccess;
    const arr = v => Array.isArray(v) ? v : [v];
    if (ia["OCSP - URI"]) arr(ia["OCSP - URI"]).forEach(u => ocsp.push(u));
    if (ia["CA Issuers - URI"]) arr(ia["CA Issuers - URI"]).forEach(u => crl.push(u));
  }

  const hasSCT = !!(cert.ext_key_usage || sigAlg.toLowerCase().includes("sha256")) && !isSelfSigned;

  const chain = [];
  let cur = cert.issuerCertificate;
  const seen = new Set();
  while (cur && cur !== cert && !seen.has(cur.fingerprint)) {
    seen.add(cur.fingerprint);
    chain.push({
      subject: dnToString(cur.subject),
      issuer: dnToString(cur.issuer),
      validFrom: cur.valid_from ? new Date(cur.valid_from).toISOString() : null,
      validUntil: cur.valid_to ? new Date(cur.valid_to).toISOString() : null,
    });
    cur = cur.issuerCertificate;
  }

  return {
    subject, issuer, isSelfSigned,
    validFrom, validUntil, daysRemaining, lifespanDays,
    keyType, keyBits, san,
    fingerprintSHA256, fingerprintSHA1, serialNumber, sigAlg,
    ocsp, crl, hasSCT, chain,
  };
}

function dnToString(dn) {
  if (!dn) return "N/A";
  if (typeof dn === "string") return dn;
  return Object.entries(dn).map(([k, v]) => `${k}=${Array.isArray(v) ? v.join(",") : v}`).join(", ");
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

function isForwardSecure(name) {
  if (!name) return false;
  const n = name.toUpperCase();
  return n.includes("ECDHE") || n.includes("DHE") ||
    n.includes("TLS_AES") || n.includes("TLS_CHACHA");
}

/* ── ISSUES ── */
function buildIssues(parsed, tlsVersion, cipher, authorized, authError, domain, probes) {
  const issues = [];
  const days = parsed.daysRemaining;

  if (days !== null && days < 0)
    issues.push({ msg: "Sertifikatın müddəti bitib", sev: "critical" });
  else if (days !== null && days < 14)
    issues.push({ msg: `Sertifikat ${days} gün sonra bitəcək — TƏCİLİ yeniləyin`, sev: "critical" });
  else if (days !== null && days < 30)
    issues.push({ msg: `Sertifikat ${days} gün sonra bitəcək`, sev: "high" });

  if (parsed.isSelfSigned)
    issues.push({ msg: "Özü-özünə imzalanmış sertifikat (self-signed)", sev: "critical" });

  if (!authorized && authError && !parsed.isSelfSigned)
    issues.push({ msg: `Sertifikat doğrulanmadı: ${authError}`, sev: "critical" });

  if (["TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"].includes(tlsVersion))
    issues.push({ msg: `Köhnəlmiş TLS versiyası: ${tlsVersion} (RFC 8996 ilə ləğv edilib)`, sev: "critical" });

  if (probes) {
    if (probes["TLSv1.0"]?.supported)
      issues.push({ msg: "Server TLS 1.0 dəstəkləyir — BEAST hücumu riski (RFC 8996)", sev: "high" });
    if (probes["TLSv1.1"]?.supported)
      issues.push({ msg: "Server TLS 1.1 dəstəkləyir — RFC 8996 ilə ləğv edilib", sev: "high" });
  }

  if (!isForwardSecure(cipher.name))
    issues.push({ msg: "Perfect Forward Secrecy (PFS) aktiv deyil", sev: "high" });

  const cn = (cipher.name || "").toUpperCase();
  if (cn.includes("RC4")) issues.push({ msg: "RC4 şifirləməsi — tamamilə sındırılıb (RFC 7465)", sev: "critical" });
  if (cn.includes("NULL")) issues.push({ msg: "NULL şifirləmə — heç bir şifrələmə yoxdur", sev: "critical" });
  if (cn.includes("EXPORT")) issues.push({ msg: "EXPORT cipher — qəsdən zəiflədilmiş (FREAK hücumu)", sev: "critical" });
  if (cn.includes("DES") && !cn.includes("3DES"))
    issues.push({ msg: "DES şifirləmə — 56-bit, sındırılıb", sev: "critical" });

  if (parsed.keyType === "RSA" && parsed.keyBits > 0 && parsed.keyBits < 2048)
    issues.push({ msg: `Zəif RSA açarı: ${parsed.keyBits} bit (minimum 2048 tələb olunur)`, sev: "critical" });

  if (parsed.lifespanDays && parsed.lifespanDays > 398)
    issues.push({ msg: `Sertifikat ömrü ${parsed.lifespanDays} gün — tövsiyə olunan: ≤398 gün`, sev: "medium" });

  const sigA = (parsed.sigAlg || "").toLowerCase();
  if (sigA.includes("sha1")) issues.push({ msg: "SHA-1 imza alqoritmi — köhnəlmiş (SHAttered hücumu)", sev: "high" });
  if (sigA.includes("md5")) issues.push({ msg: "MD5 imza alqoritmi — tamamilə sındırılıb", sev: "critical" });

  if (!parsed.hasSCT && !parsed.isSelfSigned)
    issues.push({ msg: "Certificate Transparency (SCT) aşkar edilmədi", sev: "medium" });

  if (parsed.san.length === 0 && !parsed.isSelfSigned)
    issues.push({ msg: "Subject Alternative Names (SAN) yoxdur — köhnə format", sev: "medium" });

  if (parsed.ocsp.length === 0 && !parsed.isSelfSigned)
    issues.push({ msg: "OCSP URL yoxdur — ləğvetmə yoxlaması mümkün deyil", sev: "low" });

  return issues;
}

/* ── GRADE ── */
function computeGrade(tlsVersion, cipher, authorized, parsed, issues) {
  if (!authorized || parsed.isSelfSigned) return "T";

  const criticals = issues.filter(i => i.sev === "critical");
  const ver = tlsVersion || "";
  const cn = (cipher.name || "").toUpperCase();

  if (ver.match(/^(TLSv1$|TLSv1\.0|TLSv1\.1|SSLv)/)) return "F";
  if (cn.includes("RC4") || cn.includes("NULL") || cn.includes("EXPORT")) return "F";

  if (criticals.length > 0) return "C";

  if (ver === "TLSv1.3") {
    const highs = issues.filter(i => i.sev === "high");
    return highs.length === 0 ? "A+" : "A";
  }

  if (ver === "TLSv1.2") {
    const hasECDHE = cn.includes("ECDHE");
    const hasDHE = cn.includes("DHE");
    const hasAEAD = cn.includes("GCM") || cn.includes("CHACHA") || cn.includes("POLY1305");
    const highs = issues.filter(i => i.sev === "high");

    if (hasECDHE && hasAEAD && highs.length === 0) return "A";
    if (hasECDHE && hasAEAD) return "A-";
    if (hasECDHE && !hasAEAD) return "B+";
    if (hasDHE) return "B";
    return "B-";
  }

  return "C";
}

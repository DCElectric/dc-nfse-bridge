// Ponte NFS-e Nacional da DC ELECTRIC: assina a DPS com o certificado A1 e envia ao SEFIN via mTLS.
// Variáveis: BRIDGE_TOKEN, PFX_BASE64, PFX_PASSWORD, PORT (opcional).
import http from "node:http";
import https from "node:https";
import zlib from "node:zlib";
import forge from "node-forge";
import { SignedXml } from "xml-crypto";

const { BRIDGE_TOKEN, PFX_BASE64, PFX_PASSWORD } = process.env;
if (!BRIDGE_TOKEN || !PFX_BASE64 || !PFX_PASSWORD) { console.error("Faltam BRIDGE_TOKEN, PFX_BASE64 ou PFX_PASSWORD"); process.exit(1); }
const pfx = Buffer.from(PFX_BASE64, "base64");

const p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(forge.util.createBuffer(pfx.toString("binary"))), PFX_PASSWORD);
const key = (p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag] ?? [])[0]?.key;
const cert = (p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] ?? [])[0]?.cert;
const keyPem = forge.pki.privateKeyToPem(key);
const certB64 = forge.util.encode64(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes());
// Certificados A1 antigos usam criptografia que o Node 17+ recusa no formato PFX; por isso o agente usa chave e certificados em PEM.
const certPems = (p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] ?? []).map((b) => forge.pki.certificateToPem(b.cert));
const agent = new https.Agent({ key: keyPem, cert: certPems.join("\n"), keepAlive: true });

const HOSTS = { producao: "sefin.nfse.gov.br", homologacao: "sefin.producaorestrita.nfse.gov.br" };

function sign(xml) {
  const sig = new SignedXml({ privateKey: keyPem, publicCert: certB64, signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1", canonicalizationAlgorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" });
  sig.addReference({ xpath: "//*[local-name(.)='infDPS']", transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"], digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1" });
  sig.getKeyInfoContent = () => `<X509Data><X509Certificate>${certB64}</X509Certificate></X509Data>`;
  sig.computeSignature(xml, { location: { reference: "//*[local-name(.)='infDPS']", action: "after" } });
  return sig.getSignedXml();
}

function sefin(env, path, method, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : undefined;
    const req = https.request({ host: HOSTS[env], path, method, agent, headers: { "Content-Type": "application/json", ...(data ? { "Content-Length": Buffer.byteLength(data) } : {}) }, timeout: 60000 }, (res) => {
      let out = ""; res.on("data", (c) => (out += c)); res.on("end", () => { let json; try { json = JSON.parse(out); } catch { json = { raw: out.slice(0, 2000) }; } resolve({ status: res.statusCode, json }); });
    });
    req.on("error", reject); req.on("timeout", () => req.destroy(new Error("timeout")));
    if (data) req.write(data); req.end();
  });
}

const send = (res, code, obj) => { res.writeHead(code, { "Content-Type": "application/json" }); res.end(JSON.stringify(obj)); };

http.createServer(async (req, res) => {
  if ((req.headers.authorization ?? "") !== `Bearer ${BRIDGE_TOKEN}`) return send(res, 401, { error: "unauthorized" });
  if (req.method === "GET" && req.url === "/health") return send(res, 200, { ok: true, subject: cert.subject.getField("CN")?.value, validTo: cert.validity.notAfter });
  if (req.method !== "POST" || req.url !== "/nfse") return send(res, 404, { error: "not_found" });
  let raw = ""; for await (const c of req) { raw += c; if (raw.length > 2_000_000) return send(res, 413, { error: "too_large" }); }
  try {
    const { environment, dpsXml } = JSON.parse(raw);
    if (!HOSTS[environment] || typeof dpsXml !== "string") return send(res, 400, { error: "invalid_input" });
    const signed = sign(dpsXml);
    const r = await sefin(environment, "/SefinNacional/nfse", "POST", { dpsXmlGZipB64: zlib.gzipSync(signed).toString("base64") });
    const nfseXml = r.json?.nfseXmlGZipB64 ? zlib.gunzipSync(Buffer.from(r.json.nfseXmlGZipB64, "base64")).toString("utf8") : null;
    const nNFSe = nfseXml?.match(/<nNFSe>(\d+)<\/nNFSe>/)?.[1] ?? null;
    send(res, r.status >= 200 && r.status < 300 ? 200 : 422, { ok: r.status < 300, status: r.status, chaveAcesso: r.json?.chaveAcesso ?? null, nNFSe, nfseXml, erros: r.json?.erros ?? r.json?.erro ?? (r.status >= 300 ? r.json : null) });
  } catch (e) { console.error("falha", e?.message); send(res, 500, { error: "bridge_failure", message: String(e?.message ?? e).slice(0, 300) }); }
}).listen(Number(process.env.PORT ?? 8787), () => console.log("Ponte NFS-e ativa"));

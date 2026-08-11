import { connect as cfConnect } from "cloudflare:sockets";
const 玉衡令 = "88888888-8888-8888-8888-888888888888";  //揉揉ID，改成你自己的
const 默认备用小可爱地址 = "usip.vpndns.net";  //兜底落地地址，改成你自己的
const txt缓存生存期ms = 300 * 1000;
const txt失败缓存生存期ms = 10 * 1000;
const 书解 = new TextDecoder();
const enc = new TextEncoder();
const txt缓存池 = new Map();
const txt请求池 = new Map();

function parseProxyip(v) {
  if (!v) return null;
  const m = v.match(/^([a-zA-Z0-9.-]+)(?::(\d{1,5}))?$/);
  if (!m) return null;
  const p = m[2] ? Number(m[2]) : 443;
  return p > 0 && p < 65536 ? { hostname: m[1], port: p } : null;
}
function 校验候选地址(s) {
  if (!s || s.length > 253 || s === '.' || s === '[]' || s === '..' || s.startsWith('./') || s.startsWith('../') || s.startsWith(':') || !/^[a-zA-Z0-9._\-:[\]]+$/.test(s)) return 默认备用小可爱地址;
  return s;
}
async function 获取客户端代理地址(i) {
  i = i.trim();
  if (!i.includes("://") && !i.includes("/")) return 校验候选地址(i);
  const u = i.startsWith("http://") || i.startsWith("https://") ? i : `https://${i}`;
  const n = Date.now(), c = txt缓存池.get(u);
  if (c && n < c.expireAt) return c.value;
  let p = txt请求池.get(u);
  if (!p) {
    p = (async () => {
      try {
        const r = await fetch(u, { headers: { "User-Agent": "Mozilla/5.0" }, cf: { cacheEverything: true, cacheTtl: 60 } });
        if (r.ok) {
          const t = await r.text();
          const v = 校验候选地址(t.replace(/[\r\n\s\uFEFF]/g, ""));
          if (v !== 默认备用小可爱地址) { txt缓存池.set(u, { value: v, expireAt: Date.now() + txt缓存生存期ms }); return v; }
        }
      } catch (_) {}
      txt缓存池.set(u, { value: 默认备用小可爱地址, expireAt: Date.now() + txt失败缓存生存期ms });
      return 默认备用小可爱地址;
    })();
    txt请求池.set(u, p);
    p.finally(() => txt请求池.delete(u));
  }
  return p;
}
function 提取ProxyIP(r) {
  const s = r.indexOf('/', 10);
  if (s === -1) return "";
  let c = r.slice(s + 1);
  if (!c) return "";
  let l = c.length;
  if (l > 0) { const k = c.charCodeAt(l - 1); if (k === 47 || k === 61) c = c.slice(0, l - 1); }
  const m = c.match(/(ip|txtip|p|proxy|proxyip)(?:=|%3D|:\/\/|%3A%2F%2F)([^&\s?#]+)/i);
  if (m && m[2]) {
    let v = m[2];
    if (v.charCodeAt(v.length - 1) === 61) v = v.slice(0, -1);
    try { return decodeURIComponent(v).trim(); } catch (_) { return v.trim(); }
  }
  return "";
}
async function connectOnce(h, p) { const s = cfConnect({ hostname: h, port: p }); await s.opened; return s; }
async function connectToTarget(a, p, c, f) {
  try { return await connectOnce(a, p); } catch (_) {}
  if (c) { try { return await connectOnce(c.hostname, c.port); } catch (_) {} }
  if (f && f !== c) { try { return await connectOnce(f.hostname, f.port); } catch (_) {} }
  return null;
}

const MAGIC = new Uint8Array([0x21, 0x12, 0xA4, 0x42]);
const MT = { AQ:0x003,RQ:0x004,AO:0x103,AE:0x113,PQ:0x008,PO:0x108,CQ:0x00A,CO:0x10A,BQ:0x00B,BO:0x10B,SI:0x016,DI:0x017 };
const AT = { USER:0x006,MI:0x008,ERR:0x009,PEER:0x012,DATA:0x013,REALM:0x014,NONCE:0x015,TRANSPORT:0x019,CONNID:0x02A };
const u16 = (b, o = 0) => (b[o] << 8) | b[o + 1], pad4 = n => -n & 3;
const cat = (...a) => { const r = new Uint8Array(a.reduce((s, x) => s + x.length, 0)); a.reduce((o, x) => (r.set(x, o), o + x.length), 0); return r; };
const safeClose = (...a) => a.forEach(x => { try { x?.close?.(); } catch {} });
const tid = () => crypto.getRandomValues(new Uint8Array(12));
const stunAttr = (t, v) => { const b = new Uint8Array(4 + v.length + pad4(v.length)), d = new DataView(b.buffer); d.setUint16(0, t); d.setUint16(2, v.length); b.set(v, 4); return b; };
const stunMsg = (t, id, a) => { const bd = cat(...a), h = new Uint8Array(20), d = new DataView(h.buffer); d.setUint16(0, t); d.setUint16(2, bd.length); h.set(MAGIC, 4); h.set(id, 8); return cat(h, bd); };
const expandIPv6 = ip => { ip = ip.replace(/^\[|\]$/g, '').split('%')[0]; if (!ip.includes('::')) return ip.split(':').map(g => g || '0'); const [l, r] = ip.split('::'); const L = l ? l.split(':') : [], R = r ? r.split(':') : []; const m = Math.max(0, 8 - L.length - R.length); return [...L, ...Array(m).fill('0'), ...R]; };
const xorPeer = (ip, port) => { const v6 = ip.includes(':'), b = new Uint8Array(v6 ? 20 : 8); b[1] = v6 ? 2 : 1; new DataView(b.buffer).setUint16(2, port ^ 0x2112); if (v6) { const x = new Uint8Array(16); x.set(MAGIC); expandIPv6(ip).forEach((g, i) => { const v = parseInt(g || '0', 16); b[4 + i * 2] = ((v >> 8) ^ x[i * 2]) & 0xff; b[5 + i * 2] = (v & 0xff) ^ x[i * 2 + 1]; }); } else { ip.split('.').forEach((v, i) => b[4 + i] = +v ^ MAGIC[i]); } return b; };
const parseStun = d => { if (d.length < 20 || MAGIC.some((v, i) => d[4 + i] !== v)) return null; const dv = new DataView(d.buffer, d.byteOffset, d.byteLength), ml = dv.getUint16(2), a = {}; for (let o = 20; o + 4 <= 20 + ml;) { const t = dv.getUint16(o), l = dv.getUint16(o + 2); if (o + 4 + l > d.length) break; a[t] = d.slice(o + 4, o + 4 + l); o += 4 + l + pad4(l); } return { type: dv.getUint16(0), attrs: a }; };
const parseErr = d => d?.length >= 4 ? (d[2] & 7) * 100 + d[3] : 0;
const parseXorPeer = d => { if (!d?.length || d.length < 8) return ['', 0]; const p = u16(d, 2) ^ 0x2112; if (d[1] === 2 && d.length >= 20) { const x = new Uint8Array(16); x.set(MAGIC); return [Array.from({ length: 8 }, (_, i) => ((d[4 + i * 2] ^ x[i * 2]) << 8 | (d[5 + i * 2] ^ x[i * 2 + 1])).toString(16)).join(':'), p]; } return [MAGIC.map((m, i) => d[4 + i] ^ m).join('.'), p]; };
const addIntegrity = async (m, k) => { const c = new Uint8Array(m), d = new DataView(c.buffer); d.setUint16(2, d.getUint16(2) + 24); const K = await crypto.subtle.importKey('raw', k, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']); return cat(c, stunAttr(AT.MI, new Uint8Array(await crypto.subtle.sign('HMAC', K, c)))); };
const readStun = async (r, b) => { let B = b ?? new Uint8Array(0); const p = async () => { const { done, value } = await r.read(); if (done) throw 0; if (value == null) return; B = cat(B, new Uint8Array(value)); }; try { while (B.length < 20) await p(); const n = 20 + u16(B, 2); while (B.length < n) await p(); return [parseStun(B.subarray(0, n)), B.length > n ? B.subarray(n) : null]; } catch { return [null, null]; } };
const _dnsCache = new Map();
const resolveIP = async h => { if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) return h; if (h.includes(':')) return h.replace(/^\[|\]$/g, ''); const n = Date.now(), c = _dnsCache.get(h); if (c && n < c.exp) return c.ip; const d = t => fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(h)}&type=${t}`, { headers: { Accept: 'application/dns-json' } }).then(r => r.json()).catch(() => ({})); const [ra, r6] = await Promise.all([d('A'), d('AAAA')]); const ip = ra.Answer?.find(r => r.type === 1)?.data ?? r6.Answer?.find(r => r.type === 28)?.data ?? null; if (ip) { const t = Math.min(300, Math.max(10, ra.Answer?.find(r => r.type === 1)?.TTL ?? r6.Answer?.find(r => r.type === 28)?.TTL ?? 30)); _dnsCache.set(h, { ip, exp: Date.now() + t * 1e3 }); } return ip; };
const md5 = async s => new Uint8Array(await crypto.subtle.digest('MD5', enc.encode(s)));
const getTurn = u => { let U; try { U = decodeURIComponent(u); } catch { return null; } const m = U.match(/\/turn:\/\/([^?\s]*)/i); if (!m) return null; const t = m[1], at = t.lastIndexOf('@'), cr = at >= 0 ? t.slice(0, at) : '', hp = t.slice(at + 1); let h, p; if (hp.startsWith('[')) { const e = hp.indexOf(']'); if (e === -1) return null; h = hp.slice(0, e + 1); p = hp.slice(e + 2); } else { const c = hp.lastIndexOf(':'); h = c >= 0 ? hp.slice(0, c) : hp; p = c >= 0 ? hp.slice(c + 1) : ''; } const P = +p; if (!P || P < 1 || P > 65535) return null; const ci = cr.indexOf(':'); return { host: h, port: P, user: ci >= 0 ? cr.slice(0, ci) : '', pass: ci >= 0 ? cr.slice(ci + 1) : '' }; };
const turnAuth = async (w, r, t, { user, pass }, pl) => { const tp = new Uint8Array([t, 0, 0, 0]); await w.write(stunMsg(MT.AQ, tid(), [stunAttr(AT.TRANSPORT, tp)])); let [m, e] = await readStun(r); if (!m) return null; let k = null, aa = []; const s = x => k ? addIntegrity(x, k) : Promise.resolve(x); if (m.type === MT.AE && user && parseErr(m.attrs[AT.ERR]) === 401) { const rm = 书解.decode(m.attrs[AT.REALM] ?? new Uint8Array(0)), nc = m.attrs[AT.NONCE] ?? new Uint8Array(0); k = await md5(`${user}:${rm}:${pass}`); aa = [stunAttr(AT.USER, enc.encode(user)), stunAttr(AT.REALM, enc.encode(rm)), stunAttr(AT.NONCE, nc)]; const aq = await addIntegrity(stunMsg(MT.AQ, tid(), [stunAttr(AT.TRANSPORT, tp), ...aa]), k); const ex = pl ? await Promise.all(pl(aa, s)) : []; await w.write(ex.length ? cat(aq, ...ex) : aq); [m, e] = await readStun(r, e); if (!m) return null; } else if (pl && m.type === MT.AO) { const ex = await Promise.all(pl(aa, s)); if (ex.length) await w.write(cat(...ex)); } return m.type === MT.AO ? { key: k, aa, ex: e, sign: s } : null; };
const sprout = (h, p) => { const s = cfConnect({ hostname: h, port: p }); return s.opened.then(() => s); };
const turnConn = async (turn, tIp, tP) => { let ctrl = null, data = null; const cl = () => safeClose(ctrl, data); try { ctrl = await sprout(turn.host, turn.port); const cw = ctrl.writable.getWriter(), cr = ctrl.readable.getReader(), peer = stunAttr(AT.PEER, xorPeer(tIp, tP)), auth = await turnAuth(cw, cr, 6, turn, (aa, s) => [s(stunMsg(MT.PQ, tid(), [peer, ...aa])), s(stunMsg(MT.CQ, tid(), [peer, ...aa]))]); if (!auth) { try { cw.releaseLock(); } catch {} try { cr.releaseLock(); } catch {} cl(); return null; } const dS = cfConnect({ hostname: turn.host, port: turn.port }), { aa, sign } = auth; let ex = auth.ex, r; [r, ex] = await readStun(cr, ex); if (r?.type !== MT.PO) { try{cr.releaseLock();}catch{} try{cw.releaseLock();}catch{} cl(); return null; } [r, ex] = await readStun(cr, ex); if (r?.type !== MT.CO || !r.attrs[AT.CONNID]) { try{cr.releaseLock();}catch{} try{cw.releaseLock();}catch{} cl(); return null; } try { await dS.opened; } catch (E) { safeClose(dS); try{cr.releaseLock();}catch{} try{cw.releaseLock();}catch{} cl(); return null; } data = dS; const dw = data.writable.getWriter(), dr = data.readable.getReader(); await dw.write(await sign(stunMsg(MT.BQ, tid(), [stunAttr(AT.CONNID, r.attrs[AT.CONNID]), ...aa]))); let ex2; [r, ex2] = await readStun(dr); if (r?.type !== MT.BO) { try{dw.releaseLock();}catch{} try{dr.releaseLock();}catch{} try{cr.releaseLock();}catch{} try{cw.releaseLock();}catch{} cl(); return null; } cr.releaseLock(); cw.releaseLock(); dw.releaseLock(); let kad = false; const oc = cl, ca = () => { kad = true; try { ctrlW.releaseLock(); } catch {} oc(); }, ctrlW = ctrl.writable.getWriter(); (async () => { try { const rd = ctrl.readable.getReader(); while (!(await rd.read()).done); } catch {} })(); (async () => { try { for (;;) { await new Promise(r => setTimeout(r, 27e4)); if (kad) break; await ctrlW.write(cat(await sign(stunMsg(MT.RQ, tid(), aa)), await sign(stunMsg(MT.PQ, tid(), [peer, ...aa])))); } } catch {} })(); const rd = new ReadableStream({ type: 'bytes', start(c) { if (ex2?.length) c.enqueue(ex2.slice()); }, async pull(c) { const bv = c.byobRequest?.view; if (bv) { const { done, value } = await dr.read(); if (done) { c.close(); c.byobRequest.respond(0); return; } const v = new Uint8Array(value), n = Math.min(v.byteLength, bv.byteLength); new Uint8Array(bv.buffer, bv.byteOffset, n).set(v.subarray(0, n)); c.byobRequest.respond(n); if (n < v.byteLength) c.enqueue(v.subarray(n).slice()); } else { const { done, value } = await dr.read(); if (done) { c.close(); return; } c.enqueue(new Uint8Array(value)); } }, cancel() { dr.cancel(); } }); return { readable: rd, writable: data.writable, close: ca }; } catch { cl(); return null; } };
const encodeAddr = h => { const s = h.replace(/^\[|\]$/g, ''), m = s.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/); if (m) return new Uint8Array([0x01, ...m.slice(1).map(Number)]); if (s.includes(':')) { const b = new Uint8Array(17); b[0] = 0x03; expandIPv6(s).forEach((x, i) => { const v = parseInt(x || '0', 16); b[1 + i * 2] = v >> 8; b[2 + i * 2] = v & 0xff; }); return b; } const e = enc.encode(h); return cat(new Uint8Array([0x02, e.length]), e); };
const xudpAddr = d => { if (!d.length) return ['', 0]; if (d[0] <= 1) return d.length >= 5 ? [d.subarray(1, 5).join('.'), 5] : ['', 0]; if (d[0] === 2) return d.length >= 2 + d[1] ? [书解.decode(d.subarray(2, 2 + d[1])), 2 + d[1]] : ['', 0]; return d[0] === 3 && d.length >= 17 ? [`[${Array.from({ length: 8 }, (_, i) => u16(d, 1 + i * 2).toString(16)).join(':')}]`, 17] : ['', 0]; };
const fakeIPType = h => { const m = h.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/); return m && +m[1] === 198 && [18, 19].includes(+m[2]) ? 4 : h.replace(/^\[|\]$/g, '').startsWith('fc') && h.includes(':') ? 6 : 0; };
const parseXUDP = d => { if (d.length < 6) return null; const ml = u16(d), me = 2 + ml; if (ml < 4 || me > d.length) return null; const f = { network: me > 6 ? d[6] : 0, port: me >= 9 ? u16(d, 7) : 0, host: me > 9 ? xudpAddr(d.subarray(9, me))[0] : '', payload: null, totalLen: me }; if ((d[5] & 1) && me + 2 <= d.length) { const pL = u16(d, me); if (me + 2 + pL <= d.length) { f.payload = d.subarray(me + 2, me + 2 + pL); f.totalLen = me + 2 + pL; } } return f; };
const xudpResp = (h, p, pL) => { const a = encodeAddr(h), ml = 7 + a.length, b = new Uint8Array(2 + ml + 2 + pL.length); [b[0], b[1], b[4], b[5], b[6], b[7], b[8]] = [ml >> 8, ml & 0xff, 2, 1, 2, p >> 8, p & 0xff]; b.set(a, 9); const o = 2 + ml; [b[o], b[o + 1]] = [pL.length >> 8, pL.length & 0xff]; b.set(pL, o + 2); return b; };
const turnUDP = async (turn, sw) => { let s = null, c = false; const ps = new Set(), ss = new Map(), rv = {}; let _w = null; const cl = () => { c = true; try { _w?.releaseLock(); } catch {} safeClose(s); }; try { s = await sprout(turn.host, turn.port); const w = (_w = s.writable.getWriter()), r = s.readable.getReader(), auth = await turnAuth(w, r, 17, turn); if (!auth) { try{w.releaseLock();}catch{} try{r.releaseLock();}catch{} _w=null; cl(); return null; } const { aa, sign } = auth; let b = auth.ex; (async () => { try { while (!c) { const [m, n] = await readStun(r, b); b = n; if (!m) break; if (m.type === MT.DI && m.attrs[AT.PEER] && m.attrs[AT.DATA]) { const [ip, pt] = parseXorPeer(m.attrs[AT.PEER]), S = rv[`${ip}:${pt}`]; sw(xudpResp(S?.host ?? ip, S?.port ?? pt, m.attrs[AT.DATA])); } } } finally { try { r.releaseLock(); } catch {} } })(); let wC = Promise.resolve(); const cw = m => { if (c) return; wC = wC.then(() => { if (c) return; return w.write(m).catch(() => {}); }); }; (async () => { try { while (!c) { await new Promise(r => setTimeout(r, 24e4)); if (c) break; cw(await sign(stunMsg(MT.RQ, tid(), aa))); for (const ip of ps) cw(await sign(stunMsg(MT.PQ, tid(), [stunAttr(AT.PEER, xorPeer(ip, 0)), ...aa]))); } } catch {} })(); const ep = ip => { if (ps.has(ip)) return; ps.add(ip); sign(stunMsg(MT.PQ, tid(), [stunAttr(AT.PEER, xorPeer(ip, 0)), ...aa])).then(cw); }, sU = (ip, p, d) => cw(stunMsg(MT.SI, tid(), [stunAttr(AT.PEER, xorPeer(ip, p)), stunAttr(AT.DATA, d)])), gI = (h, p) => { const k = `${h}:${p}`, c = ss.get(k); if (c) return c.ip; const ft = fakeIPType(h); if (ft) for (const s of ss.values()) if (s.port === p && s.isV6 === (ft === 6)) { const ns = { ip: s.ip, host: h, port: p, isV6: s.isV6 }; ss.set(k, ns); rv[`${s.ip}:${p}`] = ns; return s.ip; } return null; }, rA = async (h, p, k) => { const ip = await resolveIP(h); if (ip) { const s = { ip, host: h, port: p, isV6: ip.includes(':') }; ss.set(k, s); rv[`${ip}:${p}`] = s; } }, pX = d => { while (d.length >= 6) { const f = parseXUDP(d); if (!f) break; if (f.network === 2 && f.payload?.length && f.host) { const k = `${f.host}:${f.port}`, ip = gI(f.host, f.port); ip ? (ep(ip), sU(ip, f.port, f.payload)) : ss.has(k) || rA(f.host, f.port, k); } d = d.subarray(f.totalLen); } }; return { processXUDP: pX, close: cl }; } catch { cl(); return null; } };

const 玉衡印 = (() => { const b = new Uint8Array(16), h = 玉衡令.replace(/-/g, ""); for (let i = 0; i < 16; i++) b[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16); return b; })();
const ipv6ToString = b => { const p = []; for (let i = 0; i < 16; i += 2) p.push(((b[i] << 8) | b[i + 1]).toString(16)); return p.join(":").replace(/:(?:0:)+/, "::"); };
const parseGrainHeader = (buf, hasSSPass) => {
  if (buf.byteLength < 7) return null;
  const proto = buf[0];
  if (proto === 1 && hasSSPass) return { address: `${buf[1]}.${buf[2]}.${buf[3]}.${buf[4]}`, port: (buf[5] << 8) | buf[6], rawPayload: buf.subarray(7), isUDP: false, isVless: false };
  if (proto === 3 && hasSSPass) { const l = buf[1]; if (buf.byteLength < 4 + l) return null; return { address: 书解.decode(buf.subarray(2, 2 + l)), port: (buf[2 + l] << 8) | buf[3 + l], rawPayload: buf.subarray(4 + l), isUDP: false, isVless: false }; }
  if (proto === 4 && hasSSPass) { if (buf.byteLength < 19) return null; const g = []; for (let i = 0; i < 8; i++) g.push(((buf[1 + i * 2] << 8) | buf[2 + i * 2]).toString(16)); return { address: `[${g.join(':')}]`, port: (buf[17] << 8) | buf[18], rawPayload: buf.subarray(19), isUDP: false, isVless: false }; }
  if (buf.byteLength < 24 || proto !== 0) return null;
  const v = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let o = 1;
  for (let i = 0; i < 16; i++) if (buf[o++] !== 玉衡印[i]) return null;
  const sL = buf[o++];
  if (o + sL + 4 > buf.byteLength) return null;
  const c = buf[o + sL];
  if (c === 3) return { isUDP: true, rawPayload: buf.subarray(o + sL + 1), isVless: true };
  o += sL;
  const aT = buf[o++];
  if (aT !== 1) return null;
  const p = v.getUint16(o, false);
  o += 2;
  const k = buf[o++];
  let a;
  if (k === 1) { if (o + 4 > buf.byteLength) return null; a = `${buf[o]}.${buf[o + 1]}.${buf[o + 2]}.${buf[o + 3]}`; o += 4; }
  else if (k === 2) { if (o >= buf.byteLength) return null; const l = buf[o++]; if (o + l > buf.byteLength) return null; a = 书解.decode(buf.subarray(o, o + l)); o += l; }
  else if (k === 3) { if (o + 16 > buf.byteLength) return null; a = `[${ipv6ToString(buf.subarray(o, o + 16))}]`; o += 16; }
  else return null;
  return { address: a, port: p, rawPayload: buf.subarray(o), isUDP: false, isVless: true };
};
const bridgeTcpToWebSocket = async (r, w, sM) => { const rd = r.getReader({ mode: "byob" }); let b = new ArrayBuffer(65536); try { while (true) { const { done, value } = await rd.read(new Uint8Array(b)); if (done) break; w.send(value); if (sM) b = new ArrayBuffer(65536); else b = value.buffer; } } finally { rd.releaseLock(); } };
const handleWebSocket = async (ws, ip, req, cP, fP, hasSSPass) => {
  ws.binaryType = "arraybuffer";
  let ts = null, tw = null, est = false, wt = Promise.resolve(), cl = false, uh = null;
  const turn = getTurn(req.url), close = () => { if (cl) return; cl = true; try { uh?.close(); } catch {} try { tw?.releaseLock(); } catch {} try { ts?.close(); } catch {} try { ws.close(); } catch {} };
  const pP = async p => {
    try {
      if (uh) return uh.processXUDP(p);
      if (tw) return tw.write(p);
      const g = parseGrainHeader(p, hasSSPass);
      if (!g) return close();
      if (g.isVless) ws.send(new Uint8Array([p[0], 0]));
      if (g.isUDP && turn) { uh = await turnUDP(turn, d => { try { ws.send(d); } catch {} }); if (!uh) return close(); const ud = g.rawPayload; ud.length && uh.processXUDP(ud); return; }
      let sM = false;
      if (turn) { const ip = /^\d+\.\d+\.\d+\.\d+$/.test(g.address) ? g.address : (g.address.includes(':') ? g.address.replace(/^\[|\]$/g, '') : await resolveIP(g.address)); if (!ip) return close(); ts = await turnConn(turn, ip, g.port); }
      else { sM = g.port === 443 || (g.rawPayload.byteLength > 0 && g.rawPayload[0] === 0x16); ts = await connectToTarget(g.address, g.port, cP, fP); }
      if (!ts) return close();
      tw = ts.writable.getWriter(); est = true;
      bridgeTcpToWebSocket(ts.readable, ws, sM).finally(close);
      if (g.rawPayload.byteLength) await tw.write(g.rawPayload);
    } catch { close(); }
  };
  ws.addEventListener("message", e => { wt = wt.then(() => pP(new Uint8Array(e.data))).catch(close); });
  ws.addEventListener("close", close);
  ws.addEventListener("error", close);
  if (ip) wt = pP(ip).catch(close);
};
const decodeBase64Url = v => { const n = v.replace(/-/g, "+").replace(/_/g, "/"), r = n.length % 4, b = atob(r ? n + "=".repeat(4 - r) : n), u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; };
const handleWSLocal = async req => {
  const rP = 提取ProxyIP(req.url), rPr = rP ? await 获取客户端代理地址(rP) : "", cP = parseProxyip(rPr), fP = parseProxyip(默认备用小可爱地址), hasSSPass = decodeURIComponent(req.url).includes(玉衡令), pH = req.headers.get("sec-websocket-protocol");
  let iPL = null;
  if (pH) { try { iPL = decodeBase64Url(pH); } catch { return new Response("Bad WebSocket protocol.", { status: 400 }); } }
  const pr = new WebSocketPair(), [cW, sW] = Object.values(pr);
  sW.accept();
  handleWebSocket(sW, iPL, req, cP, fP, hasSSPass);
  return new Response(null, { status: 101, webSocket: cW, headers: pH ? { "Sec-WebSocket-Protocol": pH } : undefined });
};
const MAX_VLESS_HEADER_BYTES = 8192, EMPTY_BYTES = new Uint8Array(0), concatBytes = (l, r) => { const m = new Uint8Array(l.byteLength + r.byteLength); m.set(l); m.set(r, l.byteLength); return m; }, matchesUuid = b => { const u = 玉衡令.replace(/-/g, ""); for (let i = 0; i < 16; i++) if (b[i + 1] !== parseInt(u.slice(i * 2, i * 2 + 2), 16)) return false; return true; };
const parseVlessRequest = (b, hasSSPass) => {
  if (b.byteLength < 7) return null;
  const pr = b[0];
  if (pr === 1 && hasSSPass) return { hostname: `${b[1]}.${b[2]}.${b[3]}.${b[4]}`, port: (b[5] << 8) | b[6], dataOffset: 7, isVless: false };
  if (pr === 3 && hasSSPass) { const l = b[1]; if (b.byteLength < 4 + l) return null; return { hostname: 书解.decode(b.subarray(2, 2 + l)), port: (b[2 + l] << 8) | b[3 + l], dataOffset: 4 + l, isVless: false }; }
  if (pr === 4 && hasSSPass) { if (b.byteLength < 19) return null; const g = []; for (let i = 0; i < 8; i++) g.push(((b[1 + i * 2] << 8) | b[2 + i * 2]).toString(16)); return { hostname: g.join(':'), port: (b[17] << 8) | b[18], dataOffset: 19, isVless: false }; }
  if (b.byteLength < 18 || pr !== 0) return null;
  if (!matchesUuid(b)) throw new Error("invalid vless uuid");
  const cO = 18 + b[17];
  if (b.byteLength < cO + 4) return null;
  if (b[cO] !== 1) throw new Error("tcp only");
  const p = (b[cO + 1] << 8) | b[cO + 2];
  if (p === 0) throw new Error("invalid port");
  const aT = b[cO + 3];
  let o = cO + 4, h;
  if (aT === 1) { if (b.byteLength < o + 4) return null; h = `${b[o]}.${b[o + 1]}.${b[o + 2]}.${b[o + 3]}`; o += 4; }
  else if (aT === 2) { if (b.byteLength < o + 1) return null; const l = b[o++]; if (l === 0) throw new Error("empty domain"); if (b.byteLength < o + l) return null; h = 书解.decode(b.subarray(o, o + l)); o += l; }
  else if (aT === 3) { if (b.byteLength < o + 16) return null; const g = []; for (let i = 0; i < 8; i++) g.push(((b[o + i * 2] << 8) | b[o + i * 2 + 1]).toString(16)); h = g.join(":"); o += 16; }
  else throw new Error("invalid address type");
  return { version: b[0], hostname: h, port: p, dataOffset: o, isVless: true };
};
const readVlessHeader = async (r, hasSSPass) => {
  const rd = r.body.getReader();
  let b = EMPTY_BYTES;
  try {
    for (;;) {
      const { done, value } = await rd.read();
      if (done) throw new Error("incomplete vless header");
      const c = value instanceof Uint8Array ? value : new Uint8Array(value);
      b = b.byteLength ? concatBytes(b, c) : c.slice();
      const p = parseVlessRequest(b, hasSSPass);
      if (p) { rd.releaseLock(); return { ...p, initialPayload: b.subarray(p.dataOffset).slice() }; }
      if (b.byteLength > MAX_VLESS_HEADER_BYTES) throw new Error("vless header too large");
    }
  } catch (e) { try { await rd.cancel(e); } catch {} throw e; }
};
const handleXhttpLocal = async req => {
  if (!req.body) return new Response("Not Found", { status: 404 });
  const rP = 提取ProxyIP(req.url), rPr = rP ? await 获取客户端代理地址(rP) : "", cP = parseProxyip(rPr), fP = parseProxyip(默认备用小可爱地址), hasSSPass = decodeURIComponent(req.url).includes(玉衡令);
  let h;
  try { h = await readVlessHeader(req, hasSSPass); } catch { return new Response("bad request", { status: 400 }); }
  let s;
  try { s = await connectToTarget(h.hostname, h.port, cP, fP); } catch { try { await req.body.cancel(); } catch {} return new Response("bad gateway", { status: 502 }); }
  const ac = new AbortController(); let sC = false;
  const cl = r => { if (!ac.signal.aborted) { try { ac.abort(r); } catch {} } if (!sC) { sC = true; try { s.close(); } catch {} } };
  const uP = (async () => { const w = s.writable.getWriter(); try { if (h.initialPayload.byteLength) await w.write(h.initialPayload); } finally { w.releaseLock(); } await req.body.pipeTo(s.writable, { signal: ac.signal }); })();
  const rS = new IdentityTransformStream();
  const dP = (async () => { const w = rS.writable.getWriter(); try { if (h.isVless) await w.write(new Uint8Array([h.version, 0])); } catch (e) { try { await w.abort(e); } catch {} throw e; } finally { w.releaseLock(); } await s.readable.pipeTo(rS.writable, { signal: ac.signal }); })();
  void uP.catch(cl); void dP.then(() => cl(), cl); void Promise.allSettled([uP, dP]);
  return new Response(rS.readable, { status: 200, headers: { "Content-Type": "application/octet-stream", "Cache-Control": "no-store", "X-Accel-Buffering": "no" } });
};

export default {
  async fetch(req) {
    const isWS = req.headers.get("Upgrade")?.toLowerCase() === "websocket";
    const isX = req.method === "POST" && req.body;
    if (isWS) return await handleWSLocal(req);
    if (isX) return await handleXhttpLocal(req);
    return new Response("Not Found", { status: 404 });
  }
};
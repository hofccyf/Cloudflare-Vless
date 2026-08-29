import { connect as cfConnect } from "cloudflare:sockets";
const 玉衡令 = "88888888-8888-8888-8888-888888888888";  //揉揉ID，推荐改成你自己的
const 落霞 = "usip.vpndns.net";  //兜底反帒，推荐改成你自己的
const 雨霽期 = 3e5, 晦明期 = 1e4;
const 通衢 = {
    AU: 'auip.j894d.eu.cc', DE: 'deip.j894d.eu.cc', GB: 'gbip.j894d.eu.cc', HK: 'hkip.j894d.eu.cc',
    JP: 'jpip.j894d.eu.cc', KR: 'krip.j894d.eu.cc', MY: 'myip.j894d.eu.cc', NL: 'nlip.j894d.eu.cc',
    RU: 'ruip.j894d.eu.cc', SG: 'sgip.j894d.eu.cc', TW: 'twip.j894d.eu.cc', US: 'usip.j894d.eu.cc'
};
const 星野 = {
    JP:new Set(['NRT','KIX','FUK','OKA']),KR:new Set(['ICN']),HK:new Set(['HKG']),TW:new Set(['TPE','KHH']),
    SG:new Set(['SIN']),MY:new Set(['KUL','JHB']),AU:new Set(['SYD','MEL','BNE','PER','ADL']),
    US:new Set(['ATL','AUS','BNA','BOS','BUF','BWI','CLE','CLT','CMH','DAL','DEN','DFW','DTW','EWR','FLL','HNL','HOU','IAD','IAH','IND','JAX','LAS','LAX','MCI','MEM','MIA','MKE','MSP','ORD','PHL','PHX','PIT','RDU','SAN','SAT','SEA','SFO','SJC','SLC','STL','TPA','YUL','YVR','YYC','YYZ','MEX','GDL','QRO','BOG','GRU','GIG','EZE','SCL','LIM','CCS','UIO','KIN','PTY','SJU','CUR','AUA','BON','SXM','DOM','BGI','POS','PAP','SDQ','STT','STX']),
    DE:new Set(['FRA','MUC','DUS','HAM','BER','STR','LEJ','DRS','FMM','PAD','SCN','ZRH','GVA','BRN','BSL','VIE','KLU','SZG','INN','WAW','KRK','WRO','KTW','GDN','POZ','LCJ','LUZ','SZZ','PRG','BRQ','BUD','BTS','OTP','CLJ','SOF','BEG','ZAG','KIV','TBS','EVN','DXB','AUH','DOH','MCT','BAH','JED','RUH','KWI','AMM','BEY','BGW','CAI','ALG','TUN','JNB','CPT','DUR','PLZ','NBO','ACC','LOS','DKR','ABV','MPM','LLW','KGL','ADD','DAR','EBB','NDOLA','OGB']),
    GB:new Set(['LHR','MAN','EDI','GLA','BFS','BRS','CWL','LCY','LGW','LTN','STN','LPL','NCL','DUB','ORK','SNN','KEF','OSL','TRD','BGO','SVG','ARN','GOT','MMX','BMA','CPH','AAL','BLL','RNN','HEL','TMP','TKU','RIX','TLL','VNO']),
    NL:new Set(['AMS','BRU','LIL','CRL','LUX','CDG','ORY','LYS','MRS','NCE','BOD','TLS','BIA','MAD','BCN','VLC','OPO','LIS','SCQ','PMI','MAH','IBZ','SVQ','FCO','MXP','LIN','PMO','BRI','FLR','CIA','BLQ','NAP','CTA','ATH','SKG','MLA']),
    RU:new Set(['DME','SVO','LED','KZN','AER','UFA','ROV','KRR','OVB','VVO','TOF'])
};
const 解花 = new TextDecoder(), 篆印 = new TextEncoder(), 雲記 = new Map(), 池書 = new Map(), 地圖 = new Map();

function 析衢(v) {
  if (!v) return null;
  const m = v.match(/^([a-zA-Z0-9.-]+)(?::(\d{1,5}))?$/);
  if (!m) return null;
  const p = m[2] ? Number(m[2]) : 443;
  return p > 0 && p < 65536 ? { hostname: m[1], port: p } : null;
}
function 擇地(s) {
  if (!s || s.length > 253 || s === '.' || s === '[]' || s === '..' || s.startsWith('./') || s.startsWith('../') || s.startsWith(':') || !/^[a-zA-Z0-9._\-:[\]]+$/.test(s)) return 落霞;
  return s;
}
async function 索途(i) {
  i = i.trim();
  if (!i.includes("://") && !i.includes("/")) return 擇地(i);
  const u = i.startsWith("http://") || i.startsWith("https://") ? i : `https://${i}`, n = Date.now(), c = 雲記.get(u);
  if (c && n < c.expireAt) return c.value;
  let p = 池書.get(u);
  if (!p) {
    p = (async () => {
      try {
        const r = await fetch(u, { headers: { "User-Agent": "Mozilla/5.0" }, cf: { cacheEverything: true, cacheTtl: 60 } });
        if (r.ok) { const t = await r.text(), v = 擇地(t.replace(/[\r\n\s\uFEFF]/g, "")); if (v !== 落霞) { 雲記.set(u, { value: v, expireAt: Date.now() + 雨霽期 }); return v; } }
      } catch (_) {}
      雲記.set(u, { value: 落霞, expireAt: Date.now() + 晦明期 });
      return 落霞;
    })();
    池書.set(u, p); p.finally(() => 池書.delete(u));
  }
  return p;
}
function 尋蹤(r) {
  const s = r.indexOf('/', 10); if (s === -1) return ""; let c = r.slice(s + 1); if (!c) return ""; let l = c.length;
  if (l > 0) { const k = c.charCodeAt(l - 1); if (k === 47 || k === 61) c = c.slice(0, l - 1); }
  const m = c.match(/(ip|txtip|p|proxy|proxyip)(?:=|%3D|:\/\/|%3A%2F%2F)([^&\s?#]+)/i);
  if (m && m[2]) { let v = m[2]; if (v.charCodeAt(v.length - 1) === 61) v = v.slice(0, -1); try { return decodeURIComponent(v).trim(); } catch (_) { return v.trim(); } }
  return "";
}
function 列星(req) {
    const list = [], colo = req.cf?.colo;
    for (const [region, colos] of Object.entries(星野)) { if (colos.has(colo)) { list.push(通衢[region]); break; } }
    if (list.length === 0) {
        const cont = req.cf?.continent;
        if (cont === 'AS') list.push(通衢.JP); else if (cont === 'EU') list.push(通衢.DE);
        else if (cont === 'NA' || cont === 'SA') list.push(通衢.US); else if (cont === 'OC') list.push(通衢.AU);
        else list.push(通衢.US);
    }
    list.push(落霞); return list;
}
async function 一葦(h, p) { const s = cfConnect({ hostname: h, port: p }); await s.opened; return s; }
async function 雲帆(a, p, c, fList) {
  try { return await 一葦(a, p); } catch (_) {}
  if (c) { try { return await 一葦(c.hostname, c.port); } catch (_) {} }
  if (fList && fList.length > 0) { for (const f of fList) { if (f && (!c || f.hostname !== c.hostname)) { try { return await 一葦(f.hostname, f.port); } catch (_) {} } } }
  return null;
}
const 神針 = new Uint8Array([0x21,0x12,0xA4,0x42]);
const 法天 = {AQ:0x003,RQ:0x004,AO:0x103,AE:0x113,PQ:0x008,PO:0x108,CQ:0x00A,CO:0x10A,BQ:0x00B,BO:0x10B,SI:0x016,DI:0x017};
const 象地 = {USER:0x006,MI:0x008,ERR:0x009,PEER:0x012,DATA:0x013,REALM:0x014,NONCE:0x015,TRANSPORT:0x019,CONNID:0x02A};
const 二爻 = (b, o = 0) => (b[o] << 8) | b[o + 1], 四象 = n => -n & 3;
const 聚沙 = (...a) => { const r = new Uint8Array(a.reduce((s, x) => s + x.length, 0)); a.reduce((o, x) => (r.set(x, o), o + x.length), 0); return r; };
const 落鎖 = (...a) => a.forEach(x => { try { x?.close?.(); } catch {} });
const 生辰 = () => crypto.getRandomValues(new Uint8Array(12));
const 畫符 = (t, v) => { const b = new Uint8Array(4 + v.length + 四象(v.length)), d = new DataView(b.buffer); d.setUint16(0, t); d.setUint16(2, v.length); b.set(v, 4); return b; };
const 寄書 = (t, id, a) => { const bd = 聚沙(...a), h = new Uint8Array(20), d = new DataView(h.buffer); d.setUint16(0, t); d.setUint16(2, bd.length); h.set(神針, 4); h.set(id, 8); return 聚沙(h, bd); };
const 展脈 = ip => { ip = ip.replace(/^\[|\]$/g, '').split('%')[0]; if (!ip.includes('::')) return ip.split(':').map(g => g || '0'); const [l, r] = ip.split('::'); const L = l ? l.split(':') : [], R = r ? r.split(':') : []; const m = Math.max(0, 8 - L.length - R.length); return [...L, ...Array(m).fill('0'), ...R]; };
const 幻影 = (ip, port) => { const v6 = ip.includes(':'), b = new Uint8Array(v6 ? 20 : 8); b[1] = v6 ? 2 : 1; new DataView(b.buffer).setUint16(2, port ^ 0x2112); if (v6) { const x = new Uint8Array(16); x.set(神針); 展脈(ip).forEach((g, i) => { const v = parseInt(g || '0', 16); b[4 + i * 2] = ((v >> 8) ^ x[i * 2]) & 0xff; b[5 + i * 2] = (v & 0xff) ^ x[i * 2 + 1]; }); } else { ip.split('.').forEach((v, i) => b[4 + i] = +v ^ 神針[i]); } return b; };
const 解符 = d => { if (d.length < 20 || 神針.some((v, i) => d[4 + i] !== v)) return null; const dv = new DataView(d.buffer, d.byteOffset, d.byteLength), ml = dv.getUint16(2), a = {}; for (let o = 20; o + 4 <= 20 + ml;) { const t = dv.getUint16(o), l = dv.getUint16(o + 2); if (o + 4 + l > d.length) break; a[t] = d.slice(o + 4, o + 4 + l); o += 4 + l + 四象(l); } return { type: dv.getUint16(0), attrs: a }; };
const 辨咎 = d => d?.length >= 4 ? (d[2] & 7) * 100 + d[3] : 0;
const 解幻 = d => { if (!d?.length || d.length < 8) return ['', 0]; const p = 二爻(d, 2) ^ 0x2112; if (d[1] === 2 && d.length >= 20) { const x = new Uint8Array(16); x.set(神針); return [Array.from({ length: 8 }, (_, i) => ((d[4 + i * 2] ^ x[i * 2]) << 8 | (d[5 + i * 2] ^ x[i * 2 + 1])).toString(16)).join(':'), p]; } return [神針.map((m, i) => d[4 + i] ^ m).join('.'), p]; };
const 加印 = async (m, k) => { const c = new Uint8Array(m), d = new DataView(c.buffer); d.setUint16(2, d.getUint16(2) + 24); const K = await crypto.subtle.importKey('raw', k, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']); return 聚沙(c, 畫符(象地.MI, new Uint8Array(await crypto.subtle.sign('HMAC', K, c)))); };
const 閱符 = async (r, b) => { let B = b ?? new Uint8Array(0); const p = async () => { const { done, value } = await r.read(); if (done) throw 0; if (value == null) return; B = 聚沙(B, new Uint8Array(value)); }; try { while (B.length < 20) await p(); const n = 20 + 二爻(B, 2); while (B.length < n) await p(); return [解符(B.subarray(0, n)), B.length > n ? B.subarray(n) : null]; } catch { return [null, null]; } };
const 尋脈 = async h => { if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) return h; if (h.includes(':')) return h.replace(/^\[|\]$/g, ''); const n = Date.now(), c = 地圖.get(h); if (c && n < c.exp) return c.ip; const d = t => fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(h)}&type=${t}`, { headers: { Accept: 'application/dns-json' } }).then(r => r.json()).catch(() => ({})); const [ra, r6] = await Promise.all([d('A'), d('AAAA')]); const ip = ra.Answer?.find(r => r.type === 1)?.data ?? r6.Answer?.find(r => r.type === 28)?.data ?? null; if (ip) { const t = Math.min(300, Math.max(10, ra.Answer?.find(r => r.type === 1)?.TTL ?? r6.Answer?.find(r => r.type === 28)?.TTL ?? 30)); 地圖.set(h, { ip, exp: Date.now() + t * 1e3 }); } return ip; };
const 五印 = async s => new Uint8Array(await crypto.subtle.digest('MD5', 篆印.encode(s)));
const 覓角 = u => { let U; try { U = decodeURIComponent(u); } catch { return null; } const m = U.match(/\/turn:\/\/([^?\s]*)/i); if (!m) return null; const t = m[1], at = t.lastIndexOf('@'), cr = at >= 0 ? t.slice(0, at) : '', hp = t.slice(at + 1); let h, p; if (hp.startsWith('[')) { const e = hp.indexOf(']'); if (e === -1) return null; h = hp.slice(0, e + 1); p = hp.slice(e + 2); } else { const c = hp.lastIndexOf(':'); h = c >= 0 ? hp.slice(0, c) : hp; p = c >= 0 ? hp.slice(c + 1) : ''; } const P = +p; if (!P || P < 1 || P > 65535) return null; const ci = cr.indexOf(':'); return { host: h, port: P, user: ci >= 0 ? cr.slice(0, ci) : '', pass: ci >= 0 ? cr.slice(ci + 1) : '' }; };
const 覓角Q = q => { if (!q) return null; const at = q.lastIndexOf('@'), cr = at >= 0 ? q.slice(0, at) : '', hp = at >= 0 ? q.slice(at + 1) : q; const ci = hp.lastIndexOf(':'); if (ci === -1) return null; const h = hp.slice(0, ci), p = +hp.slice(ci + 1); if (!h || !p || p < 1 || p > 65535) return null; const cu = cr.indexOf(':'); return { host: h, port: p, user: cu >= 0 ? cr.slice(0, cu) : '', pass: cu >= 0 ? cr.slice(cu + 1) : '' }; };
const 過鬼 = async (w, r, t, { user, pass }, pl) => { const tp = new Uint8Array([t, 0, 0, 0]); await w.write(寄書(法天.AQ, 生辰(), [畫符(象地.TRANSPORT, tp)])); let [m, e] = await 閱符(r); if (!m) return null; let k = null, aa = []; const s = x => k ? 加印(x, k) : Promise.resolve(x); if (m.type === 法天.AE && user && 辨咎(m.attrs[象地.ERR]) === 401) { const rm = 解花.decode(m.attrs[象地.REALM] ?? new Uint8Array(0)), nc = m.attrs[象地.NONCE] ?? new Uint8Array(0); k = await 五印(`${user}:${rm}:${pass}`); aa = [畫符(象地.USER, 篆印.encode(user)), 畫符(象地.REALM, 篆印.encode(rm)), 畫符(象地.NONCE, nc)]; const aq = await 加印(寄書(法天.AQ, 生辰(), [畫符(象地.TRANSPORT, tp), ...aa]), k); const ex = pl ? await Promise.all(pl(aa, s)) : []; await w.write(ex.length ? 聚沙(aq, ...ex) : aq); [m, e] = await 閱符(r, e); if (!m) return null; } else if (pl && m.type === 法天.AO) { const ex = await Promise.all(pl(aa, s)); if (ex.length) await w.write(聚沙(...ex)); } return m.type === 法天.AO ? { key: k, aa, ex: e, sign: s } : null; };
const 抽芽 = (h, p) => { const s = cfConnect({ hostname: h, port: p }); return s.opened.then(() => s); };
const 通鬼 = async (turn, tIp, tP) => {
  let ctrl = null, data = null;
  const cl = () => 落鎖(ctrl, data);
  try {
    ctrl = await 抽芽(turn.host, turn.port);
    const cw = ctrl.writable.getWriter(), cr = ctrl.readable.getReader(), peer = 畫符(象地.PEER, 幻影(tIp, tP)), auth = await 過鬼(cw, cr, 6, turn, (aa, s) => [s(寄書(法天.PQ, 生辰(), [peer, ...aa])), s(寄書(法天.CQ, 生辰(), [peer, ...aa]))]);
    if (!auth) { try { cw.releaseLock(); } catch {} try { cr.releaseLock(); } catch {} cl(); return null; }
    const dS = cfConnect({ hostname: turn.host, port: turn.port }), { aa, sign } = auth;
    let ex = auth.ex, r;
    [r, ex] = await 閱符(cr, ex); if (r?.type !== 法天.PO) { try{cr.releaseLock();}catch{} try{cw.releaseLock();}catch{} cl(); return null; }
    [r, ex] = await 閱符(cr, ex); if (r?.type !== 法天.CO || !r.attrs[象地.CONNID]) { try{cr.releaseLock();}catch{} try{cw.releaseLock();}catch{} cl(); return null; }
    try { await dS.opened; } catch (E) { 落鎖(dS); try{cr.releaseLock();}catch{} try{cw.releaseLock();}catch{} cl(); return null; }
    data = dS;
    const dw = data.writable.getWriter(), dr = data.readable.getReader();
    await dw.write(await sign(寄書(法天.BQ, 生辰(), [畫符(象地.CONNID, r.attrs[象地.CONNID]), ...aa])));
    let ex2; [r, ex2] = await 閱符(dr);
    if (r?.type !== 法天.BO) { try{dw.releaseLock();}catch{} try{dr.releaseLock();}catch{} try{cr.releaseLock();}catch{} try{cw.releaseLock();}catch{} cl(); return null; }
    cr.releaseLock(); cw.releaseLock(); dw.releaseLock();
    try { dr.releaseLock(); } catch {}
    let kad = false;
    const oc = cl, ca = () => { kad = true; try { ctrlW.releaseLock(); } catch {} oc(); }, ctrlW = ctrl.writable.getWriter();
    (async () => { try { const rd = ctrl.readable.getReader(); while (!(await rd.read()).done); } catch {} })();
    (async () => { try { for (;;) { await new Promise(r => setTimeout(r, 27e4)); if (kad) break; await ctrlW.write(聚沙(await sign(寄書(法天.RQ, 生辰(), aa)), await sign(寄書(法天.PQ, 生辰(), [peer, ...aa])))); } } catch {} })();
    return { readable: data.readable, writable: data.writable, close: ca, prefix: (ex2 && ex2.length) ? ex2.slice() : null };
  } catch { cl(); return null; }
};
const 刻址 = h => { const s = h.replace(/^\[|\]$/g, ''), m = s.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/); if (m) return new Uint8Array([0x01, ...m.slice(1).map(Number)]); if (s.includes(':')) { const b = new Uint8Array(17); b[0] = 0x03; 展脈(s).forEach((x, i) => { const v = parseInt(x || '0', 16); b[1 + i * 2] = v >> 8; b[2 + i * 2] = v & 0xff; }); return b; } const e = 篆印.encode(h); return 聚沙(new Uint8Array([0x02, e.length]), e); };
const 解址 = d => { if (!d.length) return ['', 0]; if (d[0] <= 1) return d.length >= 5 ? [d.subarray(1, 5).join('.'), 5] : ['', 0]; if (d[0] === 2) return d.length >= 2 + d[1] ? [解花.decode(d.subarray(2, 2 + d[1])), 2 + d[1]] : ['', 0]; return d[0] === 3 && d.length >= 17 ? [`[${Array.from({ length: 8 }, (_, i) => 二爻(d, 1 + i * 2).toString(16)).join(':')}]`, 17] : ['', 0]; };
const 辨幻 = h => { const m = h.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/); return m && +m[1] === 198 && [18, 19].includes(+m[2]) ? 4 : h.replace(/^\[|\]$/g, '').startsWith('fc') && h.includes(':') ? 6 : 0; };
const 解包 = d => { if (d.length < 6) return null; const ml = 二爻(d), me = 2 + ml; if (ml < 4 || me > d.length) return null; const f = { network: me > 6 ? d[6] : 0, port: me >= 9 ? 二爻(d, 7) : 0, host: me > 9 ? 解址(d.subarray(9, me))[0] : '', payload: null, totalLen: me }; if ((d[5] & 1) && me + 2 <= d.length) { const pL = 二爻(d, me); if (me + 2 + pL <= d.length) { f.payload = d.subarray(me + 2, me + 2 + pL); f.totalLen = me + 2 + pL; } } return f; };
const 回包 = (h, p, pL) => { const a = 刻址(h), ml = 7 + a.length, b = new Uint8Array(2 + ml + 2 + pL.length); [b[0], b[1], b[4], b[5], b[6], b[7], b[8]] = [ml >> 8, ml & 0xff, 2, 1, 2, p >> 8, p & 0xff]; b.set(a, 9); const o = 2 + ml; [b[o], b[o + 1]] = [pL.length >> 8, pL.length & 0xff]; b.set(pL, o + 2); return b; };
const 通流 = async (turn, sw) => { let s = null, c = false; const ps = new Set(), ss = new Map(), rv = {}; let _w = null; const cl = () => { c = true; try { _w?.releaseLock(); } catch {} 落鎖(s); }; try { s = await 抽芽(turn.host, turn.port); const w = (_w = s.writable.getWriter()), r = s.readable.getReader(), auth = await 過鬼(w, r, 17, turn); if (!auth) { try{w.releaseLock();}catch{} try{r.releaseLock();}catch{} _w=null; cl(); return null; } const { aa, sign } = auth; let b = auth.ex; (async () => { try { while (!c) { const [m, n] = await 閱符(r, b); b = n; if (!m) break; if (m.type === 法天.DI && m.attrs[象地.PEER] && m.attrs[象地.DATA]) { const [ip, pt] = 解幻(m.attrs[象地.PEER]), S = rv[`${ip}:${pt}`]; sw(回包(S?.host ?? ip, S?.port ?? pt, m.attrs[象地.DATA])); } } } finally { try { r.releaseLock(); } catch {} } })(); let wC = Promise.resolve(); const cw = m => { if (c) return; wC = wC.then(() => { if (c) return; return w.write(m).catch(() => {}); }); }; (async () => { try { while (!c) { await new Promise(r => setTimeout(r, 24e4)); if (c) break; cw(await sign(寄書(法天.RQ, 生辰(), aa))); for (const ip of ps) cw(await sign(寄書(法天.PQ, 生辰(), [畫符(象地.PEER, 幻影(ip, 0)), ...aa]))); } } catch {} })(); const ep = ip => { if (ps.has(ip)) return; ps.add(ip); sign(寄書(法天.PQ, 生辰(), [畫符(象地.PEER, 幻影(ip, 0)), ...aa])).then(cw); }, sU = (ip, p, d) => cw(寄書(法天.SI, 生辰(), [畫符(象地.PEER, 幻影(ip, p)), 畫符(象地.DATA, d)])), gI = (h, p) => { const k = `${h}:${p}`, c = ss.get(k); if (c) return c.ip; const ft = 辨幻(h); if (ft) for (const s of ss.values()) if (s.port === p && s.isV6 === (ft === 6)) { const ns = { ip: s.ip, host: h, port: p, isV6: s.isV6 }; ss.set(k, ns); rv[`${s.ip}:${p}`] = ns; return s.ip; } return null; }, rA = async (h, p, k) => { const ip = await 尋脈(h); if (ip) { const s = { ip, host: h, port: p, isV6: ip.includes(':') }; ss.set(k, s); rv[`${ip}:${p}`] = s; } }, pX = d => { while (d.length >= 6) { const f = 解包(d); if (!f) break; if (f.network === 2 && f.payload?.length && f.host) { const k = `${f.host}:${f.port}`, ip = gI(f.host, f.port); ip ? (ep(ip), sU(ip, f.port, f.payload)) : ss.has(k) || rA(f.host, f.port, k); } d = d.subarray(f.totalLen); } }; return { processXUDP: pX, close: cl }; } catch { cl(); return null; } };
const 玉衡印 = (() => { const b = new Uint8Array(16), h = 玉衡令.replace(/-/g, ""); for (let i = 0; i < 16; i++) b[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16); return b; })();
const 六脈 = b => { const p = []; for (let i = 0; i < 16; i += 2) p.push(((b[i] << 8) | b[i + 1]).toString(16)); return p.join(":").replace(/:(?:0:)+/, "::"); };
const 探首 = (buf, 帶玉) => {
  if (buf.byteLength < 7) return null;
  const proto = buf[0];
  if (proto === 1 && 帶玉) return { address: `${buf[1]}.${buf[2]}.${buf[3]}.${buf[4]}`, port: (buf[5] << 8) | buf[6], rawPayload: buf.subarray(7), isUDP: false, isVless: false };
  if (proto === 3 && 帶玉) { const l = buf[1]; if (buf.byteLength < 4 + l) return null; return { address: 解花.decode(buf.subarray(2, 2 + l)), port: (buf[2 + l] << 8) | buf[3 + l], rawPayload: buf.subarray(4 + l), isUDP: false, isVless: false }; }
  if (proto === 4 && 帶玉) { if (buf.byteLength < 19) return null; const g = []; for (let i = 0; i < 8; i++) g.push(((buf[1 + i * 2] << 8) | buf[2 + i * 2]).toString(16)); return { address: `[${g.join(':')}]`, port: (buf[17] << 8) | buf[18], rawPayload: buf.subarray(19), isUDP: false, isVless: false }; }
  if (buf.byteLength >= 60 && buf[56] === 13 && buf[57] === 10) {
    const tA = buf[59]; let tAdd = '', tO = 60;
    if (tA === 1) { if (buf.byteLength < 66) return null; tAdd = `${buf[60]}.${buf[61]}.${buf[62]}.${buf[63]}`; tO = 64; }
    else if (tA === 3) { if (buf.byteLength < 62) return null; const tLen = buf[60]; if (buf.byteLength < 61 + tLen) return null; tAdd = 解花.decode(buf.subarray(61, 61 + tLen)); tO = 61 + tLen; }
    else if (tA === 4) { if (buf.byteLength < 76) return null; const tI = []; for (let i = 0; i < 8; i++) tI.push(((buf[60 + i * 2] << 8) | buf[61 + i * 2]).toString(16)); tAdd = `[${tI.join(':')}]`; tO = 76; }
    else return null;
    if (buf.byteLength < tO + 4) return null; const tP = (buf[tO] << 8) | buf[tO + 1];
    return { address: tAdd, port: tP, rawPayload: buf.subarray(tO + 4), isUDP: false, isVless: false };
  }
  if (buf.byteLength < 24 || proto !== 0) return null;
  const v = new DataView(buf.buffer, buf.byteOffset, buf.byteLength); let o = 1;
  for (let i = 0; i < 16; i++) if (buf[o++] !== 玉衡印[i]) return null;
  const sL = buf[o++]; if (o + sL + 4 > buf.byteLength) return null;
  const c = buf[o + sL]; if (c === 3) return { isUDP: true, rawPayload: buf.subarray(o + sL + 1), isVless: true };
  o += sL; const aT = buf[o++]; if (aT !== 1) return null;
  const p = v.getUint16(o, false); o += 2; const k = buf[o++]; let a;
  if (k === 1) { if (o + 4 > buf.byteLength) return null; a = `${buf[o]}.${buf[o + 1]}.${buf[o + 2]}.${buf[o + 3]}`; o += 4; }
  else if (k === 2) { if (o >= buf.byteLength) return null; const l = buf[o++]; if (o + l > buf.byteLength) return null; a = 解花.decode(buf.subarray(o, o + l)); o += l; }
  else if (k === 3) { if (o + 16 > buf.byteLength) return null; a = `[${六脈(buf.subarray(o, o + 16))}]`; o += 16; }
  else return null;
  return { address: a, port: p, rawPayload: buf.subarray(o), isUDP: false, isVless: true };
};
const 鵲橋 = async (r, w, sM) => { const rd = r.getReader({ mode: "byob" }); let b = new ArrayBuffer(65536); try { while (true) { const { done, value: 米 } = await rd.read(new Uint8Array(b)); if (done) break; w.send(米); b = 米.buffer; } } finally { rd.releaseLock(); } };
const 馭龍 = async (ws, ip, req, cP, fList, 帶玉) => {
  ws.binaryType = "arraybuffer";
  let ts = null, tw = null, est = false, wt = Promise.resolve(), cl = false, uh = null;
  const turn = 覓角(req.url), close = () => { if (cl) return; cl = true; try { uh?.close(); } catch {} try { tw?.releaseLock(); } catch {} try { ts?.close(); } catch {} try { ws.close(); } catch {} };
  const pP = async p => {
    try {
      if (uh) return uh.processXUDP(p);
      if (tw) return tw.write(p);
      const g = 探首(p, 帶玉); if (!g) return close();
      if (g.isVless) ws.send(new Uint8Array([p[0], 0]));
      if (g.isUDP && turn) { uh = await 通流(turn, d => { try { ws.send(d); } catch {} }); if (!uh) return close(); const ud = g.rawPayload; ud.length && uh.processXUDP(ud); return; }
      let sM = false;
      if (turn) { const ip = /^\d+\.\d+\.\d+\.\d+$/.test(g.address) ? g.address : (g.address.includes(':') ? g.address.replace(/^\[|\]$/g, '') : await 尋脈(g.address)); if (!ip) return close(); ts = await 通鬼(turn, ip, g.port); }
      else { sM = g.port === 443 || (g.rawPayload.byteLength > 0 && g.rawPayload[0] === 0x16); ts = await 雲帆(g.address, g.port, cP, fList); }
      if (!ts) return close();
      tw = ts.writable.getWriter(); est = true;
      鵲橋(ts.readable, ws, sM).finally(close);
      if (g.rawPayload.byteLength) await tw.write(g.rawPayload);
    } catch { close(); }
  };
  ws.addEventListener("message", e => { const 貨 = est ? e.data : new Uint8Array(e.data); wt = wt.then(() => pP(貨)).catch(close); });
  ws.addEventListener("close", close); ws.addEventListener("error", close);
  if (ip) wt = pP(ip).catch(close);
};
const 解印 = v => { const n = v.replace(/-/g, "+").replace(/_/g, "/"), r = n.length % 4, b = atob(r ? n + "=".repeat(4 - r) : n), u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; };
const 迎客 = async req => {
  const rP = 尋蹤(req.url), rPr = rP ? await 索途(rP) : "", cP = 析衢(rPr);
  const fList = 列星(req).map(ip => 析衢(ip)).filter(Boolean);
  const 帶玉 = decodeURIComponent(req.url).includes(玉衡令), pH = req.headers.get("sec-websocket-protocol");
  let iPL = null;
  if (pH) { try { iPL = 解印(pH); } catch { return new Response("Bad WebSocket protocol.", { status: 400 }); } }
  const pr = new WebSocketPair(), [cW, sW] = Object.values(pr); sW.accept();
  馭龍(sW, iPL, req, cP, fList, 帶玉);
  return new Response(null, { status: 101, webSocket: cW, headers: pH ? { "Sec-WebSocket-Protocol": pH } : undefined });
};
const 首限 = 8192, 空缽 = new Uint8Array(0), 合缽 = (l, r) => { const m = new Uint8Array(l.byteLength + r.byteLength); m.set(l); m.set(r, l.byteLength); return m; }, 辨玉 = b => { const u = 玉衡令.replace(/-/g, ""); for (let i = 0; i < 16; i++) if (b[i + 1] !== parseInt(u.slice(i * 2, i * 2 + 2), 16)) return false; return true; };
const 探信 = (b, 帶玉) => {
  if (b.byteLength < 7) return null;
  const pr = b[0];
  if (pr === 1 && 帶玉) return { hostname: `${b[1]}.${b[2]}.${b[3]}.${b[4]}`, port: (b[5] << 8) | b[6], dataOffset: 7, isVless: false };
  if (pr === 3 && 帶玉) { const l = b[1]; if (b.byteLength < 4 + l) return null; return { hostname: 解花.decode(b.subarray(2, 2 + l)), port: (b[2 + l] << 8) | b[3 + l], dataOffset: 4 + l, isVless: false }; }
  if (pr === 4 && 帶玉) { if (b.byteLength < 19) return null; const g = []; for (let i = 0; i < 8; i++) g.push(((b[1 + i * 2] << 8) | b[2 + i * 2]).toString(16)); return { hostname: g.join(':'), port: (b[17] << 8) | b[18], dataOffset: 19, isVless: false }; }
  if (b.byteLength >= 60 && b[56] === 13 && b[57] === 10) {
    const tA = b[59]; let tH = '', tO = 60;
    if (tA === 1) { if (b.byteLength < 66) return null; tH = `${b[60]}.${b[61]}.${b[62]}.${b[63]}`; tO = 64; }
    else if (tA === 3) { if (b.byteLength < 62) return null; const tLen = b[60]; if (b.byteLength < 61 + tLen) return null; tH = 解花.decode(b.subarray(61, 61 + tLen)); tO = 61 + tLen; }
    else if (tA === 4) { if (b.byteLength < 76) return null; const tI = []; for (let i = 0; i < 8; i++) tI.push(((b[60 + i * 2] << 8) | b[61 + i * 2]).toString(16)); tH = `[${tI.join(':')}]`; tO = 76; }
    else return null;
    if (b.byteLength < tO + 4) return null; const tP = (b[tO] << 8) | b[tO + 1];
    return { hostname: tH, port: tP, dataOffset: tO + 4, isVless: false };
  }
  if (b.byteLength < 18 || pr !== 0) return null;
  if (!辨玉(b)) throw new Error("invalid vless uuid");
  const cO = 18 + b[17]; if (b.byteLength < cO + 4) return null;
  if (b[cO] !== 1) throw new Error("tcp only");
  const p = (b[cO + 1] << 8) | b[cO + 2]; if (p === 0) throw new Error("invalid port");
  const aT = b[cO + 3]; let o = cO + 4, h;
  if (aT === 1) { if (b.byteLength < o + 4) return null; h = `${b[o]}.${b[o + 1]}.${b[o + 2]}.${b[o + 3]}`; o += 4; }
  else if (aT === 2) { if (b.byteLength < o + 1) return null; const l = b[o++]; if (l === 0) throw new Error("empty domain"); if (b.byteLength < o + l) return null; h = 解花.decode(b.subarray(o, o + l)); o += l; }
  else if (aT === 3) { if (b.byteLength < o + 16) return null; const g = []; for (let i = 0; i < 8; i++) g.push(((b[o + i * 2] << 8) | b[o + i * 2 + 1]).toString(16)); h = g.join(":"); o += 16; }
  else throw new Error("invalid address type");
  return { version: b[0], hostname: h, port: p, dataOffset: o, isVless: true };
};
const 閱信 = async (r, 帶玉) => {
  const rd = r.body.getReader(); let b = 空缽;
  try { for (;;) { const { done, value } = await rd.read(); if (done) throw new Error("incomplete vless header"); const c = value instanceof Uint8Array ? value : new Uint8Array(value); b = b.byteLength ? 合缽(b, c) : c.slice(); const p = 探信(b, 帶玉); if (p) { rd.releaseLock(); return { ...p, initialPayload: b.subarray(p.dataOffset).slice() }; } if (b.byteLength > 首限) throw new Error("vless header too large"); } } catch (e) { try { await rd.cancel(e); } catch {} throw e; }
};
const 迎信 = async req => {
  if (!req.body) return new Response("Not Found", { status: 404 });
  const rP = 尋蹤(req.url), rPr = rP ? await 索途(rP) : "", cP0 = 析衢(rPr);
  const fList = 列星(req).map(ip => 析衢(ip)).filter(Boolean);
  const 帶玉 = decodeURIComponent(req.url).includes(玉衡令);
  const urlObj = new URL(req.url);
  const turnQ = urlObj.searchParams.get('turn');
  const turn = turnQ ? 覓角Q(turnQ) : null;
  const ipQ = urlObj.searchParams.get('ip');
  let cP = cP0;
  if (ipQ && !rP) {
    const rawVal = (ipQ.includes("://") || ipQ.includes("/")) ? await 索途(ipQ) : ipQ.trim();
    cP = 析衢(擇地(rawVal));
  }
  let h;
  try { h = await 閱信(req, 帶玉); } catch { return new Response("bad request", { status: 400 }); }
  let s;
  try {
    if (turn) {
      const ip = /^\d+\.\d+\.\d+\.\d+$/.test(h.hostname) ? h.hostname : (h.hostname.includes(':') ? h.hostname.replace(/^\[|\]$/g, '') : await 尋脈(h.hostname));
      if (!ip) return new Response("resolve failed", { status: 502 });
      s = await 通鬼(turn, ip, h.port);
      if (!s) return new Response("TURN tunnel failed", { status: 502 });
    } else {
      s = await 雲帆(h.hostname, h.port, cP, fList);
    }
  } catch { try { await req.body.cancel(); } catch {} return new Response("bad gateway", { status: 502 }); }
  const ac = new AbortController(); let sC = false;
  const cl = r => { if (!ac.signal.aborted) { try { ac.abort(r); } catch {} } if (!sC) { sC = true; try { s.close(); } catch {} } };
  const uP = (async () => { const w = s.writable.getWriter(); try { if (h.initialPayload.byteLength) await w.write(h.initialPayload); } finally { w.releaseLock(); } await req.body.pipeTo(s.writable, { signal: ac.signal }); })();
  const rS = new IdentityTransformStream();
  const dP = (async () => {
    const w = rS.writable.getWriter();
    try {
      if (h.isVless) await w.write(new Uint8Array([h.version, 0]));
      if (s.prefix && s.prefix.byteLength) await w.write(s.prefix);
    } catch (e) { try { await w.abort(e); } catch {} throw e; }
    finally { w.releaseLock(); }
    await s.readable.pipeTo(rS.writable, { signal: ac.signal });
  })();
  void uP.catch(cl); void dP.then(() => cl(), cl); void Promise.allSettled([uP, dP]);
  return new Response(rS.readable, { status: 200, headers: { "Content-Type": "application/octet-stream", "Cache-Control": "no-store", "X-Accel-Buffering": "no" } });
};
export default {
  async fetch(req) {
    if (req.url.includes('__ping')) return new Response("SINGLE-FINAL-V1", { status: 200 });
    if (!decodeURIComponent(req.url).includes(玉衡令)) return new Response("Forbidden", { status: 403 });
    const isWS = req.headers.get("Upgrade")?.toLowerCase() === "websocket", isX = req.method === "POST" && req.body;
    if (isWS) return await 迎客(req);
    if (isX) return await 迎信(req);
    return new Response("Not Found", { status: 404 });
  }
};

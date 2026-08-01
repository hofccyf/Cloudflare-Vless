const CFG = {
  id: '88888888-8888-8888-8888-888888888888',
  chunk: 64 * 1024, dnPack: 32 * 1024, dnTail: 512, dnMs: 0,
  upPack: 16 * 1024, upQMax: 256 * 1024, maxED: 8 * 1024, concur: 4
};  //snippets部署的话，concur不能是4，必须是1 ！！！

const 默认备用小可爱地址 = 'usip.vpndns.net';  //兜底落地IP，建议改成你自己的
const 主连接超时毫秒 = 2000;
const 备用连接超时毫秒 = 4000;
const txt缓存生存期ms = 60 * 1000;
const txt失败缓存生存期ms = 10 * 1000;

const hex = c => (c > 64 ? c + 9 : c) & 0xF;
const idB = new Uint8Array(16);
const dec = new TextDecoder('utf-8');
const enc = s => new TextEncoder().encode(s);
for (let i = 0, p = 0, c, h; i < 16; i++) {
  c = CFG.id.charCodeAt(p++); c === 45 && (c = CFG.id.charCodeAt(p++));
  h = hex(c);
  c = CFG.id.charCodeAt(p++); c === 45 && (c = CFG.id.charCodeAt(p++));
  idB[i] = h << 4 | hex(c);
}
const [I0,I1,I2,I3,I4,I5,I6,I7,I8,I9,I10,I11,I12,I13,I14,I15] = idB;
const matchID = c =>
  c[1]===I0&&c[2]===I1&&c[3]===I2&&c[4]===I3&&c[5]===I4&&c[6]===I5&&
  c[7]===I6&&c[8]===I7&&c[9]===I8&&c[10]===I9&&c[11]===I10&&c[12]===I11&&
  c[13]===I12&&c[14]===I13&&c[15]===I14&&c[16]===I15;

const parseHeader = (c, hasSSPass) => {
  if (c.length < 7) return null;
  const proto = c[0];
  let host = '', port = 0, offset = 0;
  if (proto === 0) {
    if (c.length < 24 || !matchID(c)) return null;
    const optLen = c[17], cmdPos = 18 + optLen;
    if (cmdPos >= c.length) return null;
    const cmd = c[cmdPos];
    if (cmd !== 1 && cmd !== 3) return null;
    if (cmdPos + 4 > c.length) return null;
    port = (c[cmdPos+1] << 8) | c[cmdPos+2];
    const addrType = c[cmdPos+3];
    let addrPos = cmdPos + 4;
    if (addrType === 1) {
      if (c.length < addrPos + 4) return null;
      host = `${c[addrPos]}.${c[addrPos+1]}.${c[addrPos+2]}.${c[addrPos+3]}`;
      offset = addrPos + 4;
    } else if (addrType === 2) {
      if (c.length < addrPos + 1) return null;
      const len = c[addrPos];
      if (c.length < addrPos + 1 + len) return null;
      host = dec.decode(c.subarray(addrPos+1, addrPos+1+len));
      offset = addrPos + 1 + len;
    } else if (addrType === 3) {
      if (c.length < addrPos + 16) return null;
      const ipv6 = [];
      for (let i = 0; i < 8; i++) ipv6.push(((c[addrPos+i*2]<<8)|c[addrPos+i*2+1]).toString(16));
      host = ipv6.join(':'); offset = addrPos + 16;
    } else return null;
    return { host, port, offset, isVless: true, isUDP: cmd === 3 };
  } else if (proto === 1 || proto === 3 || proto === 4) {
    if (!hasSSPass) return null;
    if (proto === 1) {
      host = `${c[1]}.${c[2]}.${c[3]}.${c[4]}`; port = (c[5]<<8)|c[6]; offset = 7;
    } else if (proto === 3) {
      const len = c[1]; if (c.length < 4+len) return null;
      host = dec.decode(c.subarray(2, 2+len)); port = (c[2+len]<<8)|c[3+len]; offset = 4+len;
    } else {
      if (c.length < 19) return null;
      const ipv6 = [];
      for (let i = 0; i < 8; i++) ipv6.push(((c[1+i*2]<<8)|c[2+i*2]).toString(16));
      host = ipv6.join(':'); port = (c[17]<<8)|c[18]; offset = 19;
    }
    return { host, port, offset, isVless: false, isUDP: false };
  }
  return null;
};

const mkQ = (cap, qCap = cap, itemsMax = Math.max(1, qCap >> 8)) => {
  let q = [], h = 0, qB = 0, buf = null;
  const trim = () => { h > 32 && h*2 >= q.length && (q = q.slice(h), h = 0); };
  const take = () => { if (h >= q.length) return null; const d = q[h]; q[h++] = undefined; qB -= d.byteLength; trim(); return d; };
  return {
    get bytes() { return qB; }, get size() { return q.length-h; }, get empty() { return h >= q.length; }, clear() { q=[]; h=0; qB=0; },
    sow(d) { const n = d?.byteLength||0; if (!n) return 1; if (qB+n > qCap || q.length-h >= itemsMax) return 0; q.push(d); qB+=n; return 1; },
    bundle(d) {
      d ||= take(); if (!d || h >= q.length || d.byteLength >= cap) return [d, 0];
      let n = d.byteLength, e = h; while (e < q.length) { const x = q[e], nn = n+x.byteLength; if (nn > cap) break; n=nn; e++; }
      if (e === h) return [d, 0]; const out = buf ||= new Uint8Array(cap); out.set(d);
      for (let o = d.byteLength; h < e;) { const x = q[h]; q[h++]=undefined; qB-=x.byteLength; out.set(x,o); o+=x.byteLength; } trim();
      return [out.subarray(0, n), 1];
    }
  };
};

const mkDn = w => {
  const cap = CFG.dnPack, tail = CFG.dnTail, low = Math.max(4096, tail<<3);
  let pb = new Uint8Array(cap), p = 0, tp = 0, mq = 0, gen = 0, qk = 0, qr = 0;
  const reap = () => { tp && clearTimeout(tp); tp=0; mq=0; if (!p) return; w.send(pb.subarray(0,p).slice()); pb=new Uint8Array(cap); p=0; qr=0; };
  const ripen = () => {
    if (tp||mq) return; mq=1; qk=gen;
    queueMicrotask(() => {
      mq=0; if (!p||tp) return;
      if (cap-p < tail) return reap();
      tp = setTimeout(() => {
        tp=0; if (!p) return;
        if (cap-p < tail) return reap();
        if (qr < 2 && (gen !== qk || p < low)) { qr++; qk=gen; return ripen(); }
        reap();
      }, Math.max(CFG.dnMs, 1));
    });
  };
  return {
    send(u) {
      let o=0, n=u?.byteLength||0; if (!n) return;
      while (o < n) {
        if (!p && n-o >= cap) { const m=Math.min(cap,n-o); w.send(o||m!==n?u.subarray(o,o+m):u); o+=m; continue; }
        const m=Math.min(cap-p, n-o); pb.set(u.subarray(o,o+m), p); p+=m; o+=m; gen++;
        if (p===cap || cap-p < tail) reap(); else ripen();
      }
    }, reap
  };
};

const mill = async (rd, w) => {
  const r = rd.getReader({ mode: 'byob' }), tx = mkDn(w); let buf = new ArrayBuffer(CFG.chunk);
  let loopCount = 0;
  try {
    for (;;) {
      const { done, value: v } = await r.read(new Uint8Array(buf, 0, CFG.chunk));
      if (done) break; if (!v?.byteLength) continue;
      if (v.byteLength >= (CFG.chunk >> 1)) { tx.reap(); w.send(v); buf = new ArrayBuffer(CFG.chunk); }
      else { tx.send(v.slice()); buf = v.buffer; }
      if (++loopCount > 128) { loopCount = 0; await new Promise(queueMicrotask); }
    }
    tx.reap();
  } catch {} finally { try { tx.reap(); } catch {} try { r.releaseLock(); } catch {} }
};

let _已预热 = false;
const _预热地址 = addr => { if (_已预热) return; _已预热 = true; 获取动态地址(addr).catch(() => {}); };
const 地址合法正则 = /^[a-zA-Z0-9._\-:[\]]+$/;
const 路径IP正则 = /^\/ip=([^&\/]+)/;
function 校验候选地址(s) {
  if (!s||s.length>253||s==='.'||s==='[]'||s==='..'||s.startsWith('./')||s.startsWith('../')||s.startsWith(':')||!地址合法正则.test(s)) return 默认备用小可爱地址;
  return s;
}
const txt缓存池 = new Map(), txt请求池 = new Map();
async function 获取动态地址(输入) {
  if (!输入.includes('://') && !输入.includes('/')) return 校验候选地址(输入);
  const 链接 = 输入.startsWith('http') ? 输入 : 'https://'+输入;
  const now = Date.now(), 缓存 = txt缓存池.get(链接);
  if (缓存 && now < 缓存.过期时间) return 缓存.目标地址;
  let req = txt请求池.get(链接);
  if (!req) {
    req = (async () => {
      try {
        const res = await fetch(链接, { headers: { 'User-Agent': 'Mozilla/5.0' }, cf: { cacheTtl: 60 } });
        if (res.ok) {
          const txt = await res.text();
          const r = 校验候选地址(txt.replace(/[\r\n\s\uFEFF]/g, ''));
          if (r !== 默认备用小可爱地址) { txt缓存池.set(链接, { 目标地址: r, 过期时间: Date.now()+txt缓存生存期ms }); return r; }
        }
      } catch {}
      txt缓存池.set(链接, { 目标地址: 默认备用小可爱地址, 过期时间: Date.now()+txt失败缓存生存期ms });
      return 默认备用小可爱地址;
    })();
    txt请求池.set(链接, req); req.finally(() => txt请求池.delete(链接));
  }
  return await req;
}
function 拆分地址和端口(s, 默认端口) {
  const ok = p => Number.isInteger(p) && p>=1 && p<=65535 ? p : 默认端口;
  if (s.startsWith('[')) { const e = s.indexOf(']'); if (e===-1) return { 备用主机: s, 备用端口: 默认端口 }; return { 备用主机: s.slice(0,e+1), 备用端口: ok(Number(s.slice(e+2))) }; }
  const ci = s.lastIndexOf(':');
  if (ci===-1||s.indexOf(':')!==ci) return { 备用主机: s, 备用端口: 默认端口 };
  return { 备用主机: s.slice(0,ci), 备用端口: ok(Number(s.slice(ci+1))) };
}

const sprout = (f, h, p) => { const s = f.connect({ hostname: h, port: p }); return s.opened.then(() => s); };
const raceSprout = (f, h, p) => {
  if (!f?.connect) return Promise.reject(new Error('connect unavailable'));
  if (CFG.concur <= 1) return sprout(f, h, p);
  const ts = Array.from({ length: CFG.concur }, () => sprout(f, h, p));
  return Promise.any(ts).then(w => { ts.forEach(t => t.then(s => s !== w && s.close(), () => {})); return w; });
};
const 带超时竞速 = (f, h, p, ms) => {
  let t; const bomb = new Promise((_, r) => { t = setTimeout(() => r(new Error('timeout')), ms); });
  return Promise.race([raceSprout(f, h, p), bomb]).finally(() => clearTimeout(t));
};

const u16 = (b, o=0) => (b[o]<<8)|b[o+1];
const pad4 = n => -n & 3;
const MAGIC = new Uint8Array([0x21,0x12,0xA4,0x42]);
const MT = { AQ:0x003,RQ:0x004,AO:0x103,AE:0x113,PQ:0x008,PO:0x108,CQ:0x00A,CO:0x10A,BQ:0x00B,BO:0x10B,SI:0x016,DI:0x017 };
const AT = { USER:0x006,MI:0x008,ERR:0x009,PEER:0x012,DATA:0x013,REALM:0x014,NONCE:0x015,TRANSPORT:0x019,CONNID:0x02A };
const cat = (...a) => { const r = new Uint8Array(a.reduce((s,x)=>s+x.length,0)); a.reduce((o,x)=>(r.set(x,o),o+x.length),0); return r; };
const safeClose = (...a) => a.forEach(x => { try { x?.close?.(); } catch {} });
const tid = () => crypto.getRandomValues(new Uint8Array(12));
const stunAttr = (t, v) => { const b=new Uint8Array(4+v.length+pad4(v.length)), d=new DataView(b.buffer); d.setUint16(0,t); d.setUint16(2,v.length); b.set(v,4); return b; };
const stunMsg = (t, id, a) => { const bd=cat(...a), h=new Uint8Array(20), d=new DataView(h.buffer); d.setUint16(0,t); d.setUint16(2,bd.length); h.set(MAGIC,4); h.set(id,8); return cat(h,bd); };
const expandIPv6 = ip => {
  ip = ip.replace(/^\[|\]$/g,'').split('%')[0];
  if (!ip.includes('::')) return ip.split(':').map(g=>g||'0');
  const [left,right] = ip.split('::');
  const l = left?left.split(':'):[], r = right?right.split(':'):[];
  const mid = Array(8-l.length-r.length).fill('0');
  return [...l,...mid,...r];
};
const xorPeer = (ip, port) => {
  const isV6 = ip.includes(':');
  const b = new Uint8Array(isV6 ? 20 : 8);
  b[1] = isV6 ? 2 : 1;
  new DataView(b.buffer).setUint16(2, port ^ 0x2112);
  if (isV6) {
    const xk = new Uint8Array(16); xk.set(MAGIC);
    expandIPv6(ip).forEach((g,i)=>{ const v=parseInt(g||'0',16); b[4+i*2]=((v>>8)^xk[i*2])&0xff; b[5+i*2]=(v&0xff)^xk[i*2+1]; });
  } else {
    ip.split('.').forEach((v,i) => b[4+i] = +v ^ MAGIC[i]);
  }
  return b;
};
const parseStun = d => {
  if (d.length<20||MAGIC.some((v,i)=>d[4+i]!==v)) return null;
  const dv=new DataView(d.buffer,d.byteOffset,d.byteLength), ml=dv.getUint16(2), attrs={};
  for (let o=20; o+4<=20+ml;) { const t=dv.getUint16(o), l=dv.getUint16(o+2); if (o+4+l>d.length) break; attrs[t]=d.slice(o+4,o+4+l); o+=4+l+pad4(l); }
  return { type: dv.getUint16(0), attrs };
};
const parseErr = d => d?.length>=4?(d[2]&7)*100+d[3]:0;
const parseXorPeer = d => {
  if (!d?.length || d.length < 8) return ['', 0];
  const port = u16(d,2) ^ 0x2112;
  if (d[1] === 2 && d.length >= 20) {
    const xk = new Uint8Array(16); xk.set(MAGIC);
    const segs = Array.from({length:8}, (_,i) => ((d[4+i*2]^xk[i*2])<<8|(d[5+i*2]^xk[i*2+1])).toString(16));
    return [segs.join(':'), port];
  }
  return [MAGIC.map((m,i) => d[4+i]^m).join('.'), port];
};
const addIntegrity = async (m, key) => {
  const c=new Uint8Array(m), d=new DataView(c.buffer); d.setUint16(2, d.getUint16(2)+24);
  const k=await crypto.subtle.importKey('raw',key,{name:'HMAC',hash:'SHA-1'},false,['sign']);
  return cat(c, stunAttr(AT.MI, new Uint8Array(await crypto.subtle.sign('HMAC',k,c))));
};
const md5 = async s => new Uint8Array(await crypto.subtle.digest('MD5', enc(s)));
const readStun = async (rd, buf) => {
  let b=buf??new Uint8Array(0);
  const pull = async () => { const {done,value}=await rd.read(); if (done) throw 0; b=cat(b,new Uint8Array(value)); };
  try { while (b.length<20) await pull(); const n=20+u16(b,2); while (b.length<n) await pull(); return [parseStun(b.subarray(0,n)), b.length>n?b.subarray(n):null]; }
  catch { return [null,null]; }
};
const _dnsCache = new Map();
const resolveIP = async h => {
  if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) return h;
  if (h.includes(':')) return h.replace(/^\[|\]$/g,'');
  const now = Date.now(), c = _dnsCache.get(h);
  if (c && now < c.exp) return c.ip;
  const doh = t => fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(h)}&type=${t}`,{headers:{Accept:'application/dns-json'}}).then(r=>r.json()).catch(()=>({}));
  const [ra, raaaa] = await Promise.all([doh('A'), doh('AAAA')]);
  const ip = ra.Answer?.find(r=>r.type===1)?.data ?? raaaa.Answer?.find(r=>r.type===28)?.data ?? null;
  if (ip) _dnsCache.set(h, { ip, exp: Date.now()+30000 });
  return ip;
};

const getTurn = url => {
  let _u; try { _u = decodeURIComponent(url); } catch { return null; }
  const m = _u.match(/\/turn:\/\/([^?\s]*)/i); if (!m) return null;
  const t=m[1], at=t.lastIndexOf('@'), cred=at>=0?t.slice(0,at):'', hp=t.slice(at+1);
  let host, portStr;
  if (hp.startsWith('[')) { const e=hp.indexOf(']'); if (e===-1) return null; host=hp.slice(0,e+1); portStr=hp.slice(e+2); }
  else { const ci=hp.lastIndexOf(':'); host=ci>=0?hp.slice(0,ci):hp; portStr=ci>=0?hp.slice(ci+1):''; }
  const port=+portStr; if (!port||port<1||port>65535) return null;
  const ci=cred.indexOf(':');
  return { host, port, user:ci>=0?cred.slice(0,ci):'', pass:ci>=0?cred.slice(ci+1):'' };
};

const turnAuth = async (w, r, transport, { user, pass }, pipeline) => {
  const tp = new Uint8Array([transport,0,0,0]);
  await w.write(stunMsg(MT.AQ, tid(), [stunAttr(AT.TRANSPORT, tp)]));
  let [msg,ex]=await readStun(r); if (!msg) return null;
  let key=null, aa=[];
  const sign = m => key ? addIntegrity(m,key) : Promise.resolve(m);
  if (msg.type===MT.AE && user && parseErr(msg.attrs[AT.ERR])===401) {
    const realm=dec.decode(msg.attrs[AT.REALM]??new Uint8Array(0)), nonce=msg.attrs[AT.NONCE]??new Uint8Array(0);
    key=await md5(`${user}:${realm}:${pass}`);
    aa=[stunAttr(AT.USER,enc(user)),stunAttr(AT.REALM,enc(realm)),stunAttr(AT.NONCE,nonce)];
    const aq=await addIntegrity(stunMsg(MT.AQ,tid(),[stunAttr(AT.TRANSPORT,tp),...aa]),key);
    const extras=pipeline?await Promise.all(pipeline(aa,sign)):[];
    await w.write(extras.length?cat(aq,...extras):aq);
    [msg,ex]=await readStun(r,ex); if (!msg) return null;
  } else if (pipeline && msg.type===MT.AO) {
    const extras=await Promise.all(pipeline(aa,sign));
    if (extras.length) await w.write(cat(...extras));
  }
  return msg.type===MT.AO ? { key, aa, ex, sign } : null;
};

const turnConn = async (fetcher, turn, targetIp, targetPort) => {
  let ctrl = null, data = null;
  const close = () => safeClose(ctrl, data);
  try {
    ctrl = await sprout(fetcher, turn.host, turn.port);
    const cw = ctrl.writable.getWriter(), cr = ctrl.readable.getReader();
    const peer = stunAttr(AT.PEER, xorPeer(targetIp, targetPort));

    const dataSocket = fetcher.connect({ hostname: turn.host, port: turn.port });

    const auth = await turnAuth(cw, cr, 6, turn,
      (aa, sign) => [sign(stunMsg(MT.PQ,tid(),[peer,...aa])), sign(stunMsg(MT.CQ,tid(),[peer,...aa]))]
    );
    if (!auth) { try{cw.releaseLock();}catch{} try{cr.releaseLock();}catch{} close(); return null; }
    const { aa, sign } = auth; let ex = auth.ex;

    let r;
    [r, ex] = await readStun(cr, ex); if (r?.type !== MT.PO) { try{cr.releaseLock();}catch{} try{cw.releaseLock();}catch{} close(); return null; }
    [r, ex] = await readStun(cr, ex); if (r?.type !== MT.CO || !r.attrs[AT.CONNID]) { try{cr.releaseLock();}catch{} try{cw.releaseLock();}catch{} close(); return null; }

    try { await dataSocket.opened; } catch (e) { safeClose(dataSocket); try{cr.releaseLock();}catch{} try{cw.releaseLock();}catch{} close(); return null; }
    data = dataSocket;
    const dw = data.writable.getWriter(), dr = data.readable.getReader();
    await dw.write(await sign(stunMsg(MT.BQ,tid(),[stunAttr(AT.CONNID,r.attrs[AT.CONNID]),...aa])));
    let extra; [r, extra] = await readStun(dr); if (r?.type !== MT.BO) { try{dw.releaseLock();}catch{} try{dr.releaseLock();}catch{} try{cr.releaseLock();}catch{} try{cw.releaseLock();}catch{} close(); return null; }

    cr.releaseLock(); cw.releaseLock(); dw.releaseLock();

    let keepAliveDead = false;
    const origClose = close;
    const closeAll = () => { keepAliveDead = true; origClose(); };
    const ctrlW = ctrl.writable.getWriter();
    (async () => { try { const rd=ctrl.readable.getReader(); while (!(await rd.read()).done); } catch {} })();
    (async () => {
      try {
        for (;;) {
          await new Promise(res => setTimeout(res, 270000));
          if (keepAliveDead) break;
          await ctrlW.write(cat(
            await sign(stunMsg(MT.RQ, tid(), aa)),
            await sign(stunMsg(MT.PQ, tid(), [peer,...aa]))
          ));
        }
      } catch {}
    })();

    const readable = new ReadableStream({
      type: 'bytes',
      start(c) { if (extra?.length) c.enqueue(extra.slice()); },
      async pull(c) {
        const bv = c.byobRequest?.view;
        if (bv) {
          const { done, value } = await dr.read();
          if (done) { c.close(); c.byobRequest.respond(0); return; }
          const v = new Uint8Array(value);
          const n = Math.min(v.byteLength, bv.byteLength);
          new Uint8Array(bv.buffer, bv.byteOffset, n).set(v.subarray(0, n));
          c.byobRequest.respond(n);
          if (n < v.byteLength) c.enqueue(v.subarray(n).slice());
        } else {
          const { done, value } = await dr.read();
          if (done) { c.close(); return; }
          c.enqueue(new Uint8Array(value));
        }
      },
      cancel() { dr.cancel(); }
    });

    return { readable, writable: data.writable, close: closeAll };
  } catch { close(); return null; }
};

const encodeAddr = h => {
  const s=h.replace(/^\[|\]$/g,''), m=s.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (m) return new Uint8Array([0x01,...m.slice(1).map(Number)]);
  if (s.includes(':')) { const b=new Uint8Array(17); b[0]=0x03; expandIPv6(s).forEach((x,i)=>{ const v=parseInt(x||'0',16); b[1+i*2]=v>>8; b[2+i*2]=v&0xff; }); return b; }
  const e=enc(h); return cat(new Uint8Array([0x02,e.length]),e);
};
const xudpAddr = d => {
  if (!d.length) return ['',0];
  if (d[0]<=1) return d.length>=5?[d.subarray(1,5).join('.'),5]:['',0];
  if (d[0]===2) return d.length>=2+d[1]?[dec.decode(d.subarray(2,2+d[1])),2+d[1]]:['',0];
  return d[0]===3&&d.length>=17?[`[${Array.from({length:8},(_,i)=>u16(d,1+i*2).toString(16)).join(':')}]`,17]:['',0];
};
const fakeIPType = h => { const m=h.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/); return m&&+m[1]===198&&[18,19].includes(+m[2])?4:h.replace(/^\[|\]$/g,'').startsWith('fc')&&h.includes(':')?6:0; };
const parseXUDP = d => {
  if (d.length<6) return null;
  const metaLen=u16(d), metaEnd=2+metaLen;
  if (metaLen<4||metaEnd>d.length) return null;
  const f={ network:metaEnd>6?d[6]:0, port:metaEnd>=9?u16(d,7):0, host:metaEnd>9?xudpAddr(d.subarray(9,metaEnd))[0]:'', payload:null, totalLen:metaEnd };
  if ((d[5]&1)&&metaEnd+2<=d.length) { const pLen=u16(d,metaEnd); if (metaEnd+2+pLen<=d.length) { f.payload=d.subarray(metaEnd+2,metaEnd+2+pLen); f.totalLen=metaEnd+2+pLen; } }
  return f;
};
const xudpResp = (host, port, payload) => {
  const a=encodeAddr(host), ml=7+a.length, buf=new Uint8Array(2+ml+2+payload.length);
  [buf[0],buf[1],buf[4],buf[5],buf[6],buf[7],buf[8]]=[ml>>8,ml&0xff,2,1,2,port>>8,port&0xff];
  buf.set(a,9); const pOff=2+ml; [buf[pOff],buf[pOff+1]]=[payload.length>>8,payload.length&0xff];
  buf.set(payload,pOff+2); return buf;
};

const turnUDP = async (fetcher, turn, sendWs) => {
  let sock = null, closed = false;
  const perms = new Set(), sess = new Map(), reverse = {};
  let _udpW = null;
  const close = () => { closed=true; try{_udpW?.releaseLock();}catch{} safeClose(sock); };
  try {
    sock = await sprout(fetcher, turn.host, turn.port);
    const w = (_udpW = sock.writable.getWriter()), r = sock.readable.getReader();
    const auth = await turnAuth(w, r, 17, turn); if (!auth) { try{w.releaseLock();}catch{} try{r.releaseLock();}catch{} _udpW=null; close(); return null; }
    const { aa, sign } = auth; let buf = auth.ex;
    (async () => {
      try {
        while (!closed) {
          const [m,nx] = await readStun(r, buf); buf=nx; if (!m) break;
          if (m.type===MT.DI && m.attrs[AT.PEER] && m.attrs[AT.DATA]) {
            const [ip,pt]=parseXorPeer(m.attrs[AT.PEER]), s=reverse[`${ip}:${pt}`];
            sendWs(xudpResp(s?.host??ip, s?.port??pt, m.attrs[AT.DATA]));
          }
        }
      } finally { try { r.releaseLock(); } catch {} }
    })();
    let wChain = Promise.resolve();
    const chainWrite = msg => { if (closed) return; wChain = wChain.then(() => closed ? Promise.resolve() : w.write(msg).catch(()=>{})); };
    // UDP keepalive: refresh allocation + all perms every 240s
    (async () => {
      try {
        while (!closed) {
          await new Promise(res => setTimeout(res, 240000));
          if (closed) break;
          chainWrite(await sign(stunMsg(MT.RQ, tid(), aa)));
          for (const ip of perms) chainWrite(await sign(stunMsg(MT.PQ, tid(), [stunAttr(AT.PEER, xorPeer(ip, 0)), ...aa])));
        }
      } catch {}
    })();
    const ensurePerm = ip => { if (perms.has(ip)) return; perms.add(ip); sign(stunMsg(MT.PQ,tid(),[stunAttr(AT.PEER,xorPeer(ip,0)),...aa])).then(chainWrite); };
    const sendUDP = (ip, port, data) => chainWrite(stunMsg(MT.SI,tid(),[stunAttr(AT.PEER,xorPeer(ip,port)),stunAttr(AT.DATA,data)]));
    const getIP = (h, p) => {
      const k=`${h}:${p}`, c=sess.get(k); if (c) return c.ip;
      const ft=fakeIPType(h); if (ft) for (const s of sess.values()) if (s.port===p&&s.isV6===(ft===6)) { const ns={ip:s.ip,host:h,port:p,isV6:s.isV6}; sess.set(k,ns); reverse[`${s.ip}:${p}`]=ns; return s.ip; }
      return null;
    };
    const resolveAsync = async (h, p, k) => { const ip=await resolveIP(h); if (ip) { const s={ip,host:h,port:p,isV6:ip.includes(':')}; sess.set(k,s); reverse[`${ip}:${p}`]=s; } };
    const processXUDP = data => {
      while (data.length>=6) {
        const f=parseXUDP(data); if (!f) break;
        if (f.network===2&&f.payload?.length&&f.host) {
          const k=`${f.host}:${f.port}`, ip=getIP(f.host,f.port);
          ip ? (ensurePerm(ip), sendUDP(ip, f.port, f.payload)) : sess.has(k)||resolveAsync(f.host,f.port,k);
        }
        data = data.subarray(f.totalLen);
      }
    };
    return { processXUDP, close };
  } catch { close(); return null; }
};

const ws = async (req, 当前备用地址, 携带SS通行证) => {
  const [client, server] = Object.values(new WebSocketPair());
  server.accept({ allowHalfOpen: true }); server.binaryType = 'arraybuffer';
  const fetcher = req.fetcher;
  const turn = getTurn(req.url);
  const edStr = req.headers.get('sec-websocket-protocol');
  let ed = null;
  try { if (edStr && edStr.length <= CFG.maxED*4/3+4) ed = Uint8Array.fromBase64(edStr,{alphabet:'base64url'}); } catch {}
  let curW=null, sock=null, udp=null, closed=false, busy=false;
  const uq = mkQ(CFG.upPack, CFG.upQMax, CFG.upQMax>>8);
  const wither = () => {
    if (closed) return; closed=true; uq.clear();
    try { curW?.releaseLock(); } catch {} try { sock?.close?.(); } catch {}
    try { udp?.close(); } catch {} try { server.close(); } catch {}
  };
  const toU8 = d => !d?new Uint8Array(0):d instanceof Uint8Array?d:ArrayBuffer.isView(d)?new Uint8Array(d.buffer,d.byteOffset,d.byteLength):new Uint8Array(d);
  const sow = d => { const u=toU8(d); if (!u.byteLength) return 1; if (uq.sow(u)) return 1; wither(); return 0; };

  const TURN_TIMEOUT = 3000;
  const tryConnect = async (host, port) => {
    if (turn) {
      let tTurn, cancelled = false;
      const bomb = new Promise(res => { tTurn = setTimeout(() => { cancelled = true; res(null); }, TURN_TIMEOUT); });
      const turnResult = await Promise.race([
        (async () => {
          const ip = /^\d+\.\d+\.\d+\.\d+$/.test(host) ? host : await resolveIP(host);
          if (!ip) return null;
          const ts = await turnConn(fetcher, turn, ip, port);
          if (cancelled && ts) { ts.close(); return null; }
          return ts;
        })(),
        bomb
      ]).finally(() => clearTimeout(tTurn));
      if (turnResult) return turnResult;
    }
    try { return await 带超时竞速(fetcher, host, port, 主连接超时毫秒); } catch {}
    const { 备用主机: h2, 备用端口: p2 } = 拆分地址和端口(当前备用地址, port);
    if (h2) try { return await 带超时竞速(fetcher, h2, p2, 备用连接超时毫秒); } catch {}
    if (当前备用地址 !== 默认备用小可爱地址) {
      const { 备用主机: h3, 备用端口: p3 } = 拆分地址和端口(默认备用小可爱地址, port);
      if (h3) try { return await 带超时竞速(fetcher, h3, p3, 备用连接超时毫秒); } catch {}
    }
    return null;
  };

  const thresh = async () => {
    if (busy||closed) return; busy=true;
    try {
      for (;;) {
        if (closed) break;
        if (!sock) {
          const [d] = uq.bundle(); if (!d) break;
          const r = parseHeader(d, 携带SS通行证); if (!r) { wither(); break; }
          if (r.isVless) server.send(new Uint8Array([d[0], 0]));
          const { host, port, offset, isUDP } = r;
          if (isUDP) {
            if (!turn) { wither(); break; }
            const sendWs = data => { try { server.send(data); } catch {} };
            udp = await turnUDP(fetcher, turn, sendWs);
            if (!udp) { wither(); break; }
            const ud = d.subarray(offset); ud.length && udp.processXUDP(ud);
            busy=false; !uq.empty && !closed && queueMicrotask(thresh); return;
          }
          sock = await tryConnect(host, port);
          if (!sock) { wither(); break; }
          curW = sock.writable.getWriter();
          const [first] = uq.bundle(d.subarray(offset));
          first?.byteLength && await curW.write(first);
          mill(sock.readable, server).finally(() => wither());
          continue;
        }
        const [d] = uq.bundle(); if (!d) break; await curW.write(d);
      }
    } catch { wither(); } finally { busy=false; !uq.empty && !closed && queueMicrotask(thresh); }
  };

  if (ed && sow(ed)) thresh();
  server.addEventListener('message', e => {
    if (closed) return;
    const chunk = toU8(e.data);
    if (udp) { udp.processXUDP(chunk); return; }
    sow(chunk) && thresh();
  });
  server.addEventListener('close', () => wither());
  server.addEventListener('error', () => wither());
  return new Response(null, { status: 101, webSocket: client, headers: { 'Sec-WebSocket-Extensions': '' } });
};

export default {
  async fetch(req, env) {
    if (req.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
      const 网址 = new URL(req.url);
      const 携带SS通行证 = 网址.pathname.includes(CFG.id);
      let 候选地址 = 默认备用小可爱地址;
      if (网址.searchParams.has('ip')) {
        候选地址 = 网址.searchParams.get('ip');
      } else {
        const 提取 = 网址.pathname.match(路径IP正则);
        if (提取) 候选地址 = decodeURIComponent(提取[1]);
      }
      _预热地址(候选地址);
      const 当前备用地址 = await 获取动态地址(候选地址);
      return ws(req, 当前备用地址, 携带SS通行证);
    }
    return new Response('Not Found', { status: 404 });
  }
};

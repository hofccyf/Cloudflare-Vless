const gch = new TextDecoder('utf-8');
const fai = new TextEncoder();
const gpx = new TextDecoder();
const qjj = '88888888-8888-8888-8888-888888888888';  //改成你自己的
const gul = ((uuid) => {
  const hex = uuid.replace(/-/g, '');
  const arr = new Uint8Array(16);
  for (let i = 0; i < 16; i++) arr[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return arr;
})(qjj);
const [SZ0, SZ1, SZ2, SZ3, SZ4, SZ5, SZ6, SZ7, SZ8, SZ9, SZ10, SZ11, SZ12, SZ13, SZ14, SZ15] = gul;
const afq = 'usip.vpndns.net';  //兜底落地IP，建议改成你自己的
const ipf       = 256 * 1024;
const fxw       = 192 * 1024;
const bgr       = 8;
const wyc       = 4 * 1024 * 1024;
const rvu     = 2000;
const fhc   = 4000;
const psb   = 16;
const zjo = 512;
const yic = 64 * 1024 * 1024;
const tou = /^[a-zA-Z0-9._\-:\[\]]+$/;
const tdm = /^\/ip=([^&\/]+)/;
const bjz = new Uint8Array([0, 0]);
function ogw(kxp) {
  if (kxp.length * 3 <= 123) return kxp;
  const encoded = fai.encode(kxp);
  if (encoded.byteLength <= 123) return kxp;
  let len = 123;
  while (len > 0 && (encoded[len] & 0xc0) === 0x80) len--;
  return gpx.decode(encoded.subarray(0, len));
}
function vhb(gyw) {
  if (
    !gyw ||
    gyw.length === 0 ||
    gyw.length > 253 ||
    gyw === '.' ||
    gyw === '[]' ||
    gyw === '..' ||
    gyw.startsWith('./') ||
    gyw.startsWith('../') ||
    gyw.startsWith(':') ||
    !tou.test(gyw)
  ) {
    return afq;
  }
  return gyw;
}
const txtyns = new Map();
const txtkyr = new Map();
const txtwir = 60 * 1000;
const txtfbq = 10 * 1000;
async function nai(qkz) {
  if (!qkz || (!qkz.includes('://') && !qkz.includes('/'))) {
    return vhb(qkz || afq);
  }
  const bgw = qkz.startsWith('http://') || qkz.startsWith('https://') ? qkz : 'https://' + qkz;
  const zvw = Date.now();
  const lur = txtyns.get(bgw);
  if (lur && zvw < lur.ati) return lur.ixu;
  if (txtkyr.has(bgw)) return txtkyr.get(bgw);
  const afn = (async () => {
    try {
      const ggq = await fetch(bgw, {
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
        cf: { cacheTtl: 60 }
      });
      if (ggq.ok) {
        let eyn = await ggq.text();
        eyn = eyn.replace(/[\r\n\s\uFEFF]/g, '');
        const ydd = vhb(eyn);
        if (ydd !== afq) {
          txtyns.set(bgw, { ixu: ydd, ati: Date.now() + txtwir });
          return ydd;
        }
        const zra = lur ? lur.ixu : afq;
        txtyns.set(bgw, { ixu: zra, ati: Date.now() + txtfbq });
        return zra;
      }
    } catch {}
    const sip = lur ? lur.ixu : afq;
    txtyns.set(bgw, { ixu: sip, ati: Date.now() + txtfbq });
    return sip;
  })().finally(() => txtkyr.delete(bgw));
  txtkyr.set(bgw, afn);
  return afn;
}
const _u16 = (b, o=0) => (b[o]<<8)|b[o+1];
const _pad4 = n => -n & 3;
const _cat = (...a) => { const r=new Uint8Array(a.reduce((s,x)=>s+x.length,0)); a.reduce((o,x)=>(r.set(x,o),o+x.length),0); return r; };
const _safeClose = (...a) => a.forEach(x => { try { x?.close?.(); } catch {} });
const _tid = () => crypto.getRandomValues(new Uint8Array(12));
const STUN_MAGIC = new Uint8Array([0x21,0x12,0xA4,0x42]);
const MT = { AQ:0x003,RQ:0x004,AO:0x103,AE:0x113,PQ:0x008,PO:0x108,CQ:0x00A,CO:0x10A,BQ:0x00B,BO:0x10B,SI:0x016,DI:0x017 };
const AT = { USER:0x006,MI:0x008,ERR:0x009,PEER:0x012,DATA:0x013,REALM:0x014,NONCE:0x015,TRANSPORT:0x019,CONNID:0x02A };
const _stunAttr = (t, v) => { const b=new Uint8Array(4+v.length+_pad4(v.length)),d=new DataView(b.buffer); d.setUint16(0,t); d.setUint16(2,v.length); b.set(v,4); return b; };
const _stunMsg = (t, id, a) => { const bd=_cat(...a),h=new Uint8Array(20),d=new DataView(h.buffer); d.setUint16(0,t); d.setUint16(2,bd.length); h.set(STUN_MAGIC,4); h.set(id,8); return _cat(h,bd); };
const _expandIPv6 = ip => { ip=ip.replace(/^\[|\]$/g,'').split('%')[0]; if (!ip.includes('::')) return ip.split(':').map(g=>g||'0'); const [l,r]=ip.split('::'); const lp=l?l.split(':'):[],rp=r?r.split(':'):[]; return [...lp,...Array(8-lp.length-rp.length).fill('0'),...rp]; };
const _xorPeer = (ip, port) => { const v6=ip.includes(':'),b=new Uint8Array(v6?20:8),dv=new DataView(b.buffer); b[1]=v6?2:1; dv.setUint16(2,port^0x2112); if(v6){const xk=new Uint8Array(16);xk.set(STUN_MAGIC);_expandIPv6(ip).forEach((g,i)=>{const v=parseInt(g||'0',16);b[4+i*2]=((v>>8)^xk[i*2])&0xff;b[5+i*2]=(v&0xff)^xk[i*2+1];});}else{ip.split('.').forEach((v,i)=>b[4+i]=+v^STUN_MAGIC[i]);}return b; };
const _parseStun = d => { if(d.length<20||STUN_MAGIC.some((v,i)=>d[4+i]!==v))return null; const dv=new DataView(d.buffer,d.byteOffset,d.byteLength),ml=dv.getUint16(2),attrs={}; for(let o=20;o+4<=20+ml;){const t=dv.getUint16(o),l=dv.getUint16(o+2);if(o+4+l>d.length)break;attrs[t]=d.slice(o+4,o+4+l);o+=4+l+_pad4(l);}return{type:dv.getUint16(0),attrs}; };
const _parseErr = d => d?.length>=4?(d[2]&7)*100+d[3]:0;
const _addIntegrity = async (m,key) => { const c=new Uint8Array(m),d=new DataView(c.buffer);d.setUint16(2,d.getUint16(2)+24);const k=await crypto.subtle.importKey('raw',key,{name:'HMAC',hash:'SHA-1'},false,['sign']);return _cat(c,_stunAttr(AT.MI,new Uint8Array(await crypto.subtle.sign('HMAC',k,c)))); };
const _md5 = async s => new Uint8Array(await crypto.subtle.digest('MD5',fai.encode(s)));
const _readStun = async (rd, buf) => { let b=buf??new Uint8Array(0); const pull=async()=>{const{done,value}=await rd.read();if(done)throw 0;b=_cat(b,new Uint8Array(value));}; try{while(b.length<20)await pull();const n=20+_u16(b,2);while(b.length<n)await pull();return[_parseStun(b.subarray(0,n)),b.length>n?b.subarray(n):null];}catch{return[null,null];}};
const _dnsCache = new Map();
const _resolveIP = async h => { if(/^\d+\.\d+\.\d+\.\d+$/.test(h))return h; if(h.includes(':'))return h.replace(/^\[|\]$/g,''); const now=Date.now(),c=_dnsCache.get(h);if(c&&now<c.exp)return c.ip; const doh=t=>fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(h)}&type=${t}`,{headers:{Accept:'application/dns-json'}}).then(r=>r.json()).catch(()=>({})); const[ra,raaaa]=await Promise.all([doh('A'),doh('AAAA')]); const ip=ra.Answer?.find(r=>r.type===1)?.data??raaaa.Answer?.find(r=>r.type===28)?.data??null; if(ip)_dnsCache.set(h,{ip,exp:Date.now()+30000}); return ip; };
const _getTurn = url => { let u;try{u=decodeURIComponent(url);}catch{return null;} const m=u.match(/\/turn:\/\/([^?\s]*)/i);if(!m)return null; const t=m[1],at=t.lastIndexOf('@'),cred=at>=0?t.slice(0,at):'',hp=t.slice(at+1); let host,portStr; if(hp.startsWith('[')){const e=hp.indexOf(']');if(e===-1)return null;host=hp.slice(0,e+1);portStr=hp.slice(e+2);}else{const ci=hp.lastIndexOf(':');host=ci>=0?hp.slice(0,ci):hp;portStr=ci>=0?hp.slice(ci+1):'';}; const port=+portStr;if(!port||port<1||port>65535)return null; const ci=cred.indexOf(':');return{host,port,user:ci>=0?cred.slice(0,ci):'',pass:ci>=0?cred.slice(ci+1):''}; };
const _turnAuth = async (w,r,transport,{user,pass},pipeline) => { const tp=new Uint8Array([transport,0,0,0]);await w.write(_stunMsg(MT.AQ,_tid(),[_stunAttr(AT.TRANSPORT,tp)]));let[msg,ex]=await _readStun(r);if(!msg)return null;let key=null,aa=[];const sign=m=>key?_addIntegrity(m,key):Promise.resolve(m);if(msg.type===MT.AE&&user&&_parseErr(msg.attrs[AT.ERR])===401){const realm=gpx.decode(msg.attrs[AT.REALM]??new Uint8Array(0)),nonce=msg.attrs[AT.NONCE]??new Uint8Array(0);key=await _md5(`${user}:${realm}:${pass}`);aa=[_stunAttr(AT.USER,fai.encode(user)),_stunAttr(AT.REALM,fai.encode(realm)),_stunAttr(AT.NONCE,nonce)];const aq=await _addIntegrity(_stunMsg(MT.AQ,_tid(),[_stunAttr(AT.TRANSPORT,tp),...aa]),key);const extras=pipeline?await Promise.all(pipeline(aa,sign)):[];await w.write(extras.length?_cat(aq,...extras):aq);[msg,ex]=await _readStun(r,ex);if(!msg)return null;}else if(pipeline&&msg.type===MT.AO){const extras=await Promise.all(pipeline(aa,sign));if(extras.length)await w.write(_cat(...extras));}return msg.type===MT.AO?{key,aa,ex,sign}:null; };
const _turnConn = async (fetcher, turn, targetIp, targetPort) => {
  let ctrl=null,data=null;
  const close=()=>_safeClose(ctrl,data);
  try {
    ctrl=await fetcher.connect({hostname:turn.host,port:turn.port});
    await ctrl.opened;
    const cw=ctrl.writable.getWriter(),cr=ctrl.readable.getReader();
    const peer=_stunAttr(AT.PEER,_xorPeer(targetIp,targetPort));
    const dataSocket=fetcher.connect({hostname:turn.host,port:turn.port});
    const auth=await _turnAuth(cw,cr,6,turn,(aa,sign)=>[sign(_stunMsg(MT.PQ,_tid(),[peer,...aa])),sign(_stunMsg(MT.CQ,_tid(),[peer,...aa]))]);
    if(!auth){try{cw.releaseLock();}catch{}try{cr.releaseLock();}catch{}close();return null;}
    const{aa,sign}=auth;let ex=auth.ex;
    let r;
    [r,ex]=await _readStun(cr,ex);if(r?.type!==MT.PO){try{cr.releaseLock();}catch{}try{cw.releaseLock();}catch{}close();return null;}
    [r,ex]=await _readStun(cr,ex);if(r?.type!==MT.CO||!r.attrs[AT.CONNID]){try{cr.releaseLock();}catch{}try{cw.releaseLock();}catch{}close();return null;}
    try{await dataSocket.opened;}catch{_safeClose(dataSocket);try{cr.releaseLock();}catch{}try{cw.releaseLock();}catch{}close();return null;}
    data=dataSocket;
    const dw=data.writable.getWriter(),dr=data.readable.getReader();
    await dw.write(await sign(_stunMsg(MT.BQ,_tid(),[_stunAttr(AT.CONNID,r.attrs[AT.CONNID]),...aa])));
    let extra;[r,extra]=await _readStun(dr);if(r?.type!==MT.BO){try{dw.releaseLock();}catch{}try{dr.releaseLock();}catch{}try{cr.releaseLock();}catch{}try{cw.releaseLock();}catch{}close();return null;}
    cr.releaseLock();cw.releaseLock();dw.releaseLock();
    let keepAliveDead=false;
    const closeAll=()=>{keepAliveDead=true;close();};
    const ctrlW=ctrl.writable.getWriter();
    (async()=>{try{const rd=ctrl.readable.getReader();while(!(await rd.read()).done);}catch{}})();
    (async()=>{try{for(;;){await new Promise(res=>setTimeout(res,270000));if(keepAliveDead)break;await ctrlW.write(_cat(await sign(_stunMsg(MT.RQ,_tid(),aa)),await sign(_stunMsg(MT.PQ,_tid(),[peer,...aa]))));}}catch{}})();
    const readable=new ReadableStream({
      type:'bytes',
      start(c){if(extra?.length)c.enqueue(extra.slice());},
      async pull(c){const bv=c.byobRequest?.view;if(bv){const{done,value}=await dr.read();if(done){c.close();c.byobRequest.respond(0);return;}const v=new Uint8Array(value),n=Math.min(v.byteLength,bv.byteLength);new Uint8Array(bv.buffer,bv.byteOffset,n).set(v.subarray(0,n));c.byobRequest.respond(n);if(n<v.byteLength)c.enqueue(v.subarray(n).slice());}else{const{done,value}=await dr.read();if(done){c.close();return;}c.enqueue(new Uint8Array(value));}},
      cancel(){dr.cancel();}
    });
    return{readable,writable:data.writable,close:closeAll};
  }catch{close();return null;}
};
const _parseXorPeer = d => {
  if (!d?.length || d.length < 8) return ['', 0];
  const port = _u16(d,2) ^ 0x2112;
  if (d[1] === 2 && d.length >= 20) {
    const xk = new Uint8Array(16); xk.set(STUN_MAGIC);
    const segs = Array.from({length:8}, (_,i) => ((d[4+i*2]^xk[i*2])<<8|(d[5+i*2]^xk[i*2+1])).toString(16));
    return [segs.join(':'), port];
  }
  return [STUN_MAGIC.map((m,i) => d[4+i]^m).join('.'), port];
};
const _encodeAddr = h => {
  const s = h.replace(/^\[|\]$/g,''), m = s.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (m) return new Uint8Array([0x01, ...m.slice(1).map(Number)]);
  if (s.includes(':')) {
    const b = new Uint8Array(17); b[0] = 0x03;
    _expandIPv6(s).forEach((x,i) => { const v=parseInt(x||'0',16); b[1+i*2]=v>>8; b[2+i*2]=v&0xff; });
    return b;
  }
  const e = fai.encode(h);
  return _cat(new Uint8Array([0x02, e.length]), e);
};
const _xudpAddr = d => {
  if (!d.length) return ['', 0];
  if (d[0] <= 1) return d.length >= 5 ? [d.subarray(1,5).join('.'), 5] : ['', 0];
  if (d[0] === 2) return d.length >= 2+d[1] ? [gch.decode(d.subarray(2, 2+d[1])), 2+d[1]] : ['', 0];
  return d[0]===3 && d.length>=17 ? [`[${Array.from({length:8},(_,i)=>_u16(d,1+i*2).toString(16)).join(':')}]`, 17] : ['', 0];
};
const _fakeIPType = h => {
  const m = h.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  return m && +m[1]===198 && [18,19].includes(+m[2]) ? 4
    : h.replace(/^\[|\]$/g,'').startsWith('fc') && h.includes(':') ? 6 : 0;
};
const _parseXUDP = d => {
  if (d.length < 6) return null;
  const metaLen = _u16(d), metaEnd = 2 + metaLen;
  if (metaLen < 4 || metaEnd > d.length) return null;
  const f = {
    network: metaEnd > 6 ? d[6] : 0,
    port: metaEnd >= 9 ? _u16(d, 7) : 0,
    host: metaEnd > 9 ? _xudpAddr(d.subarray(9, metaEnd))[0] : '',
    payload: null, totalLen: metaEnd
  };
  if ((d[5] & 1) && metaEnd + 2 <= d.length) {
    const pLen = _u16(d, metaEnd);
    if (metaEnd + 2 + pLen <= d.length) { f.payload = d.subarray(metaEnd+2, metaEnd+2+pLen); f.totalLen = metaEnd+2+pLen; }
  }
  return f;
};
const _xudpResp = (host, port, payload) => {
  const a = _encodeAddr(host), ml = 7 + a.length;
  const buf = new Uint8Array(2 + ml + 2 + payload.length);
  buf[0]=ml>>8; buf[1]=ml&0xff; buf[4]=2; buf[5]=1; buf[6]=2; buf[7]=port>>8; buf[8]=port&0xff;
  buf.set(a, 9);
  const pOff = 2 + ml;
  buf[pOff]=payload.length>>8; buf[pOff+1]=payload.length&0xff;
  buf.set(payload, pOff+2);
  return buf;
};
const TURN_TIMEOUT = 3000;
const _turnUDP = async (fetcher, turn, sendWs) => {
  let sock = null, closed = false;
  const perms = new Set(), sess = new Map(), reverse = {};
  let _udpW = null;
  const close = () => { closed=true; try{_udpW?.releaseLock();}catch{} _safeClose(sock); };
  try {
    sock = fetcher.connect({ hostname: turn.host, port: turn.port });
    await sock.opened;
    const w = (_udpW = sock.writable.getWriter()), r = sock.readable.getReader();
    const auth = await _turnAuth(w, r, 17, turn);
    if (!auth) { try{w.releaseLock();}catch{} try{r.releaseLock();}catch{} _udpW=null; close(); return null; }
    const { aa, sign } = auth; let buf = auth.ex;
    (async () => {
      try {
        while (!closed) {
          const [m, nx] = await _readStun(r, buf); buf = nx; if (!m) break;
          if (m.type === MT.DI && m.attrs[AT.PEER] && m.attrs[AT.DATA]) {
            const [ip, pt] = _parseXorPeer(m.attrs[AT.PEER]);
            const s = reverse[`${ip}:${pt}`];
            sendWs(_xudpResp(s?.host ?? ip, s?.port ?? pt, m.attrs[AT.DATA]));
          }
        }
      } finally { try { r.releaseLock(); } catch {} }
    })();
    let wChain = Promise.resolve();
    const chainWrite = msg => { if (closed) return; wChain = wChain.then(() => closed ? Promise.resolve() : w.write(msg).catch(()=>{})); };
    (async () => {
      try {
        while (!closed) {
          await new Promise(res => setTimeout(res, 240000));
          if (closed) break;
          chainWrite(await sign(_stunMsg(MT.RQ, _tid(), aa)));
          for (const ip of perms) chainWrite(await sign(_stunMsg(MT.PQ, _tid(), [_stunAttr(AT.PEER, _xorPeer(ip, 0)), ...aa])));
        }
      } catch {}
    })();
    const ensurePerm = ip => {
      if (perms.has(ip)) return; perms.add(ip);
      sign(_stunMsg(MT.PQ, _tid(), [_stunAttr(AT.PEER, _xorPeer(ip, 0)), ...aa])).then(chainWrite);
    };
    const sendUDP = (ip, port, data) => chainWrite(_stunMsg(MT.SI, _tid(), [_stunAttr(AT.PEER, _xorPeer(ip, port)), _stunAttr(AT.DATA, data)]));
    const getIP = (h, p) => {
      const k = `${h}:${p}`, c = sess.get(k); if (c) return c.ip;
      const ft = _fakeIPType(h);
      if (ft) for (const s of sess.values()) if (s.port===p && s.isV6===(ft===6)) {
        const ns = {ip:s.ip, host:h, port:p, isV6:s.isV6}; sess.set(k,ns); reverse[`${s.ip}:${p}`]=ns; return s.ip;
      }
      return null;
    };
    const resolveAsync = async (h, p, k) => {
      const ip = await _resolveIP(h);
      if (ip) { const s={ip, host:h, port:p, isV6:ip.includes(':')}; sess.set(k,s); reverse[`${ip}:${p}`]=s; }
    };
    const processXUDP = data => {
      while (data.length >= 6) {
        const f = _parseXUDP(data); if (!f) break;
        if (f.network === 2 && f.payload?.length && f.host) {
          const k = `${f.host}:${f.port}`, ip = getIP(f.host, f.port);
          ip ? (ensurePerm(ip), sendUDP(ip, f.port, f.payload)) : (sess.has(k) || resolveAsync(f.host, f.port, k));
        }
        data = data.subarray(f.totalLen);
      }
    };
    return { processXUDP, close };
  } catch { close(); return null; }
};
export default {
  async fetch(kxl, env) {
    const lpr = kxl.headers.get('Upgrade');
    if (lpr && lpr.toLowerCase() === 'websocket') {
      const hio = new URL(kxl.url);
      const cqu = hio.pathname.includes(qjj);
      const wge = kxl.headers.get('sec-websocket-protocol');
      let zez = null;
      if (wge) {
        try {
          zez = ftr(wge);
        } catch {}
      }
      let gyw = afq;
      if (hio.searchParams.has('ip')) {
        gyw = hio.searchParams.get('ip') || afq;
      } else {
        const gne = hio.pathname.match(tdm);
        if (gne) gyw = decodeURIComponent(gne[1]);
      }
      const qpd = await nai(gyw);
      const turnsmg = _getTurn(kxl.url);
      return cwp(kxl.fetcher, qpd, cqu, zez, turnsmg);
    }
    return new Response('OK', { status: 200 });
  },
};
const _b64rke = (() => {
  const t = new Uint8Array(128);
  const _chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  for (let i = 0; i < 64; i++) t[_chars.charCodeAt(i)] = i;
  t['-'.charCodeAt(0)] = 62;
  t['_'.charCodeAt(0)] = 63;
  return t;
})();
function ftr(str) {
  const xqh = str.replace(/=/g, '');
  const hch = xqh.length;
  const gkr = (hch * 3 >> 2) - (str.endsWith('==') ? 2 : str.endsWith('=') ? 1 : 0);
  const ucl = new Uint8Array(gkr);
  let mlf = 0;
  const _lookup = (idx) => { const cc = xqh.charCodeAt(idx); return cc < 128 ? (_b64rke[cc] ?? 0) : 0; };
  for (let i = 0; i < hch; i += 4) {
    const a = _lookup(i);
    const b = _lookup(i + 1);
    const c = i + 2 < hch ? _lookup(i + 2) : 0;
    const d = i + 3 < hch ? _lookup(i + 3) : 0;
    const n = (a << 18) | (b << 12) | (c << 6) | d;
    if (mlf < gkr) ucl[mlf++] = n >> 16;
    if (mlf < gkr) ucl[mlf++] = (n >> 8) & 0xff;
    if (mlf < gkr) ucl[mlf++] = n & 0xff;
  }
  return ucl;
}
function cwp(fetcher, qpd, cqu, zez, turnsmg) {
  const fag = new WebSocketPair();
  const xov = fag[0];
  const mwb = fag[1];
  mwb.accept({ allowHalfOpen: true });
  mwb.binaryType = 'arraybuffer';
  kbj(fetcher, mwb, qpd, cqu, zez, turnsmg).catch((e) => { console.error('[bri]', e); });
  return new Response(null, {
    status: 101,
    webSocket: xov,
    headers: { 'Sec-WebSocket-Extensions': '' }
  });
}
async function kbj(fetcher, mwb, qpd, cqu, zez, turnsmg) {
  let sie;
  let eyc = false;
  let kpn;
  let udpRelay = null;
  const wsmxu = new ReadableStream({
    start(c) { kpn = c; },
    cancel(reason) { yuw(1011, reason?.message ?? 'stream cancelled'); },
  }, new ByteLengthQueuingStrategy({ highWaterMark: wyc }));
  let qpe;
  let ncb;
  const uec = new Promise((resolve, reject) => {
    qpe = resolve;
    ncb = reject;
  });
  let mfk = null;
  function yuw(kto = 1011, kxp = 'hik', WSwkq = false) {
    if (eyc) return;
    eyc = true;
    udpRelay?.close();
    if (!WSwkq) {
      try { mwb.close(kto, ogw(kxp)); } catch {}
    }
    if (kto !== 1000 || ncb) {
      const nyc = new Error(kxp);
      try { kpn?.error(nyc); } catch {}
      try { ncb?.(nyc); } catch {}
    }
    try { mfk?.abort(); } catch {}
    try { sie?.close?.(); } catch {}
  }
  async function xwh(sbk, dgs, abw) {
    if (eyc) throw new Error('trf');
    let gyl;
    const nvo = fetcher.connect({ hostname: sbk, port: dgs });
    nvo.opened.catch(() => {});
    const blz = new Promise((_, reject) => {
      gyl = setTimeout(() => reject(new Error('gdx')), abw);
    });
    try {
      await Promise.race([nvo.opened, blz]);
      return nvo;
    } catch (swt) {
      try { nvo.close(); } catch {}
      throw swt;
    } finally {
      clearTimeout(gyl);
    }
  }
  mwb.addEventListener('close', () => yuw(1000, 'was', true));
  mwb.addEventListener('error', () => yuw(1011, 'WSkqf', true));
  let ggo = true;
  let lfo = false;
  const srz = [];
  let ofp = 0;
  let gfy = 0;
  const fdy = () => {
    if (eyc || lfo) return;
    lfo = true;
    (async () => {
      let psf = 1;
      while (gfy < srz.length) {
        if (eyc) break;
        const yfs = srz[gfy++];
        ofp = Math.max(0, ofp - yfs.byteLength);
        if (gfy >= 64) {
          srz.splice(0, gfy);
          gfy = 0;
        }
        try {
          if (ggo) {
            ggo = false;
            await vau(yfs);
          } else {
            if (udpRelay) {
              udpRelay.processXUDP(yfs);
            } else {
              while (kpn.desiredSize !== null && kpn.desiredSize <= 0) {
                if (eyc) break;
                await new Promise((r) => setTimeout(r, psf));
                psf = Math.min(psf * 2, psb);
              }
              psf = 1;
              if (eyc) break;
              try {
                kpn.enqueue(yfs);
              } catch {
                yuw(1011, 'xvc');
                break;
              }
            }
          }
        } catch {
          if (!eyc) yuw(1011, 'zqo');
          break;
        }
      }
      srz.length = 0;
      gfy = 0;
      ofp = 0;
      lfo = false;
    })().catch(() => {
      srz.length = 0;
      gfy = 0;
      ofp = 0;
      lfo = false;
      if (!eyc) yuw(1011, 'lyw');
    });
  };
  if (zez && zez.byteLength > 0) {
    srz.push(zez);
    ofp += zez.byteLength;
    fdy();
  }
  mwb.addEventListener('message', (xtm) => {
    if (eyc) return;
    if (typeof xtm.data === 'string') {
      yuw(1008, 'sfi');
      return;
    }
    const okf = xtm.data instanceof ArrayBuffer ? new Uint8Array(xtm.data) : new Uint8Array(xtm.data.buffer, xtm.data.byteOffset, xtm.data.byteLength);
    const qiv = okf.byteLength;
    if (
      srz.length >= zjo ||
      ofp + qiv > yic
    ) {
      yuw(1011, 'ayw');
      return;
    }
    srz.push(okf);
    ofp += qiv;
    fdy();
  });
  async function vau(uqg) {
    const oah = uqg.buffer;
    const zbf = uqg.byteOffset;
    const lha = uqg.byteLength;
    const tnq = new DataView(oah, zbf, lha);
    if (lha < 7) { yuw(1008, 'llm'); return; }
    const hzp = tnq.getUint8(0);
    let ixu = '';
    let gpq = 0;
    let ndf = 0;
    let isVlessUDP = false;
    if (hzp === 0) {
      if (lha < 24) { yuw(1008, 'llm'); return; }
      if (!lkh(tnq, 1)) { yuw(1008, 'zql'); return; }
      const gcl = tnq.getUint8(17);
      const cmdkhd = 18 + gcl;
      if (cmdkhd >= lha) { yuw(1008, 'llm'); return; }
      const cmd = tnq.getUint8(cmdkhd);
      if (cmd !== 1 && cmd !== 3) { yuw(1008, 'usn'); return; }
      isVlessUDP = (cmd === 3);
      const epr = cmdkhd + 1;
      if (epr + 2 > lha) { yuw(1008, 'llm'); return; }
      gpq = tnq.getUint16(epr);
      if (gpq === 0) { yuw(1008, 'cki'); return; }
      const znz = epr + 2;
      if (znz >= lha) { yuw(1008, 'llm'); return; }
      const eyw = tnq.getUint8(znz);
      let rng = 0;
      let fgy = znz + 1;
      switch (eyw) {
        case 1:
          if (fgy + 4 > lha) { yuw(1008, 'llm'); return; }
          rng = 4;
          ixu = `${tnq.getUint8(fgy)}.${tnq.getUint8(fgy + 1)}.${tnq.getUint8(fgy + 2)}.${tnq.getUint8(fgy + 3)}`;
          break;
        case 2:
          if (fgy >= lha) { yuw(1008, 'llm'); return; }
          rng = tnq.getUint8(fgy);
          if (rng === 0) { yuw(1008, 'hit'); return; }
          if (rng > 253) { yuw(1008, 'vgu'); return; }
          fgy += 1;
          if (fgy + rng > lha) { yuw(1008, 'llm'); return; }
          try {
            ixu = gch.decode(new Uint8Array(oah, zbf + fgy, rng));
          } catch {
            yuw(1008, 'qcl');
            return;
          }
          break;
        case 3: {
          if (fgy + 16 > lha) { yuw(1008, 'llm'); return; }
          rng = 16;
          const b = fgy;
          ixu =
            tnq.getUint16(b).toString(16) + ':' +
            tnq.getUint16(b + 2).toString(16) + ':' +
            tnq.getUint16(b + 4).toString(16) + ':' +
            tnq.getUint16(b + 6).toString(16) + ':' +
            tnq.getUint16(b + 8).toString(16) + ':' +
            tnq.getUint16(b + 10).toString(16) + ':' +
            tnq.getUint16(b + 12).toString(16) + ':' +
            tnq.getUint16(b + 14).toString(16);
          break;
        }
        default:
          yuw(1008, 'vqw');
          return;
      }
      ndf = fgy + rng;
      try { mwb.send(bjz); } catch {}
    } else if (hzp === 1 || hzp === 3 || hzp === 4) {
      if (!cqu) { yuw(1008, 'qah'); return; }
      switch (hzp) {
        case 1:
          if (lha < 7) { yuw(1008, 'SS-V4iws'); return; }
          ixu = `${tnq.getUint8(1)}.${tnq.getUint8(2)}.${tnq.getUint8(3)}.${tnq.getUint8(4)}`;
          gpq = tnq.getUint16(5);
          ndf = 7;
          break;
        case 3: {
          const vhr = tnq.getUint8(1);
          if (vhr === 0) { yuw(1008, 'SS-qgm'); return; }
          if (lha < 4 + vhr) { yuw(1008, 'SS-zvz'); return; }
          try {
            ixu = gch.decode(new Uint8Array(oah, zbf + 2, vhr));
          } catch {
            yuw(1008, 'SS-qcl');
            return;
          }
          gpq = tnq.getUint16(2 + vhr);
          ndf = 4 + vhr;
          break;
        }
        case 4: {
          if (lha < 19) { yuw(1008, 'SS-V6iws'); return; }
          ixu = [
            tnq.getUint16(1).toString(16), tnq.getUint16(3).toString(16),
            tnq.getUint16(5).toString(16), tnq.getUint16(7).toString(16),
            tnq.getUint16(9).toString(16), tnq.getUint16(11).toString(16),
            tnq.getUint16(13).toString(16), tnq.getUint16(15).toString(16),
          ].join(':');
          gpq = tnq.getUint16(17);
          ndf = 19;
          break;
        }
        default:
          yuw(1008, 'xck');
          return;
      }
    } else {
      yuw(1008, 'xck');
      return;
    }
    if (gpq === 0 || ndf > lha) { yuw(1008, 'wob'); return; }
    const omu = lha - ndf;
    if (isVlessUDP) {
      if (!turnsmg) { yuw(1008, 'gsa TURN pff UDP'); return; }
      const send = d => { try { mwb.send(d); } catch {} };
      udpRelay = await _turnUDP(fetcher, turnsmg, send);
      if (!udpRelay) { yuw(1011, 'TURN UDP relay vsp'); return; }
      if (omu > 0) udpRelay.processXUDP(new Uint8Array(oah, zbf + ndf, omu));
      return;
    }
    const tryConnect = async () => {
      if (turnsmg) {
        let _t, _cancelled = false;
        const bomb = new Promise(res => { _t = setTimeout(() => { _cancelled = true; res(null); }, TURN_TIMEOUT); });
        const result = await Promise.race([
          (async () => {
            const ip = await _resolveIP(ixu);
            if (!ip) return null;
            const ts = await _turnConn(fetcher, turnsmg, ip, gpq);
            if (_cancelled && ts) { ts.close(); return null; }
            return ts;
          })(),
          bomb
        ]).finally(() => clearTimeout(_t));
        if (result) return result;
      }
      try { return await xwh(ixu, gpq, rvu); } catch {}
      try {
        const { gcu, wxf } = sej(qpd, gpq);
        if (gcu) return await xwh(gcu, wxf, fhc);
      } catch {}
      if (qpd !== afq) {
        try {
          const { gcu, wxf } = sej(afq, gpq);
          if (gcu) return await xwh(gcu, wxf, fhc);
        } catch {}
      }
      return null;
    };
    const huf = await tryConnect();
    if (!huf || eyc) {
      if (huf) try { huf.close(); } catch {}
      yuw(1011, 'kfz');
      return;
    }
    sie = huf;
    if (eyc) return;
    if (omu > 0) {
      try { kpn.enqueue(new Uint8Array(oah, zbf + ndf, omu).slice()); } catch {}
    }
    qpe();
  }
  try {
    await uec;
  } catch {
    return;
  }
  if (eyc) return;
  qpe = null;
  ncb = null;
  mfk = new AbortController();
  const { signal: afi } = mfk;
  await Promise.all([
    wsmxu.pipeTo(sie.writable, { signal: afi }).catch((e) => {
      if (e?.name !== 'AbortError') yuw(1011, 'xps→TCPjaj');
    }),
    sie.readable.pipeTo(
      ywe(mwb, ipf, fxw, bgr),
      { signal: afi },
    ).catch((e) => {
      if (e?.name !== 'AbortError') yuw(1011, 'TCP→WStwy');
    }),
  ]).catch(() => {});
  if (!eyc) yuw(1000, 'coh');
}
function ywe(mwb, pdd, tol, mbt) {
  const cww = [];
  let kyz = 0;
  let rat = null;
  let pnw = new Uint8Array(pdd);
  function otb() {
    if (rat) { clearTimeout(rat); rat = null; }
    if (cww.length === 0) return;
    if (mwb.readyState !== 1) {
      cww.length = 0;
      kyz = 0;
      return;
    }
    let ecn;
    if (cww.length === 1) {
      ecn = cww[0].slice();
    } else {
      if (kyz > pnw.byteLength) {
        pnw = new Uint8Array(Math.max(pdd, kyz * 2));
      } else if (kyz < pnw.byteLength >> 2 && pnw.byteLength > pdd) {
        pnw = new Uint8Array(Math.max(pdd, kyz));
      }
      let wzh = 0;
      for (const lai of cww) {
        pnw.set(lai, wzh);
        wzh += lai.byteLength;
      }
      ecn = pnw.subarray(0, kyz).slice();
    }
    cww.length = 0;
    kyz = 0;
    try { mwb.send(ecn); } catch {}
  }
  return new WritableStream({
    write(chunk) {
      cww.push(chunk);
      kyz += chunk.byteLength;
      if (kyz >= tol) {
        otb();
      } else if (!rat) {
        rat = setTimeout(otb, mbt);
      }
    },
    flush() { otb(); },
    abort() {
      if (rat) { clearTimeout(rat); rat = null; }
      cww.length = 0;
      kyz = 0;
    },
  }, new ByteLengthQueuingStrategy({ highWaterMark: pdd }));
}
function sej(ose, fvl) {
  function wje(dgs) {
    return Number.isInteger(dgs) && dgs >= 1 && dgs <= 65535 ? dgs : fvl;
  }
  if (ose.startsWith('[')) {
    const nko = ose.indexOf(']');
    if (nko === -1) return { gcu: ose, wxf: fvl };
    const gcu = ose.slice(0, nko + 1);
    const zpy = ose.slice(nko + 1);
    return {
      gcu,
      wxf: wje(zpy.startsWith(':') ? Number(zpy.slice(1)) : fvl),
    };
  }
  const trj = ose.lastIndexOf(':');
  if (trj === -1) return { gcu: ose, wxf: fvl };
  if (ose.indexOf(':') !== trj) return { gcu: ose, wxf: fvl };
  return {
    gcu: ose.slice(0, trj),
    wxf: wje(Number(ose.slice(trj + 1))),
  };
}
function lkh(tnq, offset = 0) {
  return tnq.getUint8(offset) === SZ0 &&
    tnq.getUint8(offset + 1) === SZ1 &&
    tnq.getUint8(offset + 2) === SZ2 &&
    tnq.getUint8(offset + 3) === SZ3 &&
    tnq.getUint8(offset + 4) === SZ4 &&
    tnq.getUint8(offset + 5) === SZ5 &&
    tnq.getUint8(offset + 6) === SZ6 &&
    tnq.getUint8(offset + 7) === SZ7 &&
    tnq.getUint8(offset + 8) === SZ8 &&
    tnq.getUint8(offset + 9) === SZ9 &&
    tnq.getUint8(offset + 10) === SZ10 &&
    tnq.getUint8(offset + 11) === SZ11 &&
    tnq.getUint8(offset + 12) === SZ12 &&
    tnq.getUint8(offset + 13) === SZ13 &&
    tnq.getUint8(offset + 14) === SZ14 &&
    tnq.getUint8(offset + 15) === SZ15;
}

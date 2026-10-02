const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const {PORT=3000,RESEND_API_KEY,FROM_EMAIL,SESSION_SECRET}=process.env;
if(!RESEND_API_KEY||!FROM_EMAIL||!SESSION_SECRET){console.error('Set RESEND_API_KEY, FROM_EMAIL and SESSION_SECRET (see .env.example)');process.exit(1)}
const otps=new Map(),hits=new Map(),EMAIL=/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const h=(...a)=>crypto.createHmac('sha256',SESSION_SECRET).update(a.join('|')).digest('hex');
const limited=(k,max,win)=>{const n=Date.now(),l=(hits.get(k)||[]).filter(t=>n-t<win);if(l.length>=max){hits.set(k,l);return true}l.push(n);hits.set(k,l);return false};
const out=(res,c,o)=>{res.writeHead(c,{'Content-Type':'application/json'});res.end(JSON.stringify(o))};
const body=req=>new Promise(r=>{let d='';req.on('data',c=>{d+=c;if(d.length>5e3)req.destroy()});req.on('end',()=>{try{r(JSON.parse(d))}catch{r({})}})});
const sign=p=>{const b=Buffer.from(JSON.stringify(p)).toString('base64url');return b+'.'+h('s',b)};
const read=t=>{try{const[b,s]=(t||'').split('.');if(!crypto.timingSafeEqual(Buffer.from(h('s',b)),Buffer.from(s)))return null;const p=JSON.parse(Buffer.from(b,'base64url'));return p.exp>Date.now()?p:null}catch{return null}};
setInterval(()=>{const n=Date.now();for(const[k,v]of otps)if(v.exp<n)otps.delete(k)},6e5);
http.createServer(async(req,res)=>{
const u=req.url.split('?')[0],ip=(req.headers['x-forwarded-for']||req.socket.remoteAddress||'').split(',')[0].trim();
if(req.method==='GET'&&(u==='/'||u==='/index.html')){res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});return fs.createReadStream(path.join(__dirname,'index.html')).pipe(res)}
if(req.method==='POST'&&u==='/api/otp/send'){
const{email='',mobile=''}=await body(req),e=String(email).trim().toLowerCase();
if(!EMAIL.test(e)||e.length>120)return out(res,400,{error:'Enter a valid email address'});
if(!/^[6-9]\d{9}$/.test(String(mobile)))return out(res,400,{error:'Enter a valid 10-digit mobile number'});
const old=otps.get(e);if(old&&Date.now()-old.sent<30000)return out(res,429,{error:'Please wait 30 seconds before requesting another code'});
if(limited('e:'+e,5,36e5)||limited('i:'+ip,20,36e5))return out(res,429,{error:'Too many requests. Try again later.'});
const code=String(crypto.randomInt(100000,1000000));
const r=await fetch('https://api.resend.com/emails',{method:'POST',headers:{Authorization:'Bearer '+RESEND_API_KEY,'Content-Type':'application/json'},body:JSON.stringify({from:FROM_EMAIL,to:[e],subject:'Your ShopKart verification code',html:`<p>Your ShopKart code is <b style="font-size:22px;letter-spacing:3px">${code}</b></p><p>It expires in 10 minutes. If you didn't request it, you can ignore this email.</p>`})}).catch(()=>null);
if(!r||!r.ok)return out(res,502,{error:'Could not send the email. Please try again.'});
otps.set(e,{hash:h('o',e,code),exp:Date.now()+6e5,tries:0,sent:Date.now(),mobile:String(mobile)});
return out(res,200,{ok:true})}
if(req.method==='POST'&&u==='/api/otp/verify'){
const{email='',otp=''}=await body(req),e=String(email).trim().toLowerCase(),o=otps.get(e);
if(!o||o.exp<Date.now()){otps.delete(e);return out(res,400,{error:'Code expired. Request a new one.'})}
if(++o.tries>5){otps.delete(e);return out(res,429,{error:'Too many attempts. Request a new code.'})}
if(!crypto.timingSafeEqual(Buffer.from(h('o',e,String(otp))),Buffer.from(o.hash)))return out(res,400,{error:'Incorrect OTP'});
otps.delete(e);
return out(res,200,{ok:true,email:e,mobile:o.mobile,token:sign({e,m:o.mobile,exp:Date.now()+30*864e5})})}

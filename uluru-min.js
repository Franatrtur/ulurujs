/*
Copyright (c) 2021 Franatrtur

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
*/
!function(t,e){if("undefined"!=typeof global)module.exports=t;else if("undefined"!=typeof globalThis)globalThis.Uluru=t;else{if("undefined"==typeof window)throw"No global context found";window.Uluru=t}}(function(){const t=Uint8Array,e=Uint32Array;class s{encode(e){let s=new t(e.length);for(let t=0,i=e.length;t<i;t++)s[t]=e.charCodeAt(t);return s}decode(t){return String.fromCharCode(...t)}}class i{encode(t){return"function"==typeof TextEncoder?(new TextEncoder).encode(t):(new s).encode(unescape(encodeURIComponent(t)))}decode(t){return"function"==typeof TextDecoder?new TextDecoder("utf8").decode(t):decodeURIComponent(escape((new s).decode(t)))}}const n=Array(256),h={};let a;for(let t=0;t<256;t++)a=("00"+t.toString(16)).slice(-2),n[t]=a,h[a]=t;class r{encode(e){let s=new t(e.length>>1);for(let t=0,i=e.length;t<i;t+=2)s[t>>1]=h[e.slice(t,t+2)];return s}decode(t){let e=[];for(let s=0,i=t.length;s<i;s++)e.push(n[t[s]]);return e.join("")}}class o{encode(t){return(new s).encode(atob(t))}decode(t){return btoa((new s).decode(t))}}const c=new e((new s).encode("expand 32-byte k").buffer);class d{reset(){this.xstate=new e(16),this.pmac=!!this.domac&&new e(c),this.cmac=!!this.domac&&new e(c),this.data=new e(0),this.pointer=0,this.sigbytes=0}constructor(t,s=!0,i=0,n=0){this.state=new e(16);let h=this.state;h.set(c),h.set(new e(t.buffer),4),h[13]=i;for(let t=0;t<8;t++){for(let t=0;t<4;t++)this.QR(h,t,t+4,t+8,t+12);for(let t=0;t<16;t+=4)this.QR(h,t,t+1,t+2,t+3)}this.prectr=h[15],h[15]^=n,this.ctr=n,this.domac=!!s,this.reset()}QR(t,e,s,i,n){t[e]+=t[s],t[n]^=t[e],t[n]=t[n]<<16|t[n]>>>16,t[i]+=t[n],t[s]^=t[i],t[s]=t[s]<<12|t[s]>>>20,t[e]+=t[s],t[n]^=t[e],t[n]=t[n]<<8|t[n]>>>24,t[i]+=t[n],t[s]^=t[i],t[s]=t[s]<<7|t[s]>>>25}getmac(){if(!this.pmac)return!1;let s=new e([this.pmac[0]^this.cmac[0],this.pmac[1]^this.cmac[1],this.pmac[2]^this.cmac[2],this.pmac[3]^this.cmac[3]]);for(let t=0;t<4;t++)this.QR(s,0,1,2,3),this.QR(s,3,0,1,2),this.QR(s,2,3,0,1),this.QR(s,1,2,3,0);for(let t=0;t<4;t++)s[t]+=this.pmac[t]+this.cmac[t];return new t(s.buffer)}process(t=!1){let e,s,i=(t?Math.ceil:Math.floor)((this.sigbytes-this.pointer)/16),n=Math.ceil(this.sigbytes/4)-1,h=4-this.sigbytes%4;this.state[15]=this.prectr^this.ctr+(this.pointer>>4);for(let t=0;t<i;t++){let t=this.xstate;t.set(this.state);for(let e=0;e<20;e+=2)this.QR(t,0,4,8,12),this.QR(t,1,5,9,13),this.QR(t,2,6,10,14),this.QR(t,3,7,11,15),this.QR(t,0,5,10,15),this.QR(t,1,6,11,12),this.QR(t,2,7,8,13),this.QR(t,3,4,9,14);for(let t=0;t<16&&this.pointer+t<=n;t++)s=(e=this.data[this.pointer+t])^this.xstate[t]+this.state[t],this.pointer+t==n&&(s=s<<8*h>>>8*h),this.data[this.pointer+t]=s,this.domac&&(this.pmac[3&t]^=e+this.xstate[t],this.cmac[3&t]^=s+this.xstate[t],this.QR(this.pmac,3&t,t+1&3,t+2&3,t+3&3),this.QR(this.cmac,3&t,t+1&3,t+2&3,t+3&3));this.pointer+=16,this.state[15]++}}append(s){s="string"==typeof s?(new i).encode(s):s;let n=this.data,h=64*Math.ceil((this.sigbytes+s.byteLength)/64);this.data=new t(h),this.data.set(new t(n.buffer,0,this.sigbytes)),this.data.set(new t(s.buffer),this.sigbytes),this.data=new e(this.data.buffer),this.sigbytes+=s.byteLength}update(t){return this.append(t),this.process(!1),this}finalize(){return this.process(!0),{data:new t(this.data.buffer,0,this.sigbytes),mac:this.getmac()}}}const f=[0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14],l=new e([1,32898,32906,2147516416,32907,2147483649,2147516545,32777,138,136,2147516425,2147483658,2147516555,139,32905,32771,32770,128,32778,2147483658,2147516545,32896,2147483649,2147516424]);class u{reset(){this.state=new e(25),this.temp=new e(25),this.theta=new e(5),this.data=new e(0),this.padblock=new e(16),this.sigbytes=0}constructor(){this.reset()}keccakF(t){let e,s,i=this.temp,n=this.theta;for(var h=0;h<22;h++){n[0]=t[0]^t[1]^t[2]^t[3]^t[4],n[1]=t[5]^t[6]^t[7]^t[8]^t[9],n[2]=t[10]^t[11]^t[12]^t[13]^t[14],n[3]=t[15]^t[16]^t[17]^t[18]^t[19],n[4]=t[20]^t[21]^t[22]^t[23]^t[24];for(var a=0;a<5;a++)for(var r=0;r<5;r++)s=n[(a+1)%5],t[5*a+r]^=n[(a+4)%5]^(s<<1|s>>>31),e=f[5*a+r],s=t[5*a+r],i[5*r+(2*a+3*r)%5]=s<<e|s>>>32-e;for(a=0;a<5;a++)for(r=0;r<5;r++)t[5*a+r]=i[5*a+r]^~i[(a+1)%5*5+r]&i[(a+2)%5*5+r];t[0]^=l[h]}}process(t=!1){let e=this.data.length/16;for(let t=0;t<e;t++){for(let e=0;e<16;e++)this.state[e]^=this.data[16*t+e];this.keccakF(this.state)}if(t){for(let t=0;t<16;t++)this.state[t]^=this.padblock[t];this.keccakF(this.state)}}append(s){s="string"==typeof s?(new i).encode(s):s;let n=this.data,h=this.padblock;if(s.byteLength+this.sigbytes<64)(h=new t(h.buffer)).set(new t(s.buffer),this.sigbytes),h[h.length-1]=128,h[s.byteLength+this.sigbytes]^=6,this.padblock=new e(h.buffer),this.sigbytes+=s.byteLength;else{let i=64*Math.floor((this.sigbytes+s.byteLength)/64),a=(this.sigbytes+s.byteLength)%64;(n=n.byteLength>=i?new t(n.buffer,0,i):new t(i)).set(new t(h.buffer,0,this.sigbytes)),n.set(new t(s.buffer,0,s.byteLength-a),this.sigbytes),n=new e(n.buffer,0,i>>2),h.fill(0),this.sigbytes=0,a>0&&this.append(new t(s.buffer,s.byteLength-a))}}update(t){return this.append(t),this.process(!1),this}finalize(s=32){this.process(!0);let i=16*Math.ceil(s/64),n=new e(i);for(let t=0;t<i;t+=16)n.set(new e(this.state.buffer,0,16),t),this.keccakF(this.state);return{toString(t){return(new(t||r)).decode(this.hash)},hash:new t(n.buffer,0,s)}}}class p{constructor(t=32,e=1e3){this.outputbytes=t,this.iterations=e}compute(s,i){let n,h=new t(this.outputbytes),a=new u;a.update(new e([i])),a.finalize(0);for(let t=0;t<this.iterations;t++){a.update(s),n=a.finalize(this.outputbytes).hash;for(let t=0;t<h.length;t++)h[t]^=n[t]}return h}}return{version:"1.0",author:"Franatrtur",enc:{Hex:r,Utf8:i,Ascii:s,Base64:o},ChaCha20:d,Keccak800:u,Pbkdf:p,encrypt:function(s,n){let h="object"==typeof crypto?crypto.getRandomValues(new e(1))[0]:Math.floor(4294967296*Math.random()),a=new p(32,1e4).compute((new i).encode(n),h),c=new d(a,!0,h);c.update((new i).encode(s));let f=c.finalize();return(new r).decode(new t(new e([h]).buffer))+(new o).decode(f.data)+(new r).decode(f.mac)},decrypt:function(t,s){let n,h,a;try{n=new e((new r).encode(t.slice(0,8)).buffer)[0],h=(new o).encode(t.slice(8,-32)),a=t.slice(-32)}catch(t){throw"Incorrectly formated ciphertext"}let c=new p(32,1e4).compute((new i).encode(s),n),f=new d(c,!0,n);f.update(h);let l=f.finalize();if((new r).decode(l.mac)!=a)throw"Invalid authentication";return(new i).decode(l.data)},hash:function(t){return(new u).update((new i).encode(t)).finalize().toString(r)}}}());

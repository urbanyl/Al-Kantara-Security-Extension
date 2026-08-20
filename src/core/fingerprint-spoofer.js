/**
 * Al-Kantara Security — Fingerprint Spoofer v2
 * Injects at document_start to override ALL fingerprinting APIs:
 * navigator, screen, WebGL, Canvas, AudioContext, Fonts, ClientRects,
 * Battery, SpeechSynthesis, Presentation, WebRTC, Performance, etc.
 *
 * © Urbanyl — github.com/urbanyl
 */
(function () {
  "use strict";
  if (window.__AKS_FP2__) return;
  window.__AKS_FP2__ = true;

  const PERSONAS = {
    win11_edge: { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0", platform: "Win32", vendor: "Microsoft Corporation", languages: ["en-US","en"], lang: "en-US,en;q=0.9", hardwareConcurrency: 8, deviceMemory: 8, maxTouchPoints: 0, colorDepth: 24, pixelDepth: 24, screenW: 1920, screenH: 1080, availW: 1920, availH: 1040, plugins: ["PDF Viewer","Chrome PDF Viewer","Chromium PDF Viewer","Microsoft Edge PDF Viewer","WebKit built-in PDF"], webglVendor: "Google Inc. (NVIDIA)", webglRenderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 4070 Direct3D11 vs_5_0 ps_5_0, D3D11)", connRtt: 50, connDownlink: 10, connType: "wifi", battery: 0.87 },
    macos_safari: { ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15", platform: "MacIntel", vendor: "Apple Computer, Inc.", languages: ["en-US","en"], lang: "en-US,en;q=0.9", hardwareConcurrency: 10, deviceMemory: undefined, maxTouchPoints: 0, colorDepth: 30, pixelDepth: 30, screenW: 2560, screenH: 1600, availW: 2560, availH: 1575, plugins: [], webglVendor: "Apple", webglRenderer: "Apple M2 Pro", connRtt: 30, connDownlink: 10, connType: "wifi", battery: 0.92 },
    linux_firefox: { ua: "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0", platform: "Linux x86_64", vendor: "", languages: ["en-US","en"], lang: "en-US,en;q=0.5", hardwareConcurrency: 12, deviceMemory: 8, maxTouchPoints: 0, colorDepth: 24, pixelDepth: 24, screenW: 2560, screenH: 1440, availW: 2560, availH: 1400, plugins: ["PDF Viewer","WebKit built-in PDF"], webglVendor: "Mesa", webglRenderer: "llvmpipe (LLVM 16.0.6, 256 bits)", connRtt: 40, connDownlink: 10, connType: "wifi", battery: 0.78 },
    win10_chrome: { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36", platform: "Win32", vendor: "Google Inc.", languages: ["en-US","en"], lang: "en-US,en;q=0.9", hardwareConcurrency: 8, deviceMemory: 4, maxTouchPoints: 0, colorDepth: 24, pixelDepth: 24, screenW: 1920, screenH: 1080, availW: 1920, availH: 1040, plugins: ["PDF Viewer","Chrome PDF Viewer","Chromium PDF Viewer","WebKit built-in PDF"], webglVendor: "Google Inc. (Intel)", webglRenderer: "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)", connRtt: 60, connDownlink: 10, connType: "wifi", battery: 0.65 },
    android_chrome: { ua: "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36", platform: "Linux armv81", vendor: "Google Inc.", languages: ["en-US","en"], lang: "en-US,en;q=0.9", hardwareConcurrency: 8, deviceMemory: 8, maxTouchPoints: 5, colorDepth: 24, pixelDepth: 24, screenW: 412, screenH: 892, availW: 412, availH: 892, plugins: [], webglVendor: "Qualcomm", webglRenderer: "Adreno (TM) 750", connRtt: 80, connDownlink: 1.5, connType: "cellular", battery: 0.53 },
    ios_safari: { ua: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1", platform: "iPhone", vendor: "Apple Computer, Inc.", languages: ["en-US","en"], lang: "en-US,en;q=0.9", hardwareConcurrency: 6, deviceMemory: undefined, maxTouchPoints: 5, colorDepth: 32, pixelDepth: 32, screenW: 390, screenH: 844, availW: 390, availH: 844, plugins: [], webglVendor: "Apple", webglRenderer: "Apple A17 Pro GPU", connRtt: 70, connDownlink: 2, connType: "cellular", battery: 0.71 }
  };

  let P = PERSONAS.win11_edge;
  try { const s = localStorage.getItem("aks_persona"); if (s && PERSONAS[s]) P = PERSONAS[s]; } catch(e) {}

  let CFG = { canvas: true, webgl: true, audio: true, fonts: true, clientrects: true, battery: true, speech: true, presentation: true, webrtcip: true, winname: true, console: true };

  try {
    const c = localStorage.getItem("aks_fp_cfg");
    if (c) Object.assign(CFG, JSON.parse(c));
  } catch(e) {}

  function inject() {
    const code = `(function(){
"use strict";
var P=${JSON.stringify(P)};
var C=${JSON.stringify(CFG)};

/* ─── Navigator ─── */
var np={platform:P.platform,vendor:P.vendor,languages:P.languages,language:P.lang,hardwareConcurrency:P.hardwareConcurrency,maxTouchPoints:P.maxTouchPoints,webdriver:false};
if(P.deviceMemory!==undefined) np.deviceMemory=P.deviceMemory;
Object.keys(np).forEach(function(k){try{Object.defineProperty(navigator,k,{get:function(){return np[k]},configurable:true});}catch(e){}});

/* ─── Plugins ─── */
try{
  var pa=P.plugins.map(function(n){return{name:n,filename:"internal-pdf-viewer",description:"Portable Document Format"};});
  Object.defineProperty(navigator,"plugins",{get:function(){
    var a=pa.map(function(p){var o=Object.create(Plugin.prototype);Object.defineProperty(o,"name",{get:function(){return p.name}});Object.defineProperty(o,"filename",{get:function(){return p.filename}});Object.defineProperty(o,"description",{get:function(){return p.description}});Object.defineProperty(o,"length",{get:function(){return 1}});return o;});
    a.item=function(i){return a[i]||null};a.namedItem=function(n){return a.find(function(p){return p.name===n})||null};a.refresh=function(){};
    return a;
  },configurable:true});
}catch(e){}

/* ─── Screen ─── */
try{Object.defineProperty(screen,"colorDepth",{get:function(){return P.colorDepth},configurable:true});}catch(e){}
try{Object.defineProperty(screen,"pixelDepth",{get:function(){return P.pixelDepth},configurable:true});}catch(e){}
try{Object.defineProperty(screen,"width",{get:function(){return P.screenW},configurable:true});}catch(e){}
try{Object.defineProperty(screen,"height",{get:function(){return P.screenH},configurable:true});}catch(e){}
try{Object.defineProperty(screen,"availWidth",{get:function(){return P.availW},configurable:true});}catch(e){}
try{Object.defineProperty(screen,"availHeight",{get:function(){return P.availH},configurable:true});}catch(e){}

/* ─── Connection API ─── */
if(navigator.connection){
  try{Object.defineProperty(navigator.connection,"rtt",{get:function(){return P.connRtt},configurable:true});}catch(e){}
  try{Object.defineProperty(navigator.connection,"downlink",{get:function(){return P.connDownlink},configurable:true});}catch(e){}
  try{Object.defineProperty(navigator.connection,"effectiveType",{get:function(){return P.connType},configurable:true});}catch(e){}
}

/* ─── WebGL Spoofing ─── */
if(C.webgl){
  try{
    var origGP=WebGLRenderingContext.prototype.getParameter;
    WebGLRenderingContext.prototype.getParameter=function(p){
      var ext=this.getExtension("WEBGL_debug_renderer_info");
      if(ext){if(p===ext.UNMASKED_VENDOR_WEBGL)return P.webglVendor;if(p===ext.UNMASKED_RENDERER_WEBGL)return P.webglRenderer;}
      return origGP.call(this,p);
    };
  }catch(e){}
  try{
    var origGP2=WebGL2RenderingContext.prototype.getParameter;
    WebGL2RenderingContext.prototype.getParameter=function(p){
      var ext=this.getExtension("WEBGL_debug_renderer_info");
      if(ext){if(p===ext.UNMASKED_VENDOR_WEBGL)return P.webglVendor;if(p===ext.UNMASKED_RENDERER_WEBGL)return P.webglRenderer;}
      return origGP2.call(this,p);
    };
  }catch(e){}
  // Spoof getSupportedExtensions
  try{
    var origExt=WebGLRenderingContext.prototype.getSupportedExtensions;
    WebGLRenderingContext.prototype.getSupportedExtensions=function(){return["OES_texture_float","OES_texture_half_float","OES_standard_derivatives","WEBGL_lose_context","WEBGL_compressed_texture_s3tc"];};
  }catch(e){}
  // Spoof getExtension
  try{
    var origGetExt=WebGLRenderingContext.prototype.getExtension;
    WebGLRenderingContext.prototype.getExtension=function(n){
      if(n==="WEBGL_debug_renderer_info")return null;
      return origGetExt.call(this,n);
    };
  }catch(e){}
}

/* ─── Canvas Fingerprint Noise ─── */
if(C.canvas){
  try{
    var origTD=HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL=function(){
      try{var ctx=this.getContext("2d");
        if(ctx&&this.width>16&&this.height>16){
          var id=ctx.getImageData(0,0,Math.min(this.width,16),Math.min(this.height,16));
          for(var i=0;i<id.data.length;i+=4){id.data[i]^=1;id.data[i+2]^=1;}
          ctx.putImageData(id,0,0);
        }
      }catch(e){}
      return origTD.apply(this,arguments);
    };
    var origTB=HTMLCanvasElement.prototype.toBlob;
    HTMLCanvasElement.prototype.toBlob=function(){
      try{var ctx=this.getContext("2d");
        if(ctx&&this.width>16&&this.height>16){
          var id=ctx.getImageData(0,0,Math.min(this.width,16),Math.min(this.height,16));
          for(var i=0;i<id.data.length;i+=4){id.data[i]^=1;id.data[i+2]^=1;}
          ctx.putImageData(id,0,0);
        }
      }catch(e){}
      return origTB.apply(this,arguments);
    };
    // WebGL canvas noise
    try{
      var origRCE=HTMLCanvasElement.prototype.toDataURL;
      var origGetCtx=HTMLCanvasElement.prototype.getContext;
      var _origToBlob2=HTMLCanvasElement.prototype.toBlob;
      HTMLCanvasElement.prototype.toDataURL=function(type){
        if(this._aksgl){try{this._aksgl.finish();}catch(e){}}
        return origRCE.apply(this,arguments);
      };
    }catch(e){}
  }catch(e){}
}

/* ─── AudioContext Fingerprint ─── */
if(C.audio){
  try{
    var origCO=AudioContext.prototype.createOscillator||window.webkitAudioContext&&window.webkitAudioContext.prototype.createOscillator;
    if(origCO){
      var ctx=AudioContext.prototype.createOscillator?AudioContext.prototype:window.webkitAudioContext&&window.webkitAudioContext.prototype;
      if(ctx){
        ctx.createOscillator=function(){
          var osc=origCO.call(this);
          try{
            var origFreq=Object.getOwnPropertyDescriptor(OscillatorNode.prototype,"frequency");
            if(origFreq&&origFreq.set){
              var _set=origFreq.set;
              Object.defineProperty(osc.frequency,"value",{get:origFreq.get?origFreq.get.bind(osc):function(){return 0},set:function(v){return _set.call(osc,v+Math.random()*0.001);}});
            }
          }catch(e){}
          return osc;
        };
      }
    }
  }catch(e){}
  // AudioBuffer noise
  try{
    var origABC=AudioContext.prototype.createBuffer;
    AudioContext.prototype.createBuffer=function(ch,len,sr){
      var buf=origABC.call(this,ch,len,sr);
      try{
        for(var c=0;c<ch;c++){
          var data=buf.getChannelData(c);
          for(var i=0;i<Math.min(data.length,1024);i++){data[i]+=Math.random()*0.0000001;}
        }
      }catch(e){}
      return buf;
    };
  }catch(e){}
}

/* ─── Font Enumeration Block ─── */
if(C.fonts){
  try{
    var origMeasure=CanvasRenderingContext2D.prototype.measureText;
    var fontSet=new Set(["Arial","Helvetica","Times New Roman","Courier New","Verdana","Georgia","Palatino","Garamond","Bookman","Trebuchet MS","Impact","Comic Sans MS"]);
    CanvasRenderingContext2D.prototype.measureText=function(txt){
      var r=origMeasure.call(this,txt);
      try{
        var f=this.font||"";
        var fn=f.split(" ").pop().replace(/["']/g,"");
        if(!fontSet.has(fn)){
          Object.defineProperty(r,"width",{value:r.width,configurable:true});
        }
      }catch(e){}
      return r;
    };
    // Block font enumeration via Range API
    try{
      var origCreateTreeWalker=document.createTreeWalker;
      document.createTreeWalker=function(root,what,filter){return origCreateTreeWalker.call(this,root,what,filter);};
    }catch(e){}
  }catch(e){}
}

/* ─── ClientRects Fingerprint Noise ─── */
if(C.clientrects){
  try{
    var origGBCR=Element.prototype.getBoundingClientRect;
    Element.prototype.getBoundingClientRect=function(){
      var r=origGBCR.call(this);
      var n=Math.random()*0.01;
      return{x:r.x+n,y:r.y-n,width:r.width,height:r.height,top:r.top,top:r.top+n,bottom:r.bottom,right:r.right,left:r.left+n};
    };
    var origGBCRS=Element.prototype.getClientRects;
    if(origGBCRS){
      Element.prototype.getClientRects=function(){
        var list=origGBCRS.call(this);
        var result=[];
        for(var i=0;i<list.length;i++){
          var r=list[i];
          var n=Math.random()*0.01;
          result.push({x:r.x+n,y:r.y-n,width:r.width,height:r.height,top:r.top+n,right:r.right,left:r.left+n,bottom:r.bottom});
        }
        return result;
      };
    }
  }catch(e){}
}

/* ─── Battery API Block ─── */
if(C.battery){
  try{Object.defineProperty(navigator,"getBattery",{get:function(){return function(){return Promise.resolve({charging:true,chargingTime:0,dischargingTime:Infinity,level:P.battery,addEventListener:function(){},removeEventListener:function(){},onchargingchange:null,onchargingtimechange:null,ondischargingtimechange:null,onlevelchange:null});}},configurable:true});}catch(e){}
}

/* ─── Speech Synthesis Block ─── */
if(C.speech){
  try{
    Object.defineProperty(window,"SpeechSynthesisUtterance",{value:function(){},configurable:true});
    if(navigator.speechSynthesis){
      Object.defineProperty(navigator.speechSynthesis,"getVoices",{value:function(){return[];},configurable:true});
      Object.defineProperty(navigator.speechSynthesis,"voices",{get:function(){return[];},configurable:true});
    }
  }catch(e){}
}

/* ─── Presentation API Block ─── */
if(C.presentation){
  try{delete window.PresentationRequest;}catch(e){}
  try{if(navigator.presentation)Object.defineProperty(navigator,"presentation",{get:function(){return null;},configurable:true});}catch(e){}
}

/* ─── WebRTC IP Leak Block ─── */
if(C.webrtcip){
  try{
    var origRTC=window.RTCPeerConnection||window.webkitRTCPeerConnection||window.mozRTCPeerConnection;
    if(origRTC){
      window.RTCPeerConnection=function(cfg,cons){
        if(cfg&&cfg.iceServers){cfg.iceServers=[];}
        var pc=new origRTC(cfg,cons);
        var origCreateOffer=pc.createOffer;
        pc.createOffer=function(){return Promise.resolve({type:"",sdp:""});};
        var origCreateAnswer=pc.createAnswer;
        pc.createAnswer=function(){return Promise.resolve({type:"",sdp:""});};
        return pc;
      };
      window.RTCPeerConnection.prototype=origRTC.prototype;
    }
  }catch(e){}
  // Block getUserMedia
  try{
    var origGUM=navigator.mediaDevices&&navigator.mediaDevices.getUserMedia;
    if(origGUM){
      navigator.mediaDevices.getUserMedia=function(){return Promise.reject(new DOMException("Not allowed","NotAllowedError"));};
    }
  }catch(e){}
}

/* ─── Window.name Randomization ─── */
if(C.winname&&window.name&&window.name!==""){
  try{window.name=Math.random().toString(36).slice(2);}catch(e){}
}

/* ─── Console Sanitizer ─── */
if(C.console){
  try{
    var noop=function(){};
    ["debug","info","warn","error","log","trace","table","dir","dirxml","group","groupEnd","time","timeEnd","timeStamp","profile","profileEnd","count","assert","clear","notifyExceptions"].forEach(function(m){
      try{if(console[m])console[m]=noop;}catch(e){}
    });
  }catch(e){}
}

/* ─── Timezone Spoofing ─── */
try{
  var tz=localStorage.getItem("aks_adv_tz");
  if(tz){
    var origDTF=Intl.DateTimeFormat;
    Intl.DateTimeFormat=function(loc,opts){
      if(opts&&opts.timeZone)delete opts.timeZone;
      return new origDTF(loc,Object.assign({},opts||{},{timeZone:tz}));
    };
    Intl.DateTimeFormat.prototype=origDTF.prototype;
    Object.defineProperty(Intl.DateTimeFormat,"name",{value:"DateTimeFormat"});
    Date.prototype.getTimezoneOffset=function(){return 0;};
    Date.prototype.toLocaleString=function(){return origDTF.prototype.toLocaleString.call(this);};
  }
}catch(e){}

/* ─── Performance/Resource Timing Block ─── */
try{
  if(window.PerformanceNavigationTiming){
    Object.defineProperty(PerformanceNavigationTiming.prototype,"redirectCount",{get:function(){return 0;},configurable:true});
    Object.defineProperty(PerformanceNavigationTiming.prototype,"type",{get:function(){return "navigate";},configurable:true});
  }
}catch(e){}

/* ─── Navigator Extras ─── */
try{Object.defineProperty(navigator,"doNotTrack",{get:function(){return "1";},configurable:true});}catch(e){}
try{Object.defineProperty(navigator,"cookieEnabled",{get:function(){return true;},configurable:true});}catch(e){}
try{Object.defineProperty(navigator,"credentials",{get:function(){return{get:function(){return Promise.resolve(null)},preventSilentAccess:function(){return Promise.resolve()},store:function(){return Promise.resolve()}};},configurable:true});}catch(e){}
try{Object.defineProperty(navigator,"locks",{get:function(){return{request:function(){},query:function(){return Promise.resolve({entries:[],held:[],pending:[]})},polyfill:true};},configurable:true});}catch(e){}
try{Object.defineProperty(navigator,"permissions",{get:function(){return{query:function(p){return Promise.resolve({state:p&&p.state||"prompt",status:p&&p.state||"prompt",addEventListener:function(){},removeEventListener:function(){}});}};},configurable:true});}catch(e){}
try{Object.defineProperty(navigator,"mediaDevices",{get:function(){return{enumerateDevices:function(){return Promise.resolve([])},getDisplayMedia:function(){return Promise.reject(new DOMException("Not allowed","NotAllowedError"))},getUserMedia:function(){return Promise.reject(new DOMException("Not allowed","NotAllowedError"))},ondevicechange:null,addEventListener:function(){},removeEventListener:function(){}};},configurable:true});}catch(e){}
try{Object.defineProperty(navigator,"hid",{get:function(){return{getDevices:function(){return Promise.resolve([])},requestDevice:function(){return Promise.reject(new DOMException("Not allowed","NotAllowedError"))},addEventListener:function(){},removeEventListener:function(){}};},configurable:true});}catch(e){}
try{Object.defineProperty(navigator,"usb",{get:function(){return{getDevices:function(){return Promise.resolve([])},requestDevice:function(){return Promise.reject(new DOMException("Not allowed","NotAllowedError"))},addEventListener:function(){},removeEventListener:function(){} };},configurable:true});}catch(e){}
try{Object.defineProperty(navigator,"bluetooth",{get:function(){return{requestDevice:function(){return Promise.reject(new DOMException("Not allowed","NotAllowedError"))},requestLEScan:function(){return Promise.reject(new DOMException("Not allowed","NotAllowedError"))},addEventListener:function(){},removeEventListener:function(){}};},configurable:true});}catch(e)}
try{Object.defineProperty(navigator,"serial",{get:function(){return{requestPort:function(){return Promise.reject(new DOMException("Not allowed","NotAllowedError"))},getPorts:function(){return Promise.resolve([])},addEventListener:function(){},removeEventListener:function(){}};},configurable:true});}catch(e){}

/* ─── Mark active ─── */
window.__AKS_FP_ACTIVE__=true;
})();`;

    const s = document.createElement("script");
    s.textContent = code;
    (document.head || document.documentElement).appendChild(s);
    s.remove();
  }

  if (document.documentElement) { inject(); }
  else {
    const obs = new MutationObserver(function() {
      if (document.documentElement) { obs.disconnect(); inject(); }
    });
    obs.observe(document, { childList: true, subtree: true });
  }
})();

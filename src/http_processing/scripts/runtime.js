"use strict";
// Trusted prelude. The AST frontend cannot name these helpers, introduce
// functions/accessors or call anything outside its explicit method allowlist.
const __voleLimit = 262144;
let __voleAllocated = 0;
function __voleFreezeParameters(input) {
  const parameters = Object.freeze(input.parameters ?? {});
  Object.defineProperty(input,"parameters",{
    value:parameters,writable:false,configurable:false,enumerable:true
  });
}
function __voleCharge(n) {
  __voleTick();
  if (!Number.isSafeInteger(n) || n < 0 || n > 2097152 - __voleAllocated)
    throw new Error("script allocation work exceeded");
  __voleAllocated += n;
}
function __voleTextSize(s, quoted) {
  if (typeof s !== "string" || s.length > __voleLimit) throw new Error("invalid string");
  // Unquoted ASCII has one UTF-8 byte per code unit. Keep short strings and
  // quoted/Unicode validation on the existing path; check the deadline after
  // the bounded native scan before accepting its result.
  if (!quoted && s.length >= 4096) {
    const ascii = __voleIsASCII(s, s.length);
    if (ascii === true || (ascii === undefined && !/[^\x00-\x7f]/.test(s))) {
      __voleTick();
      return s.length;
    }
  }
  let n = quoted ? 2 : 0;
  for (let i = 0; i < s.length; i++) {
    if ((i & 255) === 0) __voleTick();
    const c = s.charCodeAt(i);
    if (c >= 0xD800 && c <= 0xDBFF) {
      if (++i >= s.length || s.charCodeAt(i) < 0xDC00 || s.charCodeAt(i) > 0xDFFF)
        throw new Error("isolated surrogate");
      n += 4;
    } else if (c >= 0xDC00 && c <= 0xDFFF) {
      throw new Error("isolated surrogate");
    } else if (quoted && (c === 34 || c === 92)) n += 2;
    else if (quoted && c < 32) n += [8,9,10,12,13].includes(c) ? 2 : 6;
    else n += c < 128 ? 1 : c < 2048 ? 2 : 3;
    if (n > __voleLimit) throw new Error("string byte limit");
  }
  return n;
}
function __volePrimitive(v) {
  if (v !== null && !["undefined","boolean","number","string"].includes(typeof v))
    throw new Error("implicit object conversion");
  if (typeof v === "number" && !Number.isFinite(v)) throw new Error("nonfinite number");
  return v;
}
function __voleConvert(name,v) {
  __voleTick(); __volePrimitive(v);
  if (name === "String") return __voleValue(String(v));
  if (name === "Number") return __voleValue(Number(v));
  if (name === "Boolean") return Boolean(v);
  throw new Error("unsupported conversion");
}
function __voleKey(k) {
  if (typeof k !== "string" && typeof k !== "number") throw new Error("invalid property key");
  __volePrimitive(k); k = String(k);
  __voleTextSize(k,false);
  if (k === "constructor" || k === "prototype" || k === "__proto__" ||
      k === "toJSON" || k.startsWith("__vole"))
    throw new Error("unsupported property");
  return k;
}
function __voleValue(v) {
  if (typeof v === "string") {
    __voleTextSize(v,false); __voleCharge(v.length * 2 + 16);
  } else if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error("nonfinite number");
    __voleCharge(8);
  } else if (Array.isArray(v)) {
    if (v.length > __voleLimit) throw new Error("array limit");
    __voleCharge(v.length * 24 + 32);
  } else if (v instanceof Uint8Array) {
    __voleCharge(__voleBinarySize(v) + 32);
  } else if (v !== null && typeof v === "object") {
    __voleCharge(Object.keys(v).length * 48 + 32);
  }
  return v;
}
function __voleAdd(a,b) {
  __voleTick(); __volePrimitive(a); __volePrimitive(b);
  if (typeof a === "string" || typeof b === "string") {
    a = String(a); b = String(b);
    if (__voleTextSize(a,false) + __voleTextSize(b,false) > __voleLimit)
      throw new Error("string byte limit");
    __voleCharge((a.length+b.length)*2+16);
    return a+b;
  }
  return __voleValue(a+b);
}
function __voleUnary(op,a) {
  __voleTick(); __volePrimitive(a);
  if (op === "+") return __voleValue(+a);
  if (op === "-") return __voleValue(-a);
  if (op === "~") return ~a;
  throw new Error("unsupported unary operation");
}
function __voleBinary(op,a,b) {
  __voleTick(); __volePrimitive(a); __volePrimitive(b);
  switch(op) {
    case "-": return __voleValue(a-b);
    case "*": return __voleValue(a*b);
    case "/": return __voleValue(a/b);
    case "%": return __voleValue(a%b);
    case "<": return a<b;
    case "<=": return a<=b;
    case ">": return a>b;
    case ">=": return a>=b;
    case "==": return a==b;
    case "!=": return a!=b;
    case "|": return a|b;
    case "&": return a&b;
    case "^": return a^b;
    case "<<": return a<<b;
    case ">>": return a>>b;
    case ">>>": return a>>>b;
  }
  throw new Error("unsupported binary operation");
}
function __voleGet(o,k) {
  __voleTick(); k = __voleKey(k);
  if (o === null || o === undefined) throw new Error("null member access");
  const v = o[k];
  if (typeof v === "function" || typeof v === "symbol" ||
      (typeof v === "number" && !Number.isFinite(v)))
    throw new Error("unsupported member value");
  return v;
}
function __voleSet(o,k,v) {
  __voleTick(); k = __voleKey(k);
  if (o === null || typeof o !== "object") throw new Error("invalid assignment");
  if (Array.isArray(o) || o instanceof Uint8Array) {
    if (k === "length" || !/^(0|[1-9][0-9]*)$/.test(k) || Number(k) >= __voleLimit)
      throw new Error("array index limit");
    const index = Number(k);
    if (o instanceof Uint8Array) {
      if (index >= o.length || typeof v !== "number" || !Number.isFinite(v))
        throw new Error("invalid byte assignment");
    }
    __voleCharge(32 + Math.max(0,index+1-o.length)*24);
  } else {
    const p = Object.getPrototypeOf(o);
    if (p !== Object.prototype && p !== null) throw new Error("invalid assignment target");
    __voleCharge(32+__voleTextSize(k,false)*2);
  }
  if (typeof v === "function" || typeof v === "symbol") throw new Error("invalid assigned value");
  o[k] = v;
  return v;
}
function __voleBinarySize(v) {
  let buffer, n;
  if (v instanceof Uint8Array) { buffer=v.buffer; n=v.byteLength; }
  else if (v instanceof ArrayBuffer) { buffer=v; n=v.byteLength; }
  else throw new Error("byte buffer required");
  if (!(buffer instanceof ArrayBuffer) || buffer.resizable === true || n > __voleLimit)
    throw new Error("unsupported byte buffer");
  // Unlike a detached view's length, this operation cannot turn detachment
  // into an apparently valid zero-length body. No entity bytes are copied.
  ArrayBuffer.prototype.slice.call(buffer,0,0);
  return n;
}
function __voleBytes(value) {
  __voleCharge(32);
  __voleBinarySize(value);
  if (value instanceof Uint8Array) return value;
  __voleCharge(32);
  return new Uint8Array(value);
}
function __volePlusMode(args,index) {
  if (args.length === index) return false;
  if (args.length !== index+1 || typeof args[index] !== "boolean")
    throw new Error("invalid query decoding mode");
  return args[index];
}
function __volePercentPart(text,start,end,plusAsSpace) {
  // Bound the slice, replacement and decoded UTF-16 storage before their
  // intrinsics run. A percent sequence cannot expand the UTF-8 byte length.
  __voleCharge((end-start)*(plusAsSpace ? 8 : 6)+32);
  const encoded=text.slice(start,end);
  return decodeURIComponent(plusAsSpace ? encoded.replaceAll("+"," ") : encoded);
}
function __voleQuery(url,plusAsSpace) {
  // The emitter takes this snapshot before user code. Core already validated
  // and canonicalized the original URL and excludes fragments.
  if (typeof url !== "string" || url.length > 8192) throw new Error("invalid original URL");
  __voleCharge(url.length+32);
  const entries=[];
  let start=url.indexOf("?")+1;
  if (!start) return entries;
  let equals=-1;
  for (let i=start; i<=url.length; i++) {
    if ((i&255)===0) __voleTick();
    const code=url.charCodeAt(i);
    if (code===38 || i===url.length) {
      if (i>start) {
        __voleCharge(152);
        entries.push({
          name:__volePercentPart(url,start,equals<0 ? i : equals,plusAsSpace),
          value:equals<0 ? null : __volePercentPart(url,equals+1,i,plusAsSpace)
        });
      }
      start=i+1;
      equals=-1;
    } else if (code===61 && equals<0) {
      equals=i;
    }
  }
  return entries;
}
function __voleUTF8Encode(text) {
  if (typeof text !== "string" || text.length > __voleLimit)
    throw new Error("invalid string");
  __voleCharge(text.length+32);
  const length=__voleTextSize(text,false);
  __voleCharge(length+text.length+32);
  const output=new Uint8Array(length);
  let at=0, nextCheck=0;
  for (let i=0; i<text.length; i++) {
    if (i>=nextCheck) { __voleTick(); nextCheck=i+256; }
    const point=text.codePointAt(i);
    if (point<0x80) output[at++]=point;
    else {
      if (point<0x800) output[at++]=0xc0|(point>>6);
      else {
        if (point<0x10000) output[at++]=0xe0|(point>>12);
        else {
          output[at++]=0xf0|(point>>18);
          output[at++]=0x80|((point>>12)&63);
          i++;
        }
        output[at++]=0x80|((point>>6)&63);
      }
      output[at++]=0x80|(point&63);
    }
  }
  return output;
}
function __voleBuildText(maxUnits,write) {
  if (maxUnits > __voleLimit) throw new Error("string byte limit");
  if (!maxUnits) return "";
  // UTF-16 workspace and the intrinsic's argument list stay chunk-sized.
  // The charged parts and final join avoid per-character string growth.
  const partLength=Math.min(maxUnits,1024);
  __voleCharge(maxUnits*4+Math.ceil(maxUnits/partLength)*64+partLength*10+32);
  const units=new Uint16Array(partLength), parts=[];
  let used=0;
  write(value=>{
    units[used++]=value;
    if (used===partLength) {
      parts.push(String.fromCharCode.apply(null,units));
      used=0;
    }
  });
  if (used) parts.push(String.fromCharCode.apply(null,units.subarray(0,used)));
  __voleTick();
  return parts.join("");
}
function __voleUTF8Decode(value) {
  const bytes=__voleBytes(value);
  __voleCharge(bytes.length);
  return __voleBuildText(bytes.length,append=>{
    let nextCheck=0;
    for (let i=0; i<bytes.length;) {
      if (i>=nextCheck) { __voleTick(); nextCheck=i+256; }
      let point=bytes[i++];
      if (point>=0x80) {
        if (point<0xc2 || point>0xf4) throw new Error("invalid UTF-8");
        const following=point<0xe0 ? 1 : point<0xf0 ? 2 : 3;
        if (following>bytes.length-i) throw new Error("invalid UTF-8");
        point&=127>>(following+1);
        for (let j=0; j<following; j++) {
          const byte=bytes[i++];
          if ((byte&0xc0)!==0x80) throw new Error("invalid UTF-8");
          point=(point<<6)|(byte&63);
        }
        const minimum=following===1 ? 0x80 : following===2 ? 0x800 : 0x10000;
        if (point<minimum || point>0x10ffff || (point>=0xd800 && point<=0xdfff))
          throw new Error("invalid UTF-8");
      }
      if (point<0x10000) append(point);
      else {
        point-=0x10000;
        append(0xd800+(point>>10));
        append(0xdc00+(point&1023));
      }
    }
  });
}
const __voleBase64Alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function __voleBase64Encode(value) {
  const bytes=__voleBytes(value);
  __voleCharge(bytes.length);
  return __voleBuildText(Math.ceil(bytes.length/3)*4,append=>{
    for (let i=0; i<bytes.length; i+=3) {
      if ((i&255)===0) __voleTick();
      const a=bytes[i], b=bytes[i+1]??0, c=bytes[i+2]??0;
      append(__voleBase64Alphabet.charCodeAt(a>>2));
      append(__voleBase64Alphabet.charCodeAt(((a&3)<<4)|(b>>4)));
      append(i+1<bytes.length ? __voleBase64Alphabet.charCodeAt(((b&15)<<2)|(c>>6)) : 61);
      append(i+2<bytes.length ? __voleBase64Alphabet.charCodeAt(c&63) : 61);
    }
  });
}
function __voleBase64Value(code) {
  if (code>=65 && code<=90) return code-65;
  if (code>=97 && code<=122) return code-71;
  if (code>=48 && code<=57) return code+4;
  if (code===43) return 62;
  if (code===47) return 63;
  throw new Error("invalid Base64");
}
function __voleBase64Decode(text) {
  if (typeof text !== "string" || text.length>__voleLimit || text.length%4)
    throw new Error("invalid Base64");
  const padding=text.endsWith("==") ? 2 : text.endsWith("=") ? 1 : 0;
  const length=text.length/4*3-padding;
  const end=text.length-padding;
  __voleCharge(text.length+length+32);
  const output=new Uint8Array(length);
  let at=0;
  for (let i=0; i<text.length; i+=4) {
    if ((i&255)===0) __voleTick();
    const a=__voleBase64Value(text.charCodeAt(i)), b=__voleBase64Value(text.charCodeAt(i+1));
    const c=i+2<end ? __voleBase64Value(text.charCodeAt(i+2)) : 0;
    const d=i+3<end ? __voleBase64Value(text.charCodeAt(i+3)) : 0;
    if ((i+2>=end && (b&15)) || (i+3>=end && (c&3))) throw new Error("invalid Base64 padding");
    output[at++]=(a<<2)|(b>>4);
    if (i+2<end) output[at++]=(b<<4)|(c>>2);
    if (i+3<end) output[at++]=(c<<6)|d;
  }
  return output;
}
function __voleConcatBytes(parts) {
  if (!Array.isArray(parts)) throw new Error("byte array list required");
  __voleCharge(parts.length*32+32);
  let length=0;
  for (const part of parts) {
    __voleTick();
    length+=__voleBinarySize(part);
    if (length>__voleLimit) throw new Error("byte buffer limit");
  }
  __voleCharge(length*2+32);
  const output=new Uint8Array(length);
  let at=0;
  for (const part of parts) {
    __voleTick();
    const bytes=part instanceof Uint8Array ? part : new Uint8Array(part);
    output.set(bytes,at);
    at+=bytes.length;
  }
  return output;
}
function __voleTool(name,args,originalURL) {
  __voleTick();
  if (name==="query") return __voleQuery(originalURL,__volePlusMode(args,0));
  const value=args[0];
  if (name==="percentDecode") {
    const plusAsSpace=__volePlusMode(args,1);
    __voleTextSize(value,false);
    return __volePercentPart(value,0,value.length,plusAsSpace);
  }
  if (name==="copyBytes" && args.length>=1 && args.length<=3) {
    const bytes=__voleBytes(value);
    const start=args.length>=2 ? args[1] : 0;
    const end=args.length===3 ? args[2] : bytes.length;
    if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) ||
        start<0 || start>end || end>bytes.length) throw new Error("invalid byte range");
    __voleCharge((end-start)*2+32);
    return bytes.slice(start,end);
  }
  if (args.length!==1) throw new Error("invalid tool arguments");
  switch(name) {
    case "utf8Encode": return __voleUTF8Encode(value);
    case "utf8Decode": return __voleUTF8Decode(value);
    case "base64Encode": return __voleBase64Encode(value);
    case "base64Decode": return __voleBase64Decode(value);
    case "concatBytes": return __voleConcatBytes(value);
  }
  throw new Error("unsupported tool");
}
function __voleMeasure(v,binary,skipBody) {
  let visited=0;
  const seen = new Set();
  function walk(v,depth) {
    __voleTick();
    if (++visited > 32768 || depth > 64) throw new Error("result structure limit");
    if (v===null) return 4;
    if (typeof v==="boolean") return v ? 4 : 5;
    if (typeof v==="number") {
      if (!Number.isFinite(v)) throw new Error("nonfinite number");
      return String(v).length;
    }
    if (typeof v==="string") return __voleTextSize(v,true);
    if (binary && (v instanceof Uint8Array || v instanceof ArrayBuffer)) {
      __voleBinarySize(v); return 0;
    }
    if (!v || typeof v!=="object" || seen.has(v)) throw new Error("invalid or shared result value");
    seen.add(v);
    const p=Object.getPrototypeOf(v), array=Array.isArray(v);
    if (p!==Object.prototype && p!==Array.prototype && p!==null)
      throw new Error("invalid result prototype");
    const keys=Object.getOwnPropertyNames(v);
    if (Object.getOwnPropertySymbols(v).length || keys.length>32768) throw new Error("result property limit");
    let size=2, count=0;
    if (array && (v.length>32768 || keys.length!==v.length+1)) throw new Error("sparse result array");
    for (const k of keys) {
      if (array && k==="length") continue;
      const d=Object.getOwnPropertyDescriptor(v,k);
      if (!d || !d.enumerable || d.get || d.set || k==="toJSON") throw new Error("result accessor");
      if (v===skipBody && k==="data") continue;
      if (array && !/^(0|[1-9][0-9]*)$/.test(k)) throw new Error("invalid array property");
      size += (count++ ? 1 : 0) + (array ? 0 : __voleTextSize(k,true)+1) + walk(d.value,depth+1);
      if (size>__voleLimit) throw new Error("encoded JSON limit");
    }
    return size;
  }
  return walk(v,0);
}
function __voleJSONInput(s) {
  __voleTextSize(s,false);
  let depth=0, nodes=0, string=false, escaped=false;
  for (let i=0;i<s.length;i++) {
    if ((i&255)===0) __voleTick();
    const c=s.charCodeAt(i);
    if (string) {
      if (escaped) escaped=false;
      else if (c===92) escaped=true;
      else if (c===34) string=false;
    } else if (c===34) { string=true; if(++nodes>32768)throw new Error("JSON node limit"); }
    else if (c===91 || c===123) {
      if (++depth>64 || ++nodes>32768) throw new Error("JSON structure limit");
    } else if (c===93 || c===125) depth--;
    else if (c===44 && ++nodes>32768) throw new Error("JSON node limit");
  }
}
function __voleRangeBytes(s,start,end) {
  let n=0;
  for(let i=start;i<end;i++) {
    if((i&255)===0)__voleTick();
    const c=s.charCodeAt(i);
    if(c>=0xD800 && c<=0xDBFF) {
      if(++i>=end || s.charCodeAt(i)<0xDC00 || s.charCodeAt(i)>0xDFFF)throw new Error("isolated surrogate");
      n+=4;
    } else if(c>=0xDC00 && c<=0xDFFF)throw new Error("isolated surrogate");
    else n+=c<128 ? 1 : c<2048 ? 2 : 3;
  }
  return n;
}
function __voleReplacementSize(s,search,replacement,all) {
  const original=__voleTextSize(s,false), matched=__voleTextSize(search,false);
  __voleTextSize(replacement,false);
  // A literal ASCII substitution replaces one UTF-8 byte with one byte and
  // cannot split a validated surrogate pair, regardless of the match count.
  if(search.length===1 && replacement.length===1 && replacement!=="$" &&
      search.charCodeAt(0)<128 && replacement.charCodeAt(0)<128)return original;
  let fixed=0, prefix=0, suffix=0, match=0;
  for(let i=0;i<replacement.length;i++) {
    __voleTick();
    if(replacement[i]==="$" && i+1<replacement.length) {
      const next=replacement[i+1];
      if(next==="$"){fixed++;i++;continue;}
      if(next==="&"){match++;i++;continue;}
      if(next==="\x60"){prefix++;i++;continue;}
      if(next==="'"){suffix++;i++;continue;}
    }
    const c=replacement.charCodeAt(i);
    if(c>=0xD800 && c<=0xDBFF){fixed+=4;i++;}
    else fixed+=c<128 ? 1 : c<2048 ? 2 : 3;
  }
  if(search==="" && fixed===0 && prefix===0 && suffix===0)return original;
  let size=original, at=0, previous=0, before=0;
  while(at<=s.length) {
    __voleTick();
    const found=search==="" ? at : s.indexOf(search,at);
    if(found<0)break;
    before+=__voleRangeBytes(s,previous,found); previous=found;
    size+=fixed+match*matched+prefix*before+suffix*(original-before-matched)-matched;
    if(size>__voleLimit)throw new Error("replacement size limit");
    if(!all)break;
    at=found+(search.length || 1);
  }
  return size;
}
function __voleCall(o,k,args) {
  __voleTick(); k=__voleKey(k);
  if (args.length>8) throw new Error("too many arguments");
  if (o===JSON && (k==="parse" || k==="stringify")) {
    if(args.length!==1)throw new Error("JSON callback unsupported");
    if(k==="parse") {
      if(typeof args[0]!=="string")throw new Error("JSON string required");
      __voleJSONInput(args[0]); __voleCharge(args[0].length*8+32);
      const result=JSON.parse(args[0]);
      __voleMeasure(result,false,null);
      return result;
    }
    const size=__voleMeasure(args[0],false,null);
    __voleCharge(size*2+32);
    return JSON.stringify(args[0]);
  }
  if(o===Object && ["keys","values","entries"].includes(k)) {
    if(args.length!==1 || args[0]===null || typeof args[0]!=="object")throw new Error("Object argument");
    const n=(Array.isArray(args[0]) || args[0] instanceof Uint8Array)
      ? args[0].length : Object.getOwnPropertyNames(args[0]).length;
    if(n>32768)throw new Error("Object result limit");
    __voleCharge(n*(k==="entries" ? 96 : 24)+32);
    return Object[k](args[0]);
  }
  if(o===Array && k==="isArray") {
    if(args.length!==1)throw new Error("invalid Array call");
    return Array.isArray(args[0]);
  }
  if(o===Number && ["isFinite","isInteger"].includes(k)) {
    if(args.length!==1)throw new Error("invalid Number call");
    return Number[k](args[0]);
  }
  if(o===Math && ["abs","floor","ceil","round","trunc","min","max"].includes(k)) {
    for(const a of args)__volePrimitive(a);
    return __voleValue(Math[k](...args));
  }
  if(o===Uint8Array && k==="from") {
    if(args.length!==1 || !Array.isArray(args[0]) || args[0].length>__voleLimit)throw new Error("invalid bytes");
    for(const n of args[0]) {
      __voleTick();
      if(typeof n!=="number" || !Number.isFinite(n))throw new Error("invalid byte value");
    }
    __voleCharge(args[0].length+32);
    return Uint8Array.from(args[0]);
  }
  if(typeof o==="string") {
    if(!["slice","substring","charAt","at","includes","startsWith","endsWith","indexOf","lastIndexOf","trim","toLowerCase","toUpperCase","split","replace","replaceAll"].includes(k))
      throw new Error("unsupported string method");
    __voleTextSize(o,false);
    for(const a of args)__volePrimitive(a);
    if(k==="split") {
      if(args.length>2 || (args[0]!==undefined && typeof args[0]!=="string"))throw new Error("literal separator required");
      let limit=__voleLimit, parts=0;
      if(args[1]!==undefined) {
        if(!Number.isSafeInteger(args[1]) || args[1]<0 || args[1]>__voleLimit)throw new Error("split limit");
        limit=args[1];
      }
      const sep=args[0];
      if(limit===0)parts=0;
      else if(sep===undefined)parts=1;
      else if(sep==="")parts=Math.min(o.length,limit);
      else {
        parts=1; let at=0;
        while(parts<limit) {
          __voleTick(); const found=o.indexOf(sep,at); if(found<0)break;
          parts++; at=found+sep.length;
        }
      }
      if(parts>__voleLimit)throw new Error("split result limit");
      __voleCharge(parts*24+o.length*2+32);
      return o.split(sep,limit);
    }
    if(k==="replace" || k==="replaceAll") {
      if(args.length!==2 || typeof args[0]!=="string" || typeof args[1]!=="string")
        throw new Error("literal replacement required");
      const search=args[0], replacement=args[1];
      if(search==="" && replacement==="")return o;
      const bytes=__voleReplacementSize(o,search,replacement,k==="replaceAll");
      __voleCharge(bytes*2+32);
      // Only a bounded dense ASCII single-code-unit replaceAll is eligible.
      // Keep the same size/work preflight and every existing tick boundary.
      // Undefined leaves Unicode, templates, sparse input and failed bridge
      // admission on the original intrinsic, with the same allocation charge.
      if(k==="replaceAll" && o.length>=4096 && search.length===1 &&
          replacement.length===1 && replacement!=="$" &&
          search.charCodeAt(0)<128 && replacement.charCodeAt(0)<128) {
        const native=__voleReplaceASCIIAll(o,o.length,search.charCodeAt(0),replacement.charCodeAt(0));
        if(native!==undefined)return native;
      }
      return k==="replace" ? o.replace(search,replacement) : o.replaceAll(search,replacement);
    }
    __voleCharge(o.length*6+32);
    return __voleValue(String.prototype[k].apply(o,args));
  }
  if(Array.isArray(o) || o instanceof Uint8Array) {
    if(!["push","pop","slice","subarray","concat","join","indexOf","includes","reverse","at"].includes(k))
      throw new Error("unsupported array method");
    if(k==="join") {
      if(args.length>1 || (args[0]!==undefined && typeof args[0]!=="string"))throw new Error("join separator");
      const sep=args[0]===undefined ? "," : args[0];
      let size=Math.max(0,o.length-1)*__voleTextSize(sep,false);
      for(const item of o) {
        __voleTick(); __volePrimitive(item);
        if(item!==null && item!==undefined)size+=__voleTextSize(String(item),false);
        if(size>__voleLimit)throw new Error("join result limit");
      }
      __voleCharge(size*2+32);
      return o.join(sep);
    }
    if(k==="push") {
      if(!Array.isArray(o) || o.length+args.length>__voleLimit)throw new Error("push result limit");
      __voleCharge(args.length*24+32);
      return o.push(...args);
    }
    if(k==="concat") {
      if(!Array.isArray(o))throw new Error("unsupported typed array method");
      let n=o.length;
      for(const a of args)n+=Array.isArray(a) ? a.length : 1;
      if(n>__voleLimit)throw new Error("array size limit");
      __voleCharge(n*24+32); return o.concat(...args);
    }
    for(let i=0;i<args.length;i++) {
      if(i===0 && (k==="indexOf" || k==="includes"))continue;
      __volePrimitive(args[i]);
    }
    if((k==="pop" && !Array.isArray(o)))throw new Error("unsupported typed array method");
    if(k==="subarray") {
      if(!(o instanceof Uint8Array))throw new Error("typed array required");
      __voleCharge(32);
    }
    if(k==="slice")__voleCharge(o.length*(o instanceof Uint8Array ? 1 : 24)+32);
    return o[k](...args);
  }
  throw new Error("unsupported call");
}
function __voleRecord(v,allowed) {
  if(!v || typeof v!=="object" || Array.isArray(v) ||
      ![Object.prototype,null].includes(Object.getPrototypeOf(v)))throw new Error("data record required");
  if(Object.getOwnPropertySymbols(v).length)throw new Error("symbol field");
  const keys=Object.getOwnPropertyNames(v);
  if(keys.length>allowed.length)throw new Error("unknown field");
  for(const key of keys) {
    const d=Object.getOwnPropertyDescriptor(v,key);
    if(!allowed.includes(key) || !d || !d.enumerable || d.get || d.set || d.value===undefined)
      throw new Error("invalid data field");
  }
}
function __voleHeaderName(name) {
  if(typeof name!=="string" || !/^[!#$%&'*+.^_\x60|~0-9A-Za-z-]+$/.test(name))throw new Error("invalid header name");
  const key=name.toLowerCase();
  if(["host","content-length","transfer-encoding","content-encoding","connection","upgrade","expect","trailer","te","http2-settings","keep-alive","proxy-connection","proxy-authorization","proxy-authenticate","content-range"].includes(key))
    throw new Error("protected header");
  return __voleTextSize(name,false);
}
function __voleHeaderValue(value) {
  if(typeof value!=="string" || /[\x00-\x08\x0a-\x1f\x7f]/.test(value))throw new Error("invalid header value");
  return __voleTextSize(value,false);
}
function __voleHeaders(headers,operations) {
  if(!Array.isArray(headers) || headers.length>100)throw new Error("header count limit");
  let bytes=0, values=0;
  for(const header of headers) {
    __voleTick();
    if(!operations) {
      __voleRecord(header,["name","value"]);
      bytes+=__voleHeaderName(header.name)+__voleHeaderValue(header.value)+32;
      values++;
    } else {
      __voleRecord(header,["op","name","values"]);
      const name=__voleHeaderName(header.name);
      if(header.op==="remove") {
        if(Object.hasOwn(header,"values"))throw new Error("remove values");
        bytes+=name+32;
      } else if(header.op==="set" || header.op==="add") {
        if(!Array.isArray(header.values) || header.values.length===0 || header.values.length>100-values)
          throw new Error("header value count");
        for(const value of header.values) {
          bytes+=name+__voleHeaderValue(value)+32; values++;
          if(bytes>32768)throw new Error("header byte limit");
        }
      } else throw new Error("invalid header operation");
    }
    if(bytes>32768 || values>100)throw new Error("header limit");
  }
}
// Private adapter ABI after Finish; primitive .length creates no API copy.
// No new controlled ticks or user ToPrimitive calls.
function __voleExportTextUnits(s) {
  if(typeof s!=="string" || s.length>__voleLimit)throw new Error("invalid export text");
  return s.length;
}
function __voleFinish(v) {
  if(!v || typeof v!=="object")throw new Error("invalid result");
  // Inspect descriptors before reading type, so a rejected accessor never runs.
  __voleRecord(v,["type","url","method","status","headers","body"]);
  const type=v.type;
  if(type==="pass" || type==="abort")__voleRecord(v,["type"]);
  else if(type==="modify")__voleRecord(v,["type","url","method","status","headers","body"]);
  else if(type==="respond")__voleRecord(v,["type","status","headers","body"]);
  else throw new Error("invalid result type");
  if(Object.hasOwn(v,"url")) {
    if(typeof v.url!=="string" || __voleTextSize(v.url,false)>8192)throw new Error("URL limit");
  }
  if(Object.hasOwn(v,"method")) {
    if(typeof v.method!=="string" || !/^[!#$%&'*+.^_\x60|~0-9A-Za-z-]+$/.test(v.method) || __voleTextSize(v.method,false)>32768)
      throw new Error("invalid method");
  }
  if(Object.hasOwn(v,"status") || type==="respond") {
    if(!Number.isInteger(v.status) || v.status<200 || v.status>599 || (type==="respond" && v.status===206))
      throw new Error("invalid status");
  }
  if(Object.hasOwn(v,"headers"))__voleHeaders(v.headers,type==="modify");
  let body=null;
  if(Object.hasOwn(v,"body")) {
    body=v.body; __voleRecord(body,["kind","data"]);
    if(!Object.hasOwn(body,"data"))throw new Error("missing body data");
    if(body.kind==="text")__voleTextSize(body.data,false);
    else if(body.kind==="bytes")__voleBinarySize(body.data);
    else throw new Error("invalid body kind");
  }
  // The native adapter exports body.data as a separate bounded byte payload.
  // Its remaining JSON metadata must fit before native JSON serialization.
  __voleCharge(__voleMeasure(v,true,body)*2+32);
  return v;
}

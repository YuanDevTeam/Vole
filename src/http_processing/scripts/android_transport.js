// Trusted AndroidX transport. The frontend forbids these names in user code.
const __voleTickLimit = {};
let __voleTicks = 0;
function __voleTick() {
  if (++__voleTicks > 100000) throw __voleTickLimit;
}
function __voleIsASCII() {}
function __voleReplaceASCIIAll() {}

async function __voleTransport(input, hasBody, outputBound) {
  const port = await android.getNamedPort("vole");
  return new Promise((resolve, reject) => {
    port.onmessage = ({data}) => {
      port.onmessage = null;
      try {
        if (!(data instanceof ArrayBuffer) || data.byteLength > __voleLimit ||
            (!hasBody && data.byteLength !== 0))
          throw new Error("invalid body envelope");
        if (hasBody) {
          input.body.data = input.body.kind === "text" ? __voleUTF8Decode(data) : new Uint8Array(data);
        }
        // Input and output transcoding are charged as transport copies.
        // Start user work at the same zero balance as a native engine.
        __voleAllocated = 0;
        __voleTicks = 0;
        const result = __voleFinish(rewrite(input));
        __voleAllocated = 0;
        __voleTicks = 0;
        let body = new ArrayBuffer(0);
        if (Object.hasOwn(result, "body")) {
          const payload = result.body.data;
          let bytes;
          if (result.body.kind === "text") {
            if (__voleTextSize(payload, false) > outputBound)
              throw new Error("body output limit");
            bytes = __voleUTF8Encode(payload);
          } else {
            if (__voleBinarySize(payload) > outputBound)
              throw new Error("body output limit");
            bytes = __voleBytes(payload);
          }
          body = bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength
            ? bytes.buffer
            : bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
          delete result.body.data;
        }
        const metadata = JSON.stringify(result);
        port.postMessage(body);
        resolve(metadata);
      } catch (error) {
        if (error === __voleTickLimit) {
          port.postMessage(new ArrayBuffer(0));
          resolve("vole:timed-out");
        } else {
          reject(error);
        }
      }
    };
    port.postMessage("ready");
  });
}

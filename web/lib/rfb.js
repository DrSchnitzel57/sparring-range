"use client";

// Minimal RFB 3.8 client for the replica's guest consoles.
//
// The server end of this socket is the appliance's RFB relay: it already
// authenticated against the guest's VNC password upstream and tells this
// client "no security" (type 1). That is exactly why a member can watch a
// Windows guest without ever holding its VNC password.
//
// Only Raw encoding (0) is requested: a LAN console has no bandwidth to save,
// and a 40-line pixel path can be read by anyone, unlike a vendored decoder.

const SEC_TYPE_NONE = 1;
const ENCODING_RAW = 0;
const MSG_FRAMEBUFFER_UPDATE = 0;
const MSG_SET_COLOUR_MAP = 1;
const MSG_BELL = 2;
const MSG_SERVER_CUT_TEXT = 3;

function concat(buf, chunk) {
  const out = new Uint8Array(buf.length + chunk.length);
  out.set(buf, 0);
  out.set(chunk, buf.length);
  return out;
}

export class RFBClient {
  constructor({ url, canvas, onStatus }) {
    this.url = url;
    this.canvas = canvas;
    this.onStatus = onStatus || (() => {});
    this.state = "version";
    this.buf = new Uint8Array(0);
    this.ws = null;
    this.width = 0;
    this.height = 0;
    this.pixelFormat = null;
    this.imageData = null;
    this.buttons = 0;
    this.sendIncremental = true;
  }

  connect() {
    const ws = new WebSocket(this.url);
    ws.binaryType = "arraybuffer";
    this.ws = ws;
    ws.onopen = () => {
      this.onStatus("connected");
      this._write(new TextEncoder().encode("RFB 003.008\n"));
      this._loop();
    };
    ws.onmessage = (ev) => {
      this.buf = concat(this.buf, new Uint8Array(ev.data));
      this._loop();
    };
    ws.onclose = () => this.onStatus("disconnected");
    ws.onerror = () => this.onStatus("connection error");
  }

  close() {
    if (this.ws) { try { this.ws.close(); } catch { /* already gone */ } }
    this.ws = null;
  }

  _write(bytes) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) this.ws.send(bytes);
  }

  // ---------------------------------------------------------- protocol ---

  _loop() {
    for (;;) {
      const before = this.buf.length;
      if (!this._step()) return;         // need more bytes
      if (this.buf.length === before) return;
    }
  }

  _step() {
    const b = this.buf;
    switch (this.state) {
      case "version": {
        if (b.length < 12) return false;
        this.buf = b.slice(12);
        this.state = "security";
        this.onStatus("negotiating");
        return true;
      }
      case "security": {
        if (b.length < 1) return false;
        const count = b[0];
        if (b.length < 1 + count) return false;
        this.buf = b.slice(1 + count);
        if (!b.slice(1, 1 + count).includes(SEC_TYPE_NONE)) {
          this.onStatus("relay offered no None security");
          this.close();
          return false;
        }
        this._write(new Uint8Array([SEC_TYPE_NONE]));
        this.state = "authresult";
        return true;
      }
      case "authresult": {
        if (b.length < 4) return false;
        const result = new DataView(b.buffer, b.byteOffset, 4).getUint32(0);
        this.buf = b.slice(4);
        if (result !== 0) {
          this.onStatus(`authentication failed (${result})`);
          this.close();
          return false;
        }
        this.state = "serverinit";
        return true;
      }
      case "serverinit": {
        if (b.length < 24) return false;
        const dv = new DataView(b.buffer, b.byteOffset, b.length);
        this.width = dv.getUint16(0);
        this.height = dv.getUint16(2);
        this.pixelFormat = {
          bpp: b[4], depth: b[5], bigEndian: b[6] === 1,
          rmax: dv.getUint16(8), gmax: dv.getUint16(10), bmax: dv.getUint16(12),
          rshift: b[14], gshift: b[15], bshift: b[16],
        };
        const nameLen = dv.getUint32(20);
        if (b.length < 24 + nameLen) return false;
        this.buf = b.slice(24 + nameLen);
        this._setupCanvas();
        this._sendEncodings();
        this._sendUpdateRequest();
        this.state = "normal";
        this.onStatus(`connected (${this.width}x${this.height})`);
        return true;
      }
      case "normal": {
        if (b.length < 1) return false;
        const type = b[0];
        if (type === MSG_FRAMEBUFFER_UPDATE) {
          if (b.length < 4) return false;
          const rects = new DataView(b.buffer, b.byteOffset).getUint16(2);
          let off = 4;
          // only Raw: every rect contributes a known number of bytes
          const bpp = Math.ceil(this.pixelFormat.bpp / 8);
          for (let i = 0; i < rects; i++) {
            if (b.length < off + 12) return false;
            const dv = new DataView(b.buffer, b.byteOffset + off);
            const w = dv.getUint16(4), h = dv.getUint16(6);
            const enc = dv.getUint32(8);
            if (enc !== ENCODING_RAW) {
              this.onStatus(`unsupported encoding ${enc}`);
              this.close();
              return false;
            }
            const size = w * h * bpp;
            if (b.length < off + 12 + size) return false;
            this._paint(dv.getUint16(0), dv.getUint16(2), w, h,
                        b.slice(off + 12, off + 12 + size), bpp);
            off += 12 + size;
          }
          this.buf = b.slice(off);
          this._sendUpdateRequest();
          return true;
        }
        if (type === MSG_BELL) {
          this.buf = b.slice(1);
          return true;
        }
        if (type === MSG_SET_COLOUR_MAP) {
          if (b.length < 6) return false;
          const n = new DataView(b.buffer, b.byteOffset).getUint16(4);
          const need = 6 + n * 6;
          if (b.length < need) return false;
          this.buf = b.slice(need);
          return true;
        }
        if (type === MSG_SERVER_CUT_TEXT) {
          if (b.length < 8) return false;
          const len = new DataView(b.buffer, b.byteOffset).getUint32(4);
          const need = 8 + len;
          if (b.length < need) return false;
          this.buf = b.slice(need);
          return true;
        }
        this.onStatus(`unknown server message ${type}`);
        this.close();
        return false;
      }
      default:
        return false;
    }
  }

  // ----------------------------------------------------------- surface ---

  _setupCanvas() {
    this.canvas.width = this.width;
    this.canvas.height = this.height;
    this.ctx = this.canvas.getContext("2d");
    this.imageData = this.ctx.createImageData(this.width, this.height);
    const pf = this.pixelFormat;
    this.bytesPerPixel = Math.ceil(pf.bpp / 8);
    this.scale = {
      r: pf.rmax ? 255 / pf.rmax : 1, g: pf.gmax ? 255 / pf.gmax : 1,
      b: pf.bmax ? 255 / pf.bmax : 1,
    };
    this.canvas.tabIndex = 0;
    this._wireInput();
    this.onStatus(`console ${this.width}x${this.height}`);
  }

  _paint(x, y, w, h, pixels, bpp) {
    const pf = this.pixelFormat;
    const img = this.imageData.data;
    const dv = new DataView(pixels.buffer, pixels.byteOffset, pixels.length);
    const big = pf.bigEndian;
    const read = (i) => (bpp === 4
      ? (big ? dv.getUint32(i) : dv.getUint32(i, true))
      : (big ? dv.getUint16(i) : dv.getUint16(i, true)));
    const to8 = (v, max, scale) => (max ? Math.round(v * scale) : Math.round(v));
    const cw = this.width;
    const maxIn = (max) => (max || 255);
    for (let row = 0; row < h; row++) {
      const srcRow = row * w * bpp;
      const dstRow = ((y + row) * cw + x) * 4;
      for (let col = 0; col < w; col++) {
        const v = read(srcRow + col * bpp);
        const r = Math.max(0, Math.min(255, to8(
          (v >> pf.rshift) & maxIn(pf.rmax), pf.rmax, this.scale.r)));
        const g = Math.max(0, Math.min(255, to8(
          (v >> pf.gshift) & maxIn(pf.gmax), pf.gmax, this.scale.g)));
        const b = Math.max(0, Math.min(255, to8(
          (v >> pf.bshift) & maxIn(pf.bmax), pf.bmax, this.scale.b)));
        const o = dstRow + col * 4;
        img[o] = r;
        img[o + 1] = g;
        img[o + 2] = b;
        img[o + 3] = 255;
      }
    }
    this.ctx.putImageData(this.imageData, 0, 0);
  }

  // ------------------------------------------------------------ input ---

  _wireInput() {
    const canvas = this.canvas;
    const pos = (ev) => {
      const r = canvas.getBoundingClientRect();
      return {
        x: Math.round((ev.clientX - r.left) * (this.width / r.width)),
        y: Math.round((ev.clientY - r.top) * (this.height / r.height)),
      };
    };
    canvas.addEventListener("mousemove", (ev) => {
      const { x, y } = pos(ev);
      this._pointer(x, y, this.buttons);
    });
    canvas.addEventListener("mousedown", (ev) => {
      this.buttons |= (1 << ev.button) || 1;
      const { x, y } = pos(ev);
      this._pointer(x, y, this.buttons);
    });
    canvas.addEventListener("mouseup", (ev) => {
      this.buttons &= ~(1 << ev.button);
      const { x, y } = pos(ev);
      this._pointer(x, y, this.buttons);
    });
    canvas.addEventListener("keydown", (ev) => {
      this._key(ev.keyCode || ev.which, true);
      if (ev.keyCode >= 32) ev.preventDefault();
    });
    canvas.addEventListener("keyup", (ev) => {
      this._key(ev.keyCode || ev.which, false);
    });
  }

  _pointer(x, y, mask) {
    const b = new Uint8Array(6);
    b[0] = 5; b[1] = mask & 0xff;
    b[2] = (x >> 8) & 0xff; b[3] = x & 0xff;
    b[4] = (y >> 8) & 0xff; b[5] = y & 0xff;
    this._write(b);
  }

  _key(code, down) {
    const b = new Uint8Array(7);
    b[0] = 4; b[1] = down ? 1 : 0;
    b[3] = (code >> 24) & 0xff; b[4] = (code >> 16) & 0xff;
    b[5] = (code >> 8) & 0xff; b[6] = code & 0xff;
    this._write(b);
  }

  // ----------------------------------------------------------- requests ---

  _sendEncodings() {
    const b = new Uint8Array(20);
    b[0] = 2; b[3] = 1;              // SetEncodings: one entry
    b[19] = ENCODING_RAW;
    this._write(b);
  }

  _sendUpdateRequest() {
    const b = new Uint8Array(10);
    b[0] = 3;                        // FramebufferUpdateRequest
    b[1] = this.sendIncremental ? 1 : 0;
    b[2] = this.width >> 8; b[3] = this.width & 0xff;
    b[4] = this.height >> 8; b[5] = this.height & 0xff;
    this._write(b);
    this.sendIncremental = true;
  }
}

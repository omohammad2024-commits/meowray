
// QR Code generator written for MeowRay: byte mode, error level M,
// versions 1–8 (up to ~150 chars — plenty for a subscription URL).
// No memorized format/version tables: format and version info are computed
// with their BCH codes; Reed–Solomon runs over GF(256)/0x11d. The encoder is
// cross-validated module-for-module against Nayuki's qrcodegen in the test
// suite (tests/qr-check.js, dev-only; segno was rejected as reference — it
// emits a non-spec 0x00 pad byte on byte-boundary payloads).

const QR_TABLE = {
  1: { total: 26, ec: 10, groups: [[1, 16]], align: [], rem: 0 },
  2: { total: 44, ec: 16, groups: [[1, 28]], align: [6, 18], rem: 7 },
  3: { total: 70, ec: 26, groups: [[1, 44]], align: [6, 22], rem: 7 },
  4: { total: 100, ec: 18, groups: [[2, 32]], align: [6, 26], rem: 7 },
  5: { total: 134, ec: 24, groups: [[2, 43]], align: [6, 30], rem: 7 },
  6: { total: 172, ec: 16, groups: [[4, 27]], align: [6, 34], rem: 7 },
  7: { total: 196, ec: 18, groups: [[4, 31]], align: [6, 22, 38], rem: 0 },
  8: { total: 242, ec: 22, groups: [[2, 38], [2, 39]], align: [6, 24, 42], rem: 0 },
};
const GF_EXP = new Array(512);
const GF_LOG = new Array(256);
(function initGf() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x; GF_LOG[x] = i;
    x <<= 1; if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255];
})();
function gfMul(a, b) { return a === 0 || b === 0 ? 0 : GF_EXP[GF_LOG[a] + GF_LOG[b]]; }
function rsGenerator(deg) {
  // g(x) = Π_{i=0}^{deg-1} (x − α^i); coefficients in descending order.
  let poly = [1];
  for (let i = 0; i < deg; i++) {
    const next = new Array(poly.length + 1).fill(0);
    for (let j = 0; j < next.length; j++) {
      const fromX = j < poly.length ? poly[j] : 0;              // x · P term
      const fromRoot = j > 0 ? gfMul(poly[j - 1], GF_EXP[i]) : 0; // α^i · P term
      next[j] = fromX ^ fromRoot;
    }
    poly = next;
  }
  return poly;
}
function rsRemainder(data, gen) {
  const res = new Array(gen.length - 1).fill(0);
  for (const b of data) {
    const factor = b ^ res.shift();
    res.push(0);
    for (let i = 0; i < gen.length - 1; i++) res[i] ^= gfMul(gen[i + 1], factor);
  }
  return res;
}
function qrDataCodewords(bytes, version) {
  const info = QR_TABLE[version];
  const totalData = info.groups.reduce((s, [c, n]) => s + c * n, 0);
  const bits = [];
  const push = (val, len) => { for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1); };
  push(0b0100, 4); // byte mode
  push(bytes.length, 8); // length (versions 1–9 use 8 bits in byte mode)
  for (const b of bytes) push(b, 8);
  const capacity = totalData * 8;
  const term = Math.min(4, capacity - bits.length);
  for (let i = 0; i < term; i++) bits.push(0);
  while (bits.length % 8 !== 0) bits.push(0);
  const pads = [0xec, 0x11];
  let pi = 0;
  while (bits.length < capacity) { push(pads[pi % 2], 8); pi++; }
  const out = [];
  for (let i = 0; i < bits.length; i += 8) {
    let v = 0; for (let j = 0; j < 8; j++) v = (v << 1) | bits[i + j];
    out.push(v);
  }
  return out;
}
function qrInterleave(dataCw, version) {
  const info = QR_TABLE[version];
  const gen = rsGenerator(info.ec);
  const dataBlocks = [];
  const ecBlocks = [];
  let off = 0;
  for (const [count, per] of info.groups) {
    for (let i = 0; i < count; i++) {
      const block = dataCw.slice(off, off + per); off += per;
      dataBlocks.push(block);
      ecBlocks.push(rsRemainder(block, gen));
    }
  }
  const out = [];
  const maxData = Math.max(...dataBlocks.map((b) => b.length));
  for (let i = 0; i < maxData; i++) for (const b of dataBlocks) if (i < b.length) out.push(b[i]);
  for (let i = 0; i < info.ec; i++) for (const b of ecBlocks) out.push(b[i]);
  return { codewords: out, remainderBits: info.rem }; // remainder bits are appended as 0 bits by the matrix builder
}
function qrFormatBits(mask) {
  const data = mask; // EC level M indicator bits are 00, so data = 0b00<<3 | mask
  let rem = data << 10;
  const g = 0b10100110111;
  for (let i = 14; i >= 10; i--) if ((rem >>> i) & 1) rem ^= g << (i - 10);
  return (((data << 10) | rem) ^ 0b101010000010010).toString(2).padStart(15, "0");
}
function qrVersionBits(version) {
  let rem = version << 12;
  const g = 0x1f25;
  for (let i = 17; i >= 12; i--) if ((rem >>> i) & 1) rem ^= g << (i - 12);
  return ((version << 12) | rem).toString(2).padStart(18, "0");
}
function qrBuildMatrix(version, codewords, remBits, mask) {
  const size = version * 4 + 17;
  const m = Array.from({ length: size }, () => new Array(size).fill(null));
  const set = (r, c, v) => { if (r >= 0 && r < size && c >= 0 && c < size) m[r][c] = v; };
  function finder(r0, c0) {
    for (let r = -1; r < 8; r++) for (let c = -1; c < 8; c++) {
      const inside = r >= 0 && r < 7 && c >= 0 && c < 7;
      const border = inside && (r === 0 || r === 6 || c === 0 || c === 6);
      const core = r >= 2 && r <= 4 && c >= 2 && c <= 4;
      set(r0 + r, c0 + c, inside ? (border || core ? 1 : 0) : 0);
    }
  }
  finder(0, 0); finder(0, size - 7); finder(size - 7, 0);
  const info = QR_TABLE[version];
  for (const r of info.align) for (const c of info.align) {
    if (m[r] && m[r][c] !== null) continue; // overlaps finder areas
    // skip positions overlapping finder patterns
    if ((r < 9 && c < 9) || (r < 9 && c > size - 10) || (r > size - 10 && c < 9)) continue;
    for (let dr = -2; dr <= 2; dr++) for (let dc = -2; dc <= 2; dc++) {
      set(r + dr, c + dc, Math.max(Math.abs(dr), Math.abs(dc)) !== 1 ? 1 : 0);
    }
  }
  for (let i = 8; i < size - 8; i++) { if (m[6][i] === null) m[6][i] = i % 2 === 0 ? 1 : 0; if (m[i][6] === null) m[i][6] = i % 2 === 0 ? 1 : 0; }
  // reserve format info cells
  for (let i = 0; i < 9; i++) { if (m[8][i] === null) m[8][i] = 0; if (m[i][8] === null) m[i][8] = 0; }
  for (let i = 0; i < 8; i++) { if (m[8][size - 1 - i] === null) m[8][size - 1 - i] = 0; if (m[size - 1 - i][8] === null) m[size - 1 - i][8] = 0; }
  m[size - 8][8] = 1; // dark module
  if (version >= 7) {
    const bits = qrVersionBits(version);
    for (let i = 0; i < 18; i++) {
      const v = Number(bits[17 - i]);
      m[Math.floor(i / 3)][size - 11 + (i % 3)] = v;
      m[size - 11 + (i % 3)][Math.floor(i / 3)] = v;
    }
  }
  // data bits (codewords + remainder), MSB first
  const bits = [];
  for (const cw of codewords) for (let i = 7; i >= 0; i--) bits.push((cw >>> i) & 1);
  for (let i = 0; i < remBits; i++) bits.push(0);
  const maskFn = [
    (r, c) => (r + c) % 2 === 0, (r) => r % 2 === 0, (r, c) => c % 3 === 0,
    (r, c) => (r + c) % 3 === 0, (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
    (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
    (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
    (r, c) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0,
  ][mask];
  let bi = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const c = right - j;
        const upward = ((right + 1) & 2) === 0;
        const r = upward ? size - 1 - vert : vert;
        if (m[r][c] === null) {
          let v = bi < bits.length ? bits[bi++] : 0;
          if (maskFn(r, c)) v ^= 1;
          m[r][c] = v;
        }
      }
    }
  }
  // format info placement (bit(i) = the i-th format bit, 14 = MSB)
  const fb = qrFormatBits(mask);
  const bit = (i) => Number(fb[14 - i]);
  for (let i = 0; i <= 5; i++) m[8][i] = bit(14 - i);   // (8,0..5) = bits 14..9
  m[8][7] = bit(8); m[8][8] = bit(7); m[7][8] = bit(6);
  for (let i = 9; i < 15; i++) m[14 - i][8] = bit(14 - i); // (5..0,8) = bits 5..0
  for (let i = 0; i < 7; i++) m[size - 1 - i][8] = bit(14 - i); // (size-1..size-7,8) = bits 14..8
  for (let i = 0; i < 8; i++) m[8][size - 8 + i] = bit(7 - i);  // (8,size-8..size-1) = bits 7..0
  m[size - 8][8] = 1;
  return m;
}
function qrPenalty(m) {
  const size = m.length;
  let penalty = 0;
  const lines = [];
  for (let i = 0; i < size; i++) { lines.push(m[i]); lines.push(m.map((row) => row[i])); }
  for (const line of lines) {
    let run = 1;
    for (let i = 1; i <= line.length; i++) {
      if (i < line.length && line[i] === line[i - 1]) run++;
      else { if (run >= 5) penalty += 3 + (run - 5); run = 1; }
    }
    // rule 3: finder-like patterns with 4-module quiet zone
    const s = line.join("");
    for (let i = 0; i + 11 <= s.length; i++) {
      const w = s.slice(i, i + 11);
      if (w === "10111010000" || w === "00001011101") penalty += 40;
    }
  }
  for (let r = 0; r < size - 1; r++) for (let c = 0; c < size - 1; c++) {
    const v = m[r][c];
    if (m[r][c + 1] === v && m[r + 1][c] === v && m[r + 1][c + 1] === v) penalty += 3;
  }
  let dark = 0;
  for (const row of m) for (const v of row) dark += v;
  const total = size * size;
  const percent = Math.floor((dark * 100) / total);
  const lower = Math.floor(percent / 5) * 5;
  const upper = lower + 5;
  const k = Math.min(Math.abs(lower - 50), Math.abs(upper - 50)) / 5;
  penalty += k * 10;
  return penalty;
}
// qrMatrix(text) → 2D array of 0/1 (no quiet zone). Throws if too long.
function qrTotalData(version) {
  return QR_TABLE[version].groups.reduce((s, [c, n]) => s + c * n, 0);
}
function qrMatrix(text) {
  const bytes = Array.from(Buffer.from(String(text), "utf8"));
  for (let version = 1; version <= 8; version++) {
    const info = QR_TABLE[version];
    const totalData = info.groups.reduce((s, [c, n]) => s + c * n, 0);
    if (bytes.length + 2 > totalData) continue;
    const dataCw = qrDataCodewords(bytes, version);
    const { codewords, remainderBits } = qrInterleave(dataCw, version);
    let best = null, bestPenalty = Infinity;
    for (let mask = 0; mask < 8; mask++) {
      const matrix = qrBuildMatrix(version, codewords, remainderBits, mask);
      const p = qrPenalty(matrix);
      if (p < bestPenalty) { bestPenalty = p; best = matrix; }
    }
    return best;
  }
  throw new Error("text too long for QR (max ~150 chars)");
}
function qrSvg(text, scale) {
  const matrix = qrMatrix(text);
  const size = matrix.length;
  const q = 4; // quiet zone
  const s = scale || 4;
  const dim = (size + q * 2) * s;
  let d = "";
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (matrix[r][c]) d += "M" + (c + q) * s + " " + (r + q) * s + "h" + s + "v" + s + "h-" + s + "z";
    }
  }
  return '<svg xmlns="http://www.w3.org/2000/svg" width="' + dim + '" height="' + dim + '" viewBox="0 0 ' + dim + " " + dim + '"><rect width="' + dim + '" height="' + dim + '" fill="#ffffff"/><path d="' + d + '" fill="#0b0f14"/></svg>';
}

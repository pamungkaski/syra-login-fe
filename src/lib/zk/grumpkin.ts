
// -------------------------------------------------------------------
//  pure-JS Grumpkin helpers (no external curve libraries required)
// -------------------------------------------------------------------
import { sha256 }      from '@noble/hashes/sha2';
import { utf8ToBytes } from '@noble/hashes/utils';

export const P  = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const GX = 1n;
const GY = 17631683881184975370165255887551781615748388533673675138860n; // √(-16) mod p
const G  = { x: GX, y: GY, infinity: false };

const mod  = (n: bigint) => ((n % P) + P) % P;
const inv  = (a: bigint) => {
    // extended-Euclid mod inverse
    let t = 0n, newT = 1n, r = P, newR = mod(a);
    while (newR) { const q = r / newR; [t, newT] = [newT, t - q * newT];
        [r, newR] = [newR, r - q * newR]; }
    return mod(t);
};

export type Point = { x: bigint; y: bigint; infinity: boolean };

export function add(P1: Point, P2: Point): Point {
    if (P1.infinity) return P2;
    if (P2.infinity) return P1;
    if (P1.x === P2.x) {
        if ((P1.y + P2.y) % P === 0n) return { x: 0n, y: 0n, infinity: true }; // P + (-P)
        // doubling
        const m  = mod((3n * P1.x * P1.x) * inv(2n * P1.y));
        const x3 = mod(m * m - 2n * P1.x);
        const y3 = mod(m * (P1.x - x3) - P1.y);
        return { x: x3, y: y3, infinity: false };
    }
    // normal add
    const m  = mod((P2.y - P1.y) * inv(P2.x - P1.x));
    const x3 = mod(m * m - P1.x - P2.x);
    const y3 = mod(m * (P1.x - x3) - P1.y);
    return { x: x3, y: y3, infinity: false };
}

export function mul(k: bigint, P0: Point): Point {
    let P = P0, Q: Point = { x: 0n, y: 0n, infinity: true };
    while (k) {
        if (k & 1n) Q = add(Q, P);
        P = add(P, P);
        k >>= 1n;
    }
    return Q;
}

export function eq(P: Point, Q: Point): boolean {
    if (P.infinity && Q.infinity) return true;
    if (P.infinity || Q.infinity) return false;
    return P.x === Q.x && P.y === Q.y;   // coordinates are already mod p
}

// bigint → fixed-length big-endian byte array
function bigintToBytes(n: bigint, len: number): Uint8Array {
    const hex = n.toString(16).padStart(len * 2, '0');    // zero-pad
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
}

/**
 * Serialize a Grumpkin point as 64-byte uncompressed `x‖y` big-endian.
 * If `infinity === true`, returns 64 zero bytes (fits circuit checks).
 */
export function serialize(P: Point): Uint8Array {
    if (P.infinity) return new Uint8Array(64);            // special case ∞
    const xBytes = bigintToBytes(P.x, 32);                // 32 × 8 = 256 bits
    const yBytes = bigintToBytes(P.y, 32);
    const out    = new Uint8Array(64);
    out.set(xBytes, 0);
    out.set(yBytes, 32);
    return out;
}

// ---------------- hash-to-scalar then onto Grumpkin -----------------
export function seedToGrumpkinPoint(seed: string): Point {
    const h  = sha256(utf8ToBytes(seed));
    const k  = (BigInt('0x' + Buffer.from(h).toString('hex')) % P) || 1n;
    return mul(k, G);               // k·G  — guaranteed on-curve
}

export const isOnGrumpkin = (P: Point) =>
    mod(P.y * P.y) === mod(P.x * P.x * P.x - 17n);

export function decimalStringToField(str: string): bigint {
    let acc = 0n;
    for (const byte of Buffer.from(str, 'utf8')) {
        acc = (acc << 8n) + BigInt(byte);        // ×256 + byte
    }
    // sub ≤ 100 bytes ⇒ acc < 256¹⁰⁰ < p, so %p is optional
    return acc || 1n;                          // avoid zero
}
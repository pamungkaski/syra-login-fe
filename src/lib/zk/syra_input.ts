import { blake2b } from "blakejs";
import { Buffer } from "buffer";
import { RSAPublicKey } from "@zk-email/jwt-tx-builder-helpers/src/types";

// Pull out exactly what we need from the bls12_381 bundle
import { bls12_381 } from "@noble/curves/bls12-381";
import {decimalStringToField} from "@/lib/zk/grumpkin";
const { G1, G2, pairing, utils: blsUtils, fields } = bls12_381;
const { Fr, Fp12 } = fields;
const Fr_ORDER = Fr.ORDER;

const TAG = new TextEncoder().encode("syra-user-id");

/** Deterministic hash-to-field:  sub  →  s ∈ Fr  (never 0). */
export function sFromSub(sub: string): bigint {
    return decimalStringToField(sub)
}

/** “FRO”: hash ctx → Z ∈ G1 via hash-to-curve */
function froHashToG1(ctx: string) {
    // must pass a Uint8Array
    const msg = new TextEncoder().encode(ctx);
    return G1.hashToCurve(msg);
}

/**
 * Parse your single-blob `ivkHex` into its five compressed elements:
 *  G1 (48 bytes), G2 (96 bytes), G2 (96 bytes), G1 (48 bytes), G2 (96 bytes)
 */
function parseIvk(ivkHex: string) {
    // hex lengths: 48 bytes→96 chars, 96 bytes→192 chars, etc.
    const cuts = [96, 288, 480, 576, 768];
    const parts = cuts.map((c, i) =>
        ivkHex.slice(i === 0 ? 0 : cuts[i - 1], c)
    );
    const [h1, h2, h3, h4, h5] = parts;
    return {
        g1:      G1.ProjectivePoint.fromHex(h1),
        g2:      G2.ProjectivePoint.fromHex(h2),
        ivk_hat: G2.ProjectivePoint.fromHex(h3),
        W:       G1.ProjectivePoint.fromHex(h4),
        W_hat:   G2.ProjectivePoint.fromHex(h5),
    };
}

function sToLeBytes(s: bigint): Uint8Array {
    const bytes = [];
    let x = s;
    for (let i = 0; i < 32; i++) {
        bytes.push(Number(x & 0xffn));
        x >>= 8n;
    }
    return Uint8Array.from(bytes);   // LE, 32 bytes
}

/**
 * Generate a flat map of **numeric** signals (all JS `bigint`).
 */
export async function generateCircomSignals(
    ivkHex: string,
    uskHex: string,
    uskHatHex: string,
    jwt: string,
    jwtPubKey: RSAPublicKey,
    claims: Record<string, any>,
    message: string,
    jwtProof: string,
): Promise<Record<string, any>> {
    if (!ivkHex || !uskHex || !uskHatHex) {
        throw new Error("missing ivk/usk/uskHat");
    }

    // 1) s = H_to_Fr(sub)
    const s = sFromSub(claims.sub);

    //
    // 2) ctx = aud + iss
    const ctx = claims.aud + claims.iss;

    // 3) Z ∈ G1 via FRO
    const Z_h2c   = froHashToG1(ctx);
    const Z_affine = Z_h2c.toAffine();
    const Z   = G1.ProjectivePoint.fromAffine(Z_affine);

    // 4) parse all group elements
    const { g1, g2, ivk_hat, W, W_hat } = parseIvk(ivkHex);
    const usk     = G1.ProjectivePoint.fromHex(uskHex);
    const usk_hat = G2.ProjectivePoint.fromHex(uskHatHex);

    // 5) T = e(Z, usk_hat) → Fp12, then to bytes → bigint
    const T   = pairing(Z, usk_hat);

    // 6) sample random α, β ∈ Fr
    const alpha = BigInt("0x" + Buffer.from(blsUtils.randomPrivateKey()).toString("hex")) % Fr_ORDER;
    const beta  = BigInt("0x" + Buffer.from(blsUtils.randomPrivateKey()).toString("hex")) % Fr_ORDER;

    // 7) C = (g1^β, W^β · usk)
    const C1 = g1.multiply(beta);
    const C2 = W.multiply(beta).add(usk);

    // 8) Ĉ = (g2^α, W_hat^α · usk_hat)
    const C1hat = g2.multiply(alpha);
    const C2hat = W_hat.multiply(alpha).add(usk_hat);

    const ctxBytes = Array.from(
        new TextEncoder().encode(claims.aud + claims.iss)
    );
    const ctxLen   = ctxBytes.length;

    const mBytes = Array.from(
        new TextEncoder().encode(message)
    );
    const mLen   = mBytes.length;

    // const jwtProofBytes = Array.from(
    //     new TextEncoder().encode(jwtProof)
    // );

    // 10) flatten everything into a Record<string,bigint>
    return {
        Z,
        C1,
        C2,
        g1,
        g2,

        W,
        W_hat,
        C1hat,
        C2hat,
        ivk_hat,

        T,

        ctx:     ctxBytes,
        ctxLen:  ctxLen,
        m:       mBytes,
        mLen:    mLen,
        jwtProof: null,
        s,
        alpha,
        beta,

        // JWT‐related
        // nonce: BigInt("0x" + Buffer.from(claims.nonce).toString("hex")),
        nonce: "nonce",
    };
}

import { bls12_381 } from "@noble/curves/bls12-381";
import { blake2b }      from "blakejs";
import { concatBytes } from "@noble/hashes/utils";
import {ProjPointType} from "@noble/curves/abstract/weierstrass";
import {Buffer} from "buffer";

const { G1, G2, pairing, utils: blsUtils, fields } = bls12_381;
const { Fr, Fp12, Fp2 } = fields;

import {add as grAdd, mul as grMul, P as GRUMPKIN_P, Point as GrPoint} from './grumpkin'
import { add, mul, eq, serialize } from './grumpkin';
import {randomBytes} from "crypto";

const Fr_ORDER = GRUMPKIN_P;

export const toBytes = (P: GrPoint) => serialize(P);

type Bytes = Uint8Array;

export interface Statement {
    Z:        ProjPointType<bigint>;
    g1:       ProjPointType<bigint>;
    g2:       ProjPointType<Fp2>;
    ivk_hat:  ProjPointType<Fp2>;
    W:        ProjPointType<bigint>;
    W_hat:    ProjPointType<Fp2>;

    C1:       ProjPointType<bigint>;
    C2:       ProjPointType<bigint>;
    C1hat:   ProjPointType<Fp2>;
    C2hat:   ProjPointType<Fp2>;

    T:        Fp12;

    // bridge related
    bridge:  GrPoint;
    g3:      GrPoint;
    g4:      GrPoint;

    ctx:      Bytes;
    m:        Bytes;
    jwtProof: Bytes
}

export interface Witness {
    alpha: bigint;
    beta:  bigint;
    s:     bigint;
    r:     bigint; // bridge
}

export interface Proof {
    Statement: Statement,
    K1: Fp12,
    K2: Fp12,
    tC1:       ProjPointType<bigint>;
    tC1hat:       ProjPointType<Fp2>;
    tB:          Fp12;
    tE:          Fp12;
    tH:          Fp12;
    tK1:         Fp12;
    tK2:         Fp12;
    tK2Product:  Fp12;
    tBridge:  GrPoint;

    respAlpha?:       bigint;
    respBeta?:        bigint;
    respS?:           bigint;
    respBetaTimesS?:  bigint;
    respR1?:          bigint;
    respR2?:          bigint;
    respR3?:          bigint;
    respR?:      bigint;
}

export interface Prover {
    Proof: Proof;
    blindingAlpha:       bigint;
    blindingBeta:        bigint;
    blindingS:           bigint;
    blindingOmega:       bigint;  // β·s blinding
    blindingR1:          bigint;
    blindingR2:          bigint;
    blindingR3:          bigint;
    blindingR:   bigint;
    beta:           bigint;
    alpha:          bigint;
    omega:          bigint;
    r1:          bigint;
    r2:          bigint;
    r3:          bigint;
    s: bigint;
    r: bigint;
}

export function computeRandomOracleChallenge(transcript: Uint8Array): bigint {
    const hash = blake2b(transcript, undefined, 64);
    const hex  = Buffer.from(hash).toString("hex");
    return BigInt("0x" + hex) % Fr.ORDER;
}

export function computeChallengeContribution(
    P: Proof,
): Bytes {
    return concatBytes(
        P.Statement.Z.toRawBytes(true),
        Fp12.toBytes(P.Statement.T),
        P.Statement.C1.toRawBytes(true),
        P.Statement.C2.toRawBytes(true),
        P.Statement.C1hat.toRawBytes(true),
        P.Statement.C2hat.toRawBytes(true),
        Fp12.toBytes(P.K1),
        Fp12.toBytes(P.K2),
        P.tC1.toRawBytes(true),
        P.tC1hat.toRawBytes(true),
        Fp12.toBytes(P.tB),
        Fp12.toBytes(P.tE),
        Fp12.toBytes(P.tH),
        Fp12.toBytes(P.tK1),
        Fp12.toBytes(P.tK2),
        Fp12.toBytes(P.tK2Product),
        toBytes(P.tBridge),
        toBytes(P.Statement.bridge)
    );
}

export function init(s: Statement, w: Witness): Prover {
    const { alpha, beta, s: ss } = w;

    const A = pairing(s.Z, s.W_hat);

    const E1 = pairing(s.C2, s.g2);
    const E2 = pairing(s.g1.negate(), s.C2hat);
    const E = Fp12.mul(E1, E2);
    const J = pairing(s.C2, s.g2.negate());

    const F = pairing(s.W, s.g2);
    const G = pairing(s.g1.negate(), s.W_hat);
    const I = pairing(s.W, s.ivk_hat);

    const r1 = BigInt("0x" + Buffer.from(blsUtils.randomPrivateKey()).toString("hex")) % Fr_ORDER;
    const r2 = BigInt("0x" + Buffer.from(blsUtils.randomPrivateKey()).toString("hex")) % Fr_ORDER;
    const r3 = Fr.sub(r2, Fr.mul(alpha, ss));
    const K1 = Fp12.mul(Fp12.pow(F, ss), Fp12.pow(G, r1));
    const omega = Fr.mul(beta, ss);
    const K2 = Fp12.mul(Fp12.pow(F, omega), Fp12.pow(G, r2));

    const blindingAlpha        = BigInt("0x" + Buffer.from(blsUtils.randomPrivateKey()).toString("hex")) % Fr_ORDER;
    const blindingBeta         = BigInt("0x" + Buffer.from(blsUtils.randomPrivateKey()).toString("hex")) % Fr_ORDER;
    const blindingS            = BigInt("0x" + Buffer.from(blsUtils.randomPrivateKey()).toString("hex")) % Fr_ORDER;


    const blindingOmega        = BigInt("0x" + Buffer.from(blsUtils.randomPrivateKey()).toString("hex")) % Fr_ORDER;
    const blindingR1           = BigInt("0x" + Buffer.from(blsUtils.randomPrivateKey()).toString("hex")) % Fr_ORDER;
    const blindingR2           = BigInt("0x" + Buffer.from(blsUtils.randomPrivateKey()).toString("hex")) % Fr_ORDER;
    const blindingR3           = BigInt("0x" + Buffer.from(blsUtils.randomPrivateKey()).toString("hex")) % Fr_ORDER;
    const blindingR            = (BigInt('0x' + randomBytes(32).toString('hex')) % GRUMPKIN_P); // new

    const tC1 = s.g1.multiply(blindingBeta);
    const tC1hat = s.g2.multiply(blindingAlpha);
    const tB = Fp12.pow(A, blindingAlpha);
    const tE = Fp12.mul(Fp12.pow(F, blindingBeta), Fp12.pow(G, blindingAlpha));
    const FBS = Fp12.pow(F, blindingOmega)
    const tH = Fp12.mul(Fp12.mul(Fp12.pow(I, blindingBeta), FBS), Fp12.pow(J, blindingS));
    const tK1 = Fp12.mul(Fp12.pow(F, blindingS), Fp12.pow(G, blindingR1));
    const tK2 = Fp12.mul(FBS, Fp12.pow(G, blindingR2));
    const tK2Product = Fp12.mul(Fp12.pow(E, blindingS), Fp12.pow(G, blindingR3));

    // bridge between jwt and syra signature g3^s * g4^r
    const tBridge   = add(
        mul(blindingS, s.g3),
        mul(blindingR, s.g4)
    );

    let P : Proof = {
        Statement: s,
        K1,
        K2,
        tC1,
        tC1hat,
        tB,
        tE,
        tH,
        tK1,
        tK2,
        tK2Product,
        tBridge,
    }
    // responses
    return {
        Proof: P,
        blindingAlpha,
        blindingBeta,
        blindingOmega,
        blindingR1,
        blindingS,
        blindingR2,
        blindingR3,
        blindingR,
        beta,
        alpha,
        omega,
        s: ss,
        r1,
        r2,
        r3,
        r: w.r,
    };
}

export function prove(p: Prover, c: bigint): Proof {
    p.Proof.respBeta       = Fr.add(p.blindingBeta,     Fr.mul(p.beta,        c));
    p.Proof.respAlpha      = Fr.add(p.blindingAlpha,    Fr.mul(p.alpha,       c));
    p.Proof.respS          = (p.blindingS + (c * p.s));
    p.Proof.respBetaTimesS = Fr.add(p.blindingOmega,    Fr.mul(p.omega,       c));
    p.Proof.respR1         = Fr.add(p.blindingR1,       Fr.mul(p.r1,          c));
    p.Proof.respR2         = Fr.add(p.blindingR2,       Fr.mul(p.r2,          c));
    p.Proof.respR3         = Fr.add(p.blindingR3,       Fr.mul(p.r3,          c));
    p.Proof.respR =  (p.blindingR + (c * p.r));
    return p.Proof
}

export function verify(p: Proof, c: bigint): boolean {
    const {Statement: s} = p
    const A = pairing(s.Z, s.W_hat);
    const B = Fp12.div(pairing(s.Z, s.C2hat), s.T)

    const E1 = pairing(s.C2, s.g2);
    const E2 = pairing(s.g1.negate(), s.C2hat);
    const E = Fp12.mul(E1, E2);
    const H = Fp12.div(pairing(s.C2, s.ivk_hat), pairing(s.g1, s.g2));
    const J = pairing(s.C2, s.g2.negate());

    const F = pairing(s.W, s.g2);
    const G = pairing(s.g1.negate(), s.W_hat);
    const I = pairing(s.W, s.ivk_hat);

    const minusChallenge = Fr.neg(c)
    // tC1 == (g1 * respBeta) +
    if (!p.tC1.equals(
       s.g1.multiply(p.respBeta).add(s.C1.multiply(minusChallenge)
    ))){
       return false
    }

    if (!p.tC1hat.equals(
        s.g2.multiply(p.respAlpha).add(s.C1hat.multiply(minusChallenge)
        ))){
        return false
    }

    // On Chain
    // tB == A*responseAlpha . B*-Challenge
    // e(Z, W_hat *blindingAlpha) == e(Z, W_hat * responseAlpha) . (e(Z, C2_hat) . e(Z, usk_hat))* -Challenge
    // e(Z, W_hat *blindingAlpha) . e(Z, W_hat * -responseAlpha) . (e(Z, C2_hat*usk_hat * Challenge) == 1
    // we precompute W_hat *blindingAlpha, W_hat * responseAlpha, C2_hat*usk_hat*Challenge off chain // leaks usk_hat
    if (!Fp12.eql(p.tB,
        Fp12.mul(Fp12.pow(A, p.respAlpha), Fp12.pow(B, minusChallenge))
    )) {
        return false
    }

    // const tE = Fp12.mul(Fp12.pow(F, blindingBeta), Fp12.pow(G, blindingAlpha));
    // On Chain
    // tE = e(W, G2 * blindingBeta) . e(-G1, W_hat * blindingAlpha)
    //
    // tE == e(W, G2 * respBeta) . e(-G1, W_hat*respAlpha) . (e(C2, G2) . e(-G1, C2_hat))^-Challenge
    // tE == e(W, G2 * respBeta) . e(-G1, W_hat*respAlpha) . e(C2, G2* - Challenge) . e(- G1, C2_hat * -Challenge)
    // e(W, G2 * blindingBeta) . e(-G1, W_hat * blindingAlpha) == e(W, G2 * respBeta) . e(-G1, W_hat*respAlpha) . e(C2, G2* -Challenge) . e(- G1, C2_hat * -Challenge)
    // e(W, G2 * blindingBeta) . e(-G1, W_hat * blindingAlpha) . e(W, G2 * -respBeta) . e(G1, W_hat*respAlpha) . e(C2, G2* Challenge) . e(G1, C2_hat * -Challenge) ==  1 in GT
    // precompute G2 * blindingBeta, W_hat * blindingAlpha, -respBeta?
    if (!Fp12.eql(p.tE,
        Fp12.mul(Fp12.mul(Fp12.pow(F, p.respBeta), Fp12.pow(G, p.respAlpha)), Fp12.pow(E, minusChallenge))
    )) {
        return false
    }

    // const tH = Fp12.mul(Fp12.mul(Fp12.pow(I, blindingBeta), FBS), Fp12.pow(J, blindingS));
    // On Chain
    // tH = e(W, ivk_hat)^blindingBeta . e(W, G2)^(blindingOmega) . e(C2, -G2)^blindingS
    // tH = e(w,ivk_hat*blindingBeta) . e(W, G2*blindingOmega) . e(C2, -G2*blindingS)
    //
    // tH == e(w,ivk_hat)^blindingBeta . e(W, G2)^(respBetaTimesS) . e(C2, -G2)^respS . (e(C2, ivk_hat) . e(g1, g2) )^-Challenge
    // tH == e(w,ivk_hat*blindingBeta) . e(W, G2*respBetaTimesS) . e(C2, -G2*respS) . e(C2, ivk_hat*-Challenge) . e(g1, g2*-Challenge)
    // e(w,ivk_hat*blindingBeta) . e(W, G2*blindingOmega) . e(C2, -G2*blindingS) == e(w,ivk_hat*respBeta) . e(W, G2respBetaTimesS) . e(C2, -G2*respS) . e(C2, ivk_hat*-Challenge) . e(g1, g2*-Challenge)
    // e(w,ivk_hat*blindingBeta) . e(W, G2*blindingOmega) . e(C2, -G2*blindingS) e(w,ivk_hat*-respBeta) . e(W, -G2respBetaTimesS) . e(C2, G2*respS) . e(C2, ivk_hat*Challenge) . e(g1, g2*Challenge) == 1 in GT
    // Pre compute ivk_hat*blindingBeta, -G2*blindingS, G2*blindingOmega, -respBeta
    const FBS = Fp12.pow(F, p.respBetaTimesS)
    if (!Fp12.eql(p.tH,
        Fp12.mul(Fp12.mul(Fp12.mul(Fp12.pow(I, p.respBeta), FBS), Fp12.pow(J, p.respS)), Fp12.pow(H, minusChallenge))
    )) {
        return false
    }

    // const tK1 = Fp12.mul(Fp12.pow(F, blindingS), Fp12.pow(G, blindingR1));
    // On Chain
    // tK1 = e(W, G2)^blindingS . e(-G1, W_Hat)^blindingR1
    // tK1 = e(W, G2*blindingS) . e(-G1, W_Hat*blindingR1)
    //
    // tK1 == e(W, G2)^respS . e(-G1, W_Hat)^respR1 . (e(W, G2)^s . e(-g1, W_hat)^r1 )^-Challenge
    // tK1 == e(W, G2*respS) . e(-G1, W_Hat*respR1) . (e(W, G2*s) . e(-g1, W_hat*r1) )^-Challenge
    // tK1 == e(W, G2*respS) . e(-G1, W_Hat*respR1) . e(W, G2*s*-Challenge) . e(-g1, W_hat*r1*-Challenge)
    // e(W, G2*blindingS) . e(-G1, W_Hat*blindingR1) == e(W, G2*respS) . e(-G1, W_Hat*respR1) . e(W, G2*s*-Challenge) . e(-g1, W_hat*r1*-Challenge)
    // e(W, G2*blindingS) . e(-G1, W_Hat*blindingR1) . e(W, -G2*respS) . e(-G1,- W_Hat*respR1) . e(W, G2*s*Challenge) . e(-g1, W_hat*r1*Challenge) == 1 in GT
    // precompute G2*blindingS, W_Hat*blindingR1, G2*s*Challenge, W_hat*r1**Challenge, last 2 is not leaking s and r1 cus of ECDLP, need to
    if (!Fp12.eql(p.tK1,
        Fp12.mul(Fp12.mul(Fp12.pow(F, p.respS), Fp12.pow(G, p.respR1)), Fp12.pow(p.K1, minusChallenge))
    )) {
        return false
    }

    // const K2 = Fp12.mul(Fp12.pow(F, omega), Fp12.pow(G, r2));
    // const tK2 = Fp12.mul(FBS, Fp12.pow(G, blindingR2));
    // On Chain
    // tK2 = e(W, G2)^blindingOmega . e(-G1, W_Hat)^blindingR2
    //
    // tk2 == e(W,G2)^respBetaTimeS(omega) . e(-G1, W_Hat)^respR2 . (e(W, G2)^omega . e(-G1, W_Hat)^r2)^-Challenge
    // tk2 == e(W,G2*respBetaTimeS(omega)) . e(-G1, W_Hat*respR2) . e(W, G2*omega*-Challenge) . e(-G1, W_Hat*r2*-Challenge)
    // e(W, G2)^blindingOmega . e(-G1, W_Hat)^blindingR2 == e(W,G2*respBetaTimeS(omega)) . e(-G1, W_Hat*respR2) . e(W, G2*omega*-Challenge) . e(-G1, W_Hat*r2*-Challenge)
    // e(W, G2)^blindingOmega . e(-G1, W_Hat)^blindingR2 e(W,-G2*respBetaTimeS(omega)) . e(G1, W_Hat*respR2) . e(W, G2*omega*Challenge) . e(-G1, W_Hat*r2*Challenge) == 1 in GT
    // precompute
    const K2c = Fp12.pow(p.K2, minusChallenge)
    if (!Fp12.eql(p.tK2,
        Fp12.mul(Fp12.mul(FBS, Fp12.pow(G, p.respR2)), K2c)
    )) {
        return false
    }

    // const tK2Product = Fp12.mul(Fp12.pow(E, blindingS), Fp12.pow(G, blindingR3));
    // On Chain
    // tK2Product = (e(C2, G2) . e(-G1, C2_hat))^blindingS . e(-G1, W_Hat)^r3
    // tK2Product = e(C2, G2*blindingS) . e(-G1, C2_hat*blindingS) . e(-G1, W_Hat*r3)
    //
    // tK2Product == (e(C2, G2) . e(-G1, C2_hat))^respS . e(-G1, W_Hat)^respR3 . (e(W, G2)^omega . e(-G1, W_Hat)^r2)^-Challenge
    // tK2Product == e(C2, G2*respS) . e(-G1, C2_hat*respS) . e(-G1, W_Hat*respR3) . e(W, G2*omega*-Challenge) . e(-G1, W_Hat*r2*-Challenge)
    // e(C2, G2*blindingS) . e(-G1, C2_hat*blindingS) . e(-G1, W_Hat*r3) == e(C2, G2*respS) . e(-G1, C2_hat*respS) . e(-G1, W_Hat*respR3) . e(W, G2*omega*-Challenge) . e(-G1, W_Hat*r2*-Challenge)
    // e(C2, G2*blindingS) . e(-G1, C2_hat*blindingS) . e(-G1, W_Hat*r3) . e(C2, -G2*respS) . e(G1, C2_hat*respS) . e(G1, W_Hat*respR3) . e(W, G2*omega*Challenge) . e(-G1, W_Hat*r2*Challenge) == 1 in GT
    if (!Fp12.eql(p.tK2Product,
        Fp12.mul(Fp12.mul(Fp12.pow(E, p.respS), Fp12.pow(G, p.respR3)), K2c)
    )) {
        return false
    }

    // —— Grumpkin equation  G3· z_s + G4· z_r == tBridge + c·bridge ——
    const L = add(
        mul(p.respS, p.Statement.g3),
        mul(p.respR, p.Statement.g4)
    );
    const R = add(
        p.tBridge,
        mul(c, p.Statement.bridge)
    );
    if (!eq(L, R)) return false;

    return true;
}

// ——— Wrappers over your “flat” signals ————————————————————————————————

/**
 * @param signals  the output of your generateCircomSignals(...)
 * @returns        a NIZK proof object you can serialize
 */
export function proveFromSignals(signals: Record<string, any>): Proof {

    // 2) cast ctx/m back to Uint8Array
    const ctx = Uint8Array.from(signals.ctx as number[]);
    const m   = Uint8Array.from(signals.m as number[]);
    // const jwtProof   = Uint8Array.from(signals.jwtProof as number[]);

    // 3) assemble Statement & Witness
    const stmt: Statement = {
        Z: signals.Z,
        g1:      signals.g1,
        g2:      signals.g2,
        ivk_hat: signals.ivk_hat,
        W:       signals.W,
        W_hat:   signals.W_hat,
        C1:      signals.C1,
        C2:      signals.C2,
        C1hat:  signals.C1hat,
        C2hat:  signals.C2hat,
        T:       signals.T,
        ctx, m,
        g3: signals.g3,
        g4: signals.g4,
        bridge: signals.bridge, // C
    };
    const w: Witness = {
        alpha: signals.alpha,
        beta:  signals.beta,
        s:     signals.s,
        r: signals.r,
    };

    let protocol = init(stmt, w)
    let transcript = computeChallengeContribution(protocol.Proof)
    const fullTranscript = concatBytes(
        concatBytes(transcript, stmt.m),
    );
    const c = computeRandomOracleChallenge(fullTranscript);

    return prove(protocol, c);
}

export function verifyFromProof(
    proof: Proof
): boolean {
    let transcript = computeChallengeContribution(proof)
    const fullTranscript = concatBytes(
        concatBytes(transcript, proof.Statement.m)
    );
    const c = computeRandomOracleChallenge(fullTranscript);
    return verify(proof, c);
}

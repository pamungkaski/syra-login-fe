// ------------------------------------------------------------------
//  deps
// ------------------------------------------------------------------
import { randomBytes } from 'crypto';
import { Noir }        from '@noir-lang/noir_js';
import { UltraHonkBackend } from '@aztec/bb.js';
import TOML from '@iarna/toml';

import circuit           from './noir-circuits/target/syra_login.json';
import { generateInputs } from 'noir-jwt';

// 🔸 your own pure-JS curve helpers
import {
    seedToGrumpkinPoint,
    decimalStringToField,
    mul as grMul,
    add as grAdd,
    Point,
    P as GRUMPKIN_P,          // modulus (needed for scalars)
} from './grumpkin';

// ------------------------------------------------------------------
//  utils (unchanged)
// ------------------------------------------------------------------
function padAndIntify(str: string, size = 100) {
    const utf = Buffer.from(str, 'utf8');
    const out = Buffer.alloc(size);
    utf.copy(out);
    return { storage: Array.from(out), len: utf.length };
}

const toNoirPoint = (pt: { x: bigint; y: bigint; infinity: boolean }) => ({
    x: pt.x.toString(),
    y: pt.y.toString(),
    is_infinite: pt.infinity,
});

// ------------------------------------------------------------------
//  main API
// ------------------------------------------------------------------
export interface FinialVerifierJWTProof {
    proof:   any;
    witness: any;
    g3: Point,
    g4: Point,
    r: bigint,
    bridge: Point,
}

export async function proveGoogleJWTFinalVerifier(
    rawJWT:   string,
    publicKey: JsonWebKey,
    claims:   Record<string, any>,
): Promise<FinialVerifierJWTProof> {

    /* 1. deterministic generators from tags */
    const g3 = seedToGrumpkinPoint('BN254-Pedersen-G3');
    const g4 = seedToGrumpkinPoint('BN254-Pedersen-G4');

    /* 2. random nonce & “sub” scalar (reduce mod p) */
    const r = (BigInt('0x' + randomBytes(32).toString('hex')) % GRUMPKIN_P) || 1n;
    const s = decimalStringToField(claims.sub)


    /* 3. commitment  C = s·G3 + r·G4 */
    const sG3   = grMul(s, g3);
    const rG4   = grMul(r, g4);
    const bridge = grAdd(sG3, rG4);


    /* 4. remaining public inputs */
    const inputs = await generateInputs({
        jwt: rawJWT,
        pubkey: publicKey,
        maxSignedDataLength: 1344,
        shaPrecomputeTillKeys: [],
    });

    const domainBV = padAndIntify(claims.aud, 100);
    const issuerBV = padAndIntify(claims.iss, 100);

    const wst = {
        ...inputs,
        g3:     toNoirPoint(g3),
        g4:     toNoirPoint(g4),
        bridge: toNoirPoint(bridge),
        domain:  { storage: domainBV.storage,  len: domainBV.len },
        issuer:  { storage: issuerBV.storage,  len: issuerBV.len },
        current_time: Math.floor(Date.now() / 1000).toString(),
        r: r.toString(),
    };

    /* 5. execute circuit + prove */
    const noir    = new Noir(circuit);
    const backend = new UltraHonkBackend(circuit.bytecode);

    const { witness } = await noir.execute(wst);
    const proof       = await backend.generateProof(witness);

    return { proof, witness, g3, g4, r, bridge };
}

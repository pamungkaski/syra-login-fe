import {
    generateJWTVerifierInputs,
    JWTInputGenerationArgs,
} from '@/lib/zk/jwtHelpers/input-generators';
import {RSAPublicKey} from '@/lib/zk/jwtHelpers/types';

import {ProofResult, proveJWTNonSub, proveJWTSub} from './prover'

const jwksUrl = 'https://www.googleapis.com/oauth2/v3/certs';

// constants from the circuit
const NONCE_MAX_BYTES    = 66;
const ISSUER_MAX_BYTES   = 32;
const AUDIENCE_MAX_BYTES = 128;

function bytesToPackedIntsLE(bytes: number[]): string[] {
    const LIMB = 31;
    const packed: string[] = [];

    for (let i = 0; i < bytes.length; i += LIMB) {
        let v = 0n;
        /*  j = 0 is the *least‑significant* byte  */
        for (let j = 0; j < LIMB && i + j < bytes.length; j++) {
            v += BigInt(bytes[i + j]) << (8n * BigInt(j));
        }
        packed.push(v.toString());
    }
    return packed;
}

function packString(str: string, max: number) {
    const utf8 = Buffer.from(str, 'utf8');
    const bytes = Array.from(utf8);

    if (bytes.length > max)
        throw new Error(`value "${str}" exceeds ${max} bytes`);

    // right‑pad with zeros
    const padded = bytes.concat(new Array(max - bytes.length).fill(0));

    return {
        packed: bytesToPackedIntsLE(padded),   // decimal strings, little‑endian limbs
        len:    bytes.length.toString(),       // original byte length (as string)
    };
}

function base64urlToBase64(b64u: string): string {
    // Convert URL-safe chars back to standard base64
    let b64 = b64u.replace(/-/g, '+').replace(/_/g, '/')
    // Pad with “=” so the length is a multiple of 4
    const pad = 4 - (b64.length % 4)
    if (pad < 4) b64 += '='.repeat(pad)
    return b64
}


export interface GoogleJWTProofResult {
    subJWTProof: ProofResult;
    nonSubJWTProof: ProofResult;
    publicKey: RSAPublicKey;
    payload:   Record<string, any>;
    kid: string;
    jwk: JsonWebKey,
}

export async function proveGoogleJWT(
    rawJWT: string
): Promise<GoogleJWTProofResult> {
    // split into exactly three parts
    const parts = rawJWT.split('.');
    if (parts.length !== 3) {
        throw new Error(`Invalid JWT format: expected 3 dot‐separated parts, got ${parts.length}`);
    }
    const [ headerB64, payloadB64 ] = parts;

    // sanity‐check
    if (!headerB64) {
        throw new Error('JWT header segment is empty');
    }

    // decode header
    let hdr: any;
    try {
        const headerJson = Buffer.from(headerB64, 'base64').toString('utf-8');
        hdr = JSON.parse(headerJson);
    } catch (err) {
        console.error('Decoded header was:', Buffer.from(headerB64, 'base64').toString());
        throw err;
    }

    // get sub key start index
    const payloadStr = Buffer.from(payloadB64, 'base64').toString('utf8')

    const subKey = `"sub":`
    const audKey = `"aud":`
    const issKey = `"iss":`
    const nonceKey = `"nonce":`

    const subKeyStartIndex = payloadStr.indexOf(subKey)
    if (subKeyStartIndex < 0) {
        throw new Error(`could not find ${subKey} in payload`)
    }
    const audKeyStartIndex = payloadStr.indexOf(audKey)
    if (subKeyStartIndex < 0) {
        throw new Error(`could not find ${subKey} in payload`)
    }
    const issKeyStartIndex = payloadStr.indexOf(issKey)
    if (subKeyStartIndex < 0) {
        throw new Error(`could not find ${subKey} in payload`)
    }
    const nonceKeyStartIndex = payloadStr.indexOf(nonceKey)
    if (subKeyStartIndex < 0) {
        throw new Error(`could not find ${subKey} in payload`)
    }

    const payloadObj = JSON.parse(payloadStr);

    // Grab the `sub` field directly
    const subValue = payloadObj.sub;
    const audValue = payloadObj.aud;
    const issValue = payloadObj.iss;
    const nonceValue = payloadObj.nonce;

    const { packed: audStatement,   len: audLength   } = packString(audValue,   AUDIENCE_MAX_BYTES);
    const { packed: issStatement,   len: issLength   } = packString(issValue,   ISSUER_MAX_BYTES);
    const { packed: nonceStatement, len: nonceLength } = packString(nonceValue, NONCE_MAX_BYTES);


    // now hdr.kid should be defined
    const kid: string | undefined = hdr.kid;
    if (!kid) {
        throw new Error(`No "kid" in JWT header: ${JSON.stringify(hdr)}`);
    }

    // fetch JWKS and find key
    const resp = await fetch(jwksUrl);
    if (!resp.ok) throw new Error(`JWKS fetch failed ${resp.status}`);
    const { keys } = await resp.json();
    const jwk = keys.find((k: any) => k.kid === kid);
    if (!jwk) throw new Error(`No JWK found for kid=${kid}`);

    // build your public key
    const eB64 = base64urlToBase64(jwk.e)
    const eBuf = Buffer.from(eB64, 'base64')
    const eHex = eBuf.toString('hex')
    const publicKey: RSAPublicKey = { n: jwk.n, e: Number(BigInt('0x' + eHex)) };
    const params: JWTInputGenerationArgs = { maxMessageLength: 1344 };

    // generate inputs
    const inputs = await generateJWTVerifierInputs(rawJWT, publicKey, params);
    const subInputs = {
        ...inputs,
        subKeyStartIndex: subKeyStartIndex.toString(),
        subStatement: subValue,
    };
    // const nonSubInputs = {
    //     ...inputs,
    //     audKeyStartIndex: audKeyStartIndex.toString(),
    //     audStatement,
    //     audLength,
    //     issKeyStartIndex: issKeyStartIndex.toString(),
    //     issStatement,
    //     issLength,
    //     nonceKeyStartIndex: nonceKeyStartIndex.toString(),
    //     nonceStatement,
    //     nonceLength,
    // };

    const subJWTProof: ProofResult = await proveJWTSub(subInputs);
    // const nonSubJWTProof: ProofResult = await proveJWTNonSub(nonSubInputs);

    // return proof plus publicKey, header, payload
    return {
        subJWTProof,
        nonSubJWTProof: null,
        publicKey,
        payload: payloadObj,
        kid,
        jwk: jwk,
    };
}

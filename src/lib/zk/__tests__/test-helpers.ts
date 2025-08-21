// Test helpers for ZK library tests

export const mockJWT = {
  header: { kid: 'test-kid', alg: 'RS256' },
  payload: {
    sub: '123456789',
    aud: 'test-audience',
    iss: 'https://accounts.google.com',
    nonce: 'test-nonce-123',
    iat: 1234567890,
    exp: 1234571490
  },
  
  // Create a valid JWT string from header and payload
  create: (customHeader?: any, customPayload?: any) => {
    const header = { ...mockJWT.header, ...customHeader };
    const payload = { ...mockJWT.payload, ...customPayload };
    
    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64');
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64');
    
    return `${headerB64}.${payloadB64}.mock-signature`;
  }
};

export const mockJWK = {
  kid: 'test-kid',
  kty: 'RSA',
  alg: 'RS256',
  use: 'sig',
  n: 'xGOr-H0A-6_BOXMq83kU00T6Fh6SUliHT055LmNlsn_kEJ0LqS4G5wAW5cxVIgCEw',
  e: 'AQAB'
};

export const mockProofInputs = {
  message: new Uint8Array([1, 2, 3, 4, 5]),
  signature: new Uint8Array([6, 7, 8, 9, 10]),
  pubkey: new Uint8Array([11, 12, 13, 14, 15]),
  subStatement: '123456789',
  subKeyStartIndex: '10',
  audStatement: ['test', 'audience'],
  audLength: '13',
  audKeyStartIndex: '25'
};

export const mockZKProof = {
  proof: {
    pi_a: ['1', '2', '1'],
    pi_b: [['3', '4'], ['5', '6']],
    pi_c: ['7', '8', '1']
  },
  publicSignals: ['signal1', 'signal2', 'signal3']
};

// Helper to create mock fetch responses
export const createMockFetchResponse = (data: any, ok: boolean = true, status: number = 200) => {
  return Promise.resolve({
    ok,
    status,
    json: () => Promise.resolve(data),
    arrayBuffer: () => {
      const str = JSON.stringify(data);
      const buf = new ArrayBuffer(str.length);
      const view = new Uint8Array(buf);
      for (let i = 0; i < str.length; i++) {
        view[i] = str.charCodeAt(i);
      }
      return Promise.resolve(buf);
    }
  });
};

// Helper to compare Uint8Arrays
export const uint8ArraysEqual = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
};
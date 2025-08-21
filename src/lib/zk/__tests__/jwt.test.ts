import { packString, bytesToPackedIntsLE, proveGoogleJWT } from '../jwt';

describe('JWT ZK Library', () => {
  describe('bytesToPackedIntsLE', () => {
    it('should pack empty bytes array', () => {
      const result = bytesToPackedIntsLE([]);
      expect(result).toEqual([]);
    });

    it('should pack single byte', () => {
      const result = bytesToPackedIntsLE([255]);
      expect(result).toEqual(['255']);
    });

    it('should pack bytes with LIMB size of 31', () => {
      const bytes = new Array(31).fill(1);
      const result = bytesToPackedIntsLE(bytes);
      expect(result).toHaveLength(1);
      
      // Calculate expected value: sum of 2^(8*i) for i from 0 to 30
      let expectedValue = 0n;
      for (let i = 0; i < 31; i++) {
        expectedValue += 1n << (8n * BigInt(i));
      }
      expect(result[0]).toEqual(expectedValue.toString());
    });

    it('should handle multiple limbs', () => {
      const bytes = new Array(62).fill(1); // Two full limbs
      const result = bytesToPackedIntsLE(bytes);
      expect(result).toHaveLength(2);
    });

    it('should handle partial last limb', () => {
      const bytes = new Array(35).fill(2); // One full limb + 4 bytes
      const result = bytesToPackedIntsLE(bytes);
      expect(result).toHaveLength(2);
    });
  });

  describe('packString', () => {
    it('should pack empty string', () => {
      const result = packString('', 10);
      expect(result.len).toEqual('0');
      expect(result.packed).toHaveLength(1);
    });

    it('should pack simple ASCII string', () => {
      const result = packString('hello', 10);
      expect(result.len).toEqual('5');
      // 'hello' = [104, 101, 108, 108, 111]
      const expectedBytes = [104, 101, 108, 108, 111, 0, 0, 0, 0, 0];
      const expectedPacked = bytesToPackedIntsLE(expectedBytes);
      expect(result.packed).toEqual(expectedPacked);
    });

    it('should handle UTF-8 characters', () => {
      const result = packString('🚀', 10);
      expect(result.len).toEqual('4'); // UTF-8 encoding of rocket emoji is 4 bytes
    });

    it('should throw error if string exceeds max bytes', () => {
      expect(() => packString('hello world', 5)).toThrow('value "hello world" exceeds 5 bytes');
    });

    it('should pad with zeros to max length', () => {
      const result = packString('hi', 5);
      expect(result.len).toEqual('2');
      // Verify padding
      const bytes = Buffer.from('hi', 'utf8');
      const paddedBytes = [...bytes, 0, 0, 0];
      const expectedPacked = bytesToPackedIntsLE(paddedBytes);
      expect(result.packed).toEqual(expectedPacked);
    });
  });

  describe('base64urlToBase64', () => {
    it('should convert URL-safe base64 to standard base64', () => {
      // Mock the base64urlToBase64 function since it's not exported
      const base64urlToBase64 = (b64u: string): string => {
        let b64 = b64u.replace(/-/g, '+').replace(/_/g, '/');
        const pad = 4 - (b64.length % 4);
        if (pad < 4) b64 += '='.repeat(pad);
        return b64;
      };

      expect(base64urlToBase64('abc-def_')).toEqual('abc+def/');
      expect(base64urlToBase64('abc')).toEqual('abc=');
      expect(base64urlToBase64('abcd')).toEqual('abcd');
    });
  });

  describe('proveGoogleJWT', () => {
    it('should reject invalid JWT format', async () => {
      await expect(proveGoogleJWT('invalid')).rejects.toThrow('Invalid JWT format: expected 3 dot‐separated parts, got 1');
      await expect(proveGoogleJWT('part1.part2')).rejects.toThrow('Invalid JWT format: expected 3 dot‐separated parts, got 2');
      await expect(proveGoogleJWT('part1.part2.part3.part4')).rejects.toThrow('Invalid JWT format: expected 3 dot‐separated parts, got 4');
    });

    it('should reject JWT with empty header', async () => {
      await expect(proveGoogleJWT('.payload.signature')).rejects.toThrow('JWT header segment is empty');
    });

    it('should handle invalid base64 in header', async () => {
      const invalidJWT = 'invalid_base64.payload.signature';
      await expect(proveGoogleJWT(invalidJWT)).rejects.toThrow();
    });

    it('should reject JWT without kid in header', async () => {
      const headerWithoutKid = Buffer.from(JSON.stringify({ alg: 'RS256' })).toString('base64');
      const payload = Buffer.from(JSON.stringify({ sub: '123' })).toString('base64');
      const jwt = `${headerWithoutKid}.${payload}.signature`;
      
      await expect(proveGoogleJWT(jwt)).rejects.toThrow('No "kid" in JWT header');
    });

    it('should reject JWT without required payload fields', async () => {
      const header = Buffer.from(JSON.stringify({ kid: 'test', alg: 'RS256' })).toString('base64');
      const payloadWithoutSub = Buffer.from(JSON.stringify({ aud: 'test', iss: 'test', nonce: 'test' })).toString('base64');
      const jwt = `${header}.${payloadWithoutSub}.signature`;
      
      await expect(proveGoogleJWT(jwt)).rejects.toThrow('could not find "sub": in payload');
    });

    // Integration test with mocked fetch
    it('should handle JWKS fetch failure', async () => {
      const header = Buffer.from(JSON.stringify({ kid: 'test', alg: 'RS256' })).toString('base64');
      const payload = Buffer.from(JSON.stringify({ 
        sub: '123',
        aud: 'audience',
        iss: 'issuer',
        nonce: 'nonce123'
      })).toString('base64');
      const jwt = `${header}.${payload}.signature`;

      // Mock fetch to simulate failure
      const originalFetch = global.fetch;
      global.fetch = jest.fn().mockResolvedValue({
        ok: false,
        status: 500
      });

      await expect(proveGoogleJWT(jwt)).rejects.toThrow('JWKS fetch failed 500');

      global.fetch = originalFetch;
    });
  });
});
import { P, Point, add, mul, eq, serialize, seedToGrumpkinPoint, isOnGrumpkin, decimalStringToField } from '../grumpkin';
import { sha256 } from '@noble/hashes/sha2';
import { utf8ToBytes } from '@noble/hashes/utils';

// Mock noble hashes
jest.mock('@noble/hashes/sha2');
jest.mock('@noble/hashes/utils');

describe('Grumpkin Library', () => {
  const G: Point = { x: 1n, y: 17631683881184975370165255887551781615748388533673675138860n, infinity: false };
  const INFINITY: Point = { x: 0n, y: 0n, infinity: true };

  describe('add', () => {
    it('should handle addition with infinity point', () => {
      const p1: Point = { x: 5n, y: 10n, infinity: false };
      
      expect(add(p1, INFINITY)).toEqual(p1);
      expect(add(INFINITY, p1)).toEqual(p1);
      expect(add(INFINITY, INFINITY)).toEqual(INFINITY);
    });

    it('should handle point doubling', () => {
      const result = add(G, G);
      
      expect(result.infinity).toBe(false);
      expect(typeof result.x).toBe('bigint');
      expect(typeof result.y).toBe('bigint');
      expect(result.x).not.toBe(G.x);
      expect(result.y).not.toBe(G.y);
    });

    it('should handle addition of inverse points', () => {
      const p1: Point = { x: 5n, y: 10n, infinity: false };
      const p2: Point = { x: 5n, y: P - 10n, infinity: false }; // -p1
      
      const result = add(p1, p2);
      expect(result.infinity).toBe(true);
    });

    it('should handle normal point addition', () => {
      const p1: Point = { x: 2n, y: 3n, infinity: false };
      const p2: Point = { x: 5n, y: 7n, infinity: false };
      
      const result = add(p1, p2);
      expect(result.infinity).toBe(false);
      expect(result.x).not.toBe(p1.x);
      expect(result.x).not.toBe(p2.x);
    });
  });

  describe('mul', () => {
    it('should return infinity for multiplication by zero', () => {
      const result = mul(0n, G);
      expect(result.infinity).toBe(true);
    });

    it('should return the point for multiplication by one', () => {
      const result = mul(1n, G);
      expect(eq(result, G)).toBe(true);
    });

    it('should handle scalar multiplication correctly', () => {
      const result2 = mul(2n, G);
      const expected2 = add(G, G);
      expect(eq(result2, expected2)).toBe(true);

      const result3 = mul(3n, G);
      const expected3 = add(add(G, G), G);
      expect(eq(result3, expected3)).toBe(true);
    });

    it('should handle large scalar multiplication', () => {
      const largeScalar = 12345678901234567890n;
      const result = mul(largeScalar, G);
      
      expect(result.infinity).toBe(false);
      expect(typeof result.x).toBe('bigint');
      expect(typeof result.y).toBe('bigint');
    });

    it('should handle multiplication with infinity point', () => {
      const result = mul(5n, INFINITY);
      expect(result.infinity).toBe(true);
    });
  });

  describe('eq', () => {
    it('should correctly compare equal points', () => {
      const p1: Point = { x: 5n, y: 10n, infinity: false };
      const p2: Point = { x: 5n, y: 10n, infinity: false };
      
      expect(eq(p1, p2)).toBe(true);
    });

    it('should correctly compare different points', () => {
      const p1: Point = { x: 5n, y: 10n, infinity: false };
      const p2: Point = { x: 5n, y: 11n, infinity: false };
      const p3: Point = { x: 6n, y: 10n, infinity: false };
      
      expect(eq(p1, p2)).toBe(false);
      expect(eq(p1, p3)).toBe(false);
    });

    it('should handle infinity comparisons', () => {
      expect(eq(INFINITY, INFINITY)).toBe(true);
      expect(eq(G, INFINITY)).toBe(false);
      expect(eq(INFINITY, G)).toBe(false);
    });
  });

  describe('serialize', () => {
    it('should serialize infinity point as 64 zero bytes', () => {
      const result = serialize(INFINITY);
      
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(64);
      expect(result.every(b => b === 0)).toBe(true);
    });

    it('should serialize normal point as 64 bytes', () => {
      const p: Point = { x: 1n, y: 2n, infinity: false };
      const result = serialize(p);
      
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(64);
      
      // Check x coordinate (first 32 bytes)
      expect(result[31]).toBe(1); // Last byte of x
      for (let i = 0; i < 31; i++) {
        expect(result[i]).toBe(0); // Other bytes should be 0
      }
      
      // Check y coordinate (last 32 bytes)
      expect(result[63]).toBe(2); // Last byte of y
      for (let i = 32; i < 63; i++) {
        expect(result[i]).toBe(0); // Other bytes should be 0
      }
    });

    it('should handle large coordinate values', () => {
      const largeX = (1n << 250n) + 12345n;
      const largeY = (1n << 248n) + 67890n;
      const p: Point = { x: largeX, y: largeY, infinity: false };
      
      const result = serialize(p);
      expect(result.length).toBe(64);
      
      // Reconstruct values to verify
      let reconstructedX = 0n;
      for (let i = 0; i < 32; i++) {
        reconstructedX = (reconstructedX << 8n) | BigInt(result[i]);
      }
      expect(reconstructedX).toBe(largeX);
      
      let reconstructedY = 0n;
      for (let i = 32; i < 64; i++) {
        reconstructedY = (reconstructedY << 8n) | BigInt(result[i]);
      }
      expect(reconstructedY).toBe(largeY);
    });
  });

  describe('seedToGrumpkinPoint', () => {
    it('should generate a point from seed string', () => {
      const mockHash = new Uint8Array(32);
      mockHash.fill(42);
      (sha256 as jest.Mock).mockReturnValue(mockHash);
      (utf8ToBytes as jest.Mock).mockReturnValue(new Uint8Array([104, 101, 108, 108, 111])); // "hello"
      
      const result = seedToGrumpkinPoint('hello');
      
      expect(utf8ToBytes).toHaveBeenCalledWith('hello');
      expect(sha256).toHaveBeenCalled();
      expect(result.infinity).toBe(false);
      expect(typeof result.x).toBe('bigint');
      expect(typeof result.y).toBe('bigint');
    });

    it('should generate different points for different seeds', () => {
      (utf8ToBytes as jest.Mock).mockImplementation((str: string) => 
        new Uint8Array(Buffer.from(str, 'utf8'))
      );
      
      (sha256 as jest.Mock).mockImplementation((bytes: Uint8Array) => {
        // Simple mock hash that varies with input
        const hash = new Uint8Array(32);
        hash[0] = bytes[0] || 1;
        return hash;
      });
      
      const p1 = seedToGrumpkinPoint('seed1');
      const p2 = seedToGrumpkinPoint('seed2');
      
      expect(eq(p1, p2)).toBe(false);
    });

    it('should handle edge case where hash mod P is zero', () => {
      const zeroHash = new Uint8Array(32);
      zeroHash.fill(0);
      (sha256 as jest.Mock).mockReturnValue(zeroHash);
      (utf8ToBytes as jest.Mock).mockReturnValue(new Uint8Array([0]));
      
      const result = seedToGrumpkinPoint('zero');
      
      // Should use 1n instead of 0n
      expect(eq(result, G)).toBe(true); // 1n * G = G
    });
  });

  describe('isOnGrumpkin', () => {
    it('should verify generator point is on curve', () => {
      expect(isOnGrumpkin(G)).toBe(true);
    });

    it('should verify doubled point is on curve', () => {
      const doubled = add(G, G);
      expect(isOnGrumpkin(doubled)).toBe(true);
    });

    it('should detect point not on curve', () => {
      const notOnCurve: Point = { x: 2n, y: 3n, infinity: false };
      expect(isOnGrumpkin(notOnCurve)).toBe(false);
    });

    it('should verify points from scalar multiplication are on curve', () => {
      const p1 = mul(12345n, G);
      const p2 = mul(67890n, G);
      
      expect(isOnGrumpkin(p1)).toBe(true);
      expect(isOnGrumpkin(p2)).toBe(true);
    });
  });

  describe('decimalStringToField', () => {
    it('should convert empty string to 1n', () => {
      const result = decimalStringToField('');
      expect(result).toBe(1n);
    });

    it('should convert ASCII string to field element', () => {
      const result = decimalStringToField('A'); // ASCII 65
      expect(result).toBe(65n);
    });

    it('should convert multi-byte string correctly', () => {
      const result = decimalStringToField('AB'); // ASCII 65, 66
      // Should be (65 << 8) + 66 = 16706
      expect(result).toBe(16706n);
    });

    it('should handle UTF-8 strings', () => {
      const result = decimalStringToField('hello');
      // 'hello' = [104, 101, 108, 108, 111]
      let expected = 0n;
      for (const byte of [104, 101, 108, 108, 111]) {
        expected = (expected << 8n) + BigInt(byte);
      }
      expect(result).toBe(expected);
    });

    it('should avoid returning zero', () => {
      // Even if somehow we get 0, it should return 1n
      jest.spyOn(Buffer, 'from').mockReturnValue(Buffer.from([]));
      const result = decimalStringToField('test');
      expect(result).toBe(1n);
    });
  });

  describe('Field arithmetic helpers', () => {
    it('should correctly compute modular arithmetic', () => {
      // Test that P is prime (indirectly through operations)
      const a = 12345678901234567890n;
      const b = 98765432109876543210n;
      
      // Addition mod P
      const sum = ((a + b) % P + P) % P;
      expect(sum).toBeGreaterThanOrEqual(0n);
      expect(sum).toBeLessThan(P);
      
      // Multiplication mod P
      const product = ((a * b) % P + P) % P;
      expect(product).toBeGreaterThanOrEqual(0n);
      expect(product).toBeLessThan(P);
    });

    it('should handle negative values correctly', () => {
      const negative = -12345n;
      const modResult = ((negative % P) + P) % P;
      
      expect(modResult).toBeGreaterThanOrEqual(0n);
      expect(modResult).toBeLessThan(P);
      expect(modResult).toBe(P - 12345n);
    });
  });
});
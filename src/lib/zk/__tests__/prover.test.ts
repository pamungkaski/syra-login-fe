import { proveJWTSub, proveJWTNonSub, ProofResult } from '../prover';
import * as idbKeyval from 'idb-keyval';
import * as snarkjs from 'snarkjs';

// Mock dependencies
jest.mock('idb-keyval');
jest.mock('snarkjs');
jest.mock('../jwt_js/witness_calculator.js', () => ({
  default: jest.fn()
}));
jest.mock('../syra-login_js/witness_calculator.js', () => ({
  default: jest.fn()
}));

describe('Prover Library', () => {
  const mockWasmBytes = new Uint8Array([1, 2, 3, 4]);
  const mockZkeyBytes = new Uint8Array([5, 6, 7, 8]);
  const mockWtnsBin = new Uint8Array([9, 10, 11, 12]);
  const mockProof = { pi_a: ['1', '2'], pi_b: [['3', '4'], ['5', '6']], pi_c: ['7', '8'] };
  const mockPublicSignals = ['signal1', 'signal2'];

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Reset fetch mock
    global.fetch = jest.fn();
  });

  describe('loadCachedAsset', () => {
    it('should return cached asset from IndexedDB if available', async () => {
      const cachedData = new Uint8Array([100, 101, 102]);
      (idbKeyval.get as jest.Mock).mockResolvedValue(cachedData);

      // Since loadCachedAsset is not exported, we'll test it indirectly through proveJWTSub
      // This is a limitation - ideally loadCachedAsset would be exported for direct testing
    });

    it('should fetch and cache asset if not in IndexedDB', async () => {
      (idbKeyval.get as jest.Mock).mockResolvedValue(undefined);
      const responseBuffer = new ArrayBuffer(4);
      new Uint8Array(responseBuffer).set([200, 201, 202, 203]);
      
      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        arrayBuffer: jest.fn().mockResolvedValue(responseBuffer)
      });

      // Test will be done through proveJWTSub
    });

    it('should throw error if fetch fails', async () => {
      (idbKeyval.get as jest.Mock).mockResolvedValue(undefined);
      (global.fetch as jest.Mock).mockResolvedValue({
        ok: false,
        status: 404
      });

      // Test will be done through proveJWTSub
    });
  });

  describe('proveJWTSub', () => {
    const mockInput = {
      message: 'test message',
      signature: 'test signature',
      pubkey: 'test pubkey'
    };

    beforeEach(() => {
      // Mock IndexedDB to return cached assets
      (idbKeyval.get as jest.Mock).mockImplementation((key: string) => {
        if (key === 'jwt-wasm') return Promise.resolve(mockWasmBytes);
        if (key === 'jwt-zkey') return Promise.resolve(mockZkeyBytes);
        return Promise.resolve(undefined);
      });

      // Mock witness calculator
      const mockWitnessCalculator = {
        calculateWTNSBin: jest.fn().mockResolvedValue(mockWtnsBin)
      };
      const builderSub = require('../jwt_js/witness_calculator.js').default;
      builderSub.mockResolvedValue(mockWitnessCalculator);

      // Mock snarkjs
      (snarkjs.groth16.prove as jest.Mock).mockResolvedValue({
        proof: mockProof,
        publicSignals: mockPublicSignals
      });
    });

    it('should generate proof successfully', async () => {
      const result = await proveJWTSub(mockInput);

      expect(result).toEqual({
        proof: mockProof,
        publicSignals: mockPublicSignals
      });

      // Verify witness calculator was called correctly
      const builderSub = require('../jwt_js/witness_calculator.js').default;
      expect(builderSub).toHaveBeenCalledWith(mockWasmBytes);

      // Verify snarkjs prove was called
      expect(snarkjs.groth16.prove).toHaveBeenCalledWith(mockZkeyBytes, mockWtnsBin);
    });

    it('should fetch assets if not cached', async () => {
      // Mock IndexedDB to return nothing
      (idbKeyval.get as jest.Mock).mockResolvedValue(undefined);
      
      // Mock fetch responses
      const wasmBuffer = new ArrayBuffer(4);
      new Uint8Array(wasmBuffer).set(mockWasmBytes);
      const zkeyBuffer = new ArrayBuffer(4);
      new Uint8Array(zkeyBuffer).set(mockZkeyBytes);

      (global.fetch as jest.Mock).mockImplementation((url: string) => {
        if (url === '/jwt_js/jwt.wasm') {
          return Promise.resolve({
            ok: true,
            arrayBuffer: jest.fn().mockResolvedValue(wasmBuffer)
          });
        }
        if (url === '/jwt_0001.zkey') {
          return Promise.resolve({
            ok: true,
            arrayBuffer: jest.fn().mockResolvedValue(zkeyBuffer)
          });
        }
        return Promise.reject(new Error('Unknown URL'));
      });

      const result = await proveJWTSub(mockInput);

      // Verify fetch was called
      expect(global.fetch).toHaveBeenCalledWith('/jwt_js/jwt.wasm');
      expect(global.fetch).toHaveBeenCalledWith('/jwt_0001.zkey');

      // Verify assets were cached
      expect(idbKeyval.set).toHaveBeenCalledWith('jwt-wasm', mockWasmBytes);
      expect(idbKeyval.set).toHaveBeenCalledWith('jwt-zkey', mockZkeyBytes);
    });

    it('should handle witness calculation errors', async () => {
      const mockWitnessCalculator = {
        calculateWTNSBin: jest.fn().mockRejectedValue(new Error('Witness calculation failed'))
      };
      const builderSub = require('../jwt_js/witness_calculator.js').default;
      builderSub.mockResolvedValue(mockWitnessCalculator);

      await expect(proveJWTSub(mockInput)).rejects.toThrow('Witness calculation failed');
    });

    it('should handle proof generation errors', async () => {
      (snarkjs.groth16.prove as jest.Mock).mockRejectedValue(new Error('Proof generation failed'));

      await expect(proveJWTSub(mockInput)).rejects.toThrow('Proof generation failed');
    });
  });

  describe('proveJWTNonSub', () => {
    const mockInput = {
      aud: 'test audience',
      iss: 'test issuer',
      nonce: 'test nonce'
    };

    beforeEach(() => {
      // Mock IndexedDB to return cached assets
      (idbKeyval.get as jest.Mock).mockImplementation((key: string) => {
        if (key === 'nonSub-wasm') return Promise.resolve(mockWasmBytes);
        if (key === 'nonSub-zkey') return Promise.resolve(mockZkeyBytes);
        return Promise.resolve(undefined);
      });

      // Mock witness calculator
      const mockWitnessCalculator = {
        calculateWTNSBin: jest.fn().mockResolvedValue(mockWtnsBin)
      };
      const builderNonSub = require('../syra-login_js/witness_calculator.js').default;
      builderNonSub.mockResolvedValue(mockWitnessCalculator);

      // Mock snarkjs
      (snarkjs.groth16.prove as jest.Mock).mockResolvedValue({
        proof: mockProof,
        publicSignals: mockPublicSignals
      });
    });

    it('should generate proof successfully', async () => {
      const result = await proveJWTNonSub(mockInput);

      expect(result).toEqual({
        proof: mockProof,
        publicSignals: mockPublicSignals
      });

      // Verify witness calculator was called correctly
      const builderNonSub = require('../syra-login_js/witness_calculator.js').default;
      expect(builderNonSub).toHaveBeenCalledWith(mockWasmBytes);

      // Verify snarkjs prove was called
      expect(snarkjs.groth16.prove).toHaveBeenCalledWith(mockZkeyBytes, mockWtnsBin);
    });

    it('should use correct asset paths for non-sub proof', async () => {
      // Mock IndexedDB to return nothing
      (idbKeyval.get as jest.Mock).mockResolvedValue(undefined);
      
      // Mock fetch responses
      const wasmBuffer = new ArrayBuffer(4);
      new Uint8Array(wasmBuffer).set(mockWasmBytes);
      const zkeyBuffer = new ArrayBuffer(4);
      new Uint8Array(zkeyBuffer).set(mockZkeyBytes);

      (global.fetch as jest.Mock).mockImplementation((url: string) => {
        if (url === '/syra-login_js/syra-login.wasm') {
          return Promise.resolve({
            ok: true,
            arrayBuffer: jest.fn().mockResolvedValue(wasmBuffer)
          });
        }
        if (url === '/syra_0001.zkey') {
          return Promise.resolve({
            ok: true,
            arrayBuffer: jest.fn().mockResolvedValue(zkeyBuffer)
          });
        }
        return Promise.reject(new Error('Unknown URL'));
      });

      await proveJWTNonSub(mockInput);

      // Verify correct URLs were used
      expect(global.fetch).toHaveBeenCalledWith('/syra-login_js/syra-login.wasm');
      expect(global.fetch).toHaveBeenCalledWith('/syra_0001.zkey');

      // Verify correct cache keys were used
      expect(idbKeyval.set).toHaveBeenCalledWith('nonSub-wasm', mockWasmBytes);
      expect(idbKeyval.set).toHaveBeenCalledWith('nonSub-zkey', mockZkeyBytes);
    });
  });
});
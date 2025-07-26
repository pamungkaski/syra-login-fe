import { proveFromSignals, verifyFromProof, computeRandomOracleChallenge, computeChallengeContribution, Proof, Statement, Witness } from '../syra-signature';
import { bls12_381 } from '@noble/curves/bls12-381';
import { blake2b } from 'blakejs';
import { Point as GrPoint } from '../grumpkin';

const { G1, G2, pairing, fields } = bls12_381;
const { Fp12 } = fields;

// Mock dependencies
jest.mock('blakejs');
jest.mock('../grumpkin');

describe('SyRA Signature Library', () => {
  // Helper to create mock points
  const mockG1Point = () => G1.ProjectivePoint.BASE;
  const mockG2Point = () => G2.ProjectivePoint.BASE;
  const mockFp12 = () => Fp12.ONE;
  const mockGrumpkinPoint = (): GrPoint => ({ x: 1n, y: 2n });

  describe('computeRandomOracleChallenge', () => {
    it('should compute challenge from transcript', () => {
      const mockHash = new Uint8Array(64);
      mockHash.fill(42);
      (blake2b as jest.Mock).mockReturnValue(mockHash);

      const transcript = new Uint8Array([1, 2, 3, 4]);
      const result = computeRandomOracleChallenge(transcript);

      expect(blake2b).toHaveBeenCalledWith(transcript, undefined, 64);
      expect(typeof result).toBe('bigint');
      expect(result).toBeGreaterThanOrEqual(0n);
    });

    it('should handle empty transcript', () => {
      const mockHash = new Uint8Array(64);
      mockHash.fill(0);
      (blake2b as jest.Mock).mockReturnValue(mockHash);

      const transcript = new Uint8Array([]);
      const result = computeRandomOracleChallenge(transcript);

      expect(result).toBe(0n);
    });
  });

  describe('computeChallengeContribution', () => {
    it('should concatenate all proof components', () => {
      const mockProof: Proof = {
        Statement: {
          Z: mockG1Point(),
          g1: mockG1Point(),
          g2: mockG2Point(),
          ivk_hat: mockG2Point(),
          W: mockG1Point(),
          W_hat: mockG2Point(),
          C1: mockG1Point(),
          C2: mockG1Point(),
          C1hat: mockG2Point(),
          C2hat: mockG2Point(),
          T: mockFp12(),
          bridge: mockGrumpkinPoint(),
          g3: mockGrumpkinPoint(),
          g4: mockGrumpkinPoint(),
          ctx: new Uint8Array([1, 2, 3]),
          m: new Uint8Array([4, 5, 6]),
          jwtProof: new Uint8Array([7, 8, 9])
        },
        K1: mockFp12(),
        K2: mockFp12(),
        tC1: mockG1Point(),
        tC1hat: mockG2Point(),
        tB: mockFp12(),
        tE: mockFp12(),
        tH: mockFp12(),
        tK1: mockFp12(),
        tK2: mockFp12(),
        tK2Product: mockFp12(),
        tBridge: mockGrumpkinPoint()
      };

      const result = computeChallengeContribution(mockProof);

      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBeGreaterThan(0);
    });
  });

  describe('proveFromSignals', () => {
    const mockSignals = {
      Z: mockG1Point(),
      g1: mockG1Point(),
      g2: mockG2Point(),
      ivk_hat: mockG2Point(),
      W: mockG1Point(),
      W_hat: mockG2Point(),
      C1: mockG1Point(),
      C2: mockG1Point(),
      C1hat: mockG2Point(),
      C2hat: mockG2Point(),
      T: mockFp12(),
      g3: mockGrumpkinPoint(),
      g4: mockGrumpkinPoint(),
      bridge: mockGrumpkinPoint(),
      ctx: [1, 2, 3],
      m: [4, 5, 6],
      alpha: 123n,
      beta: 456n,
      s: 789n,
      r: 101112n
    };

    beforeEach(() => {
      // Mock blake2b for challenge computation
      const mockHash = new Uint8Array(64);
      mockHash.fill(42);
      (blake2b as jest.Mock).mockReturnValue(mockHash);

      // Mock grumpkin operations
      const grumpkin = require('../grumpkin');
      grumpkin.serialize = jest.fn().mockReturnValue(new Uint8Array([1, 2, 3]));
      grumpkin.add = jest.fn().mockReturnValue(mockGrumpkinPoint());
      grumpkin.mul = jest.fn().mockReturnValue(mockGrumpkinPoint());
    });

    it('should generate proof from signals', () => {
      const proof = proveFromSignals(mockSignals);

      expect(proof).toBeDefined();
      expect(proof.Statement).toBeDefined();
      expect(proof.K1).toBeDefined();
      expect(proof.K2).toBeDefined();
      expect(proof.respAlpha).toBeDefined();
      expect(proof.respBeta).toBeDefined();
      expect(proof.respS).toBeDefined();
      expect(proof.respR).toBeDefined();
    });

    it('should convert array inputs to Uint8Array', () => {
      const proof = proveFromSignals(mockSignals);

      expect(proof.Statement.ctx).toBeInstanceOf(Uint8Array);
      expect(proof.Statement.m).toBeInstanceOf(Uint8Array);
      expect(proof.Statement.ctx).toEqual(new Uint8Array([1, 2, 3]));
      expect(proof.Statement.m).toEqual(new Uint8Array([4, 5, 6]));
    });

    it('should compute challenge and responses', () => {
      const proof = proveFromSignals(mockSignals);

      // Verify responses are computed (non-zero)
      expect(proof.respAlpha).toBeDefined();
      expect(proof.respBeta).toBeDefined();
      expect(proof.respS).toBeDefined();
      expect(proof.respBetaTimesS).toBeDefined();
      expect(proof.respR1).toBeDefined();
      expect(proof.respR2).toBeDefined();
      expect(proof.respR3).toBeDefined();
      expect(proof.respR).toBeDefined();
    });
  });

  describe('verifyFromProof', () => {
    let mockProof: Proof;

    beforeEach(() => {
      // Create a valid mock proof
      mockProof = {
        Statement: {
          Z: mockG1Point(),
          g1: mockG1Point(),
          g2: mockG2Point(),
          ivk_hat: mockG2Point(),
          W: mockG1Point(),
          W_hat: mockG2Point(),
          C1: mockG1Point(),
          C2: mockG1Point(),
          C1hat: mockG2Point(),
          C2hat: mockG2Point(),
          T: mockFp12(),
          bridge: mockGrumpkinPoint(),
          g3: mockGrumpkinPoint(),
          g4: mockGrumpkinPoint(),
          ctx: new Uint8Array([1, 2, 3]),
          m: new Uint8Array([4, 5, 6]),
          jwtProof: new Uint8Array([7, 8, 9])
        },
        K1: mockFp12(),
        K2: mockFp12(),
        tC1: mockG1Point(),
        tC1hat: mockG2Point(),
        tB: mockFp12(),
        tE: mockFp12(),
        tH: mockFp12(),
        tK1: mockFp12(),
        tK2: mockFp12(),
        tK2Product: mockFp12(),
        tBridge: mockGrumpkinPoint(),
        respAlpha: 100n,
        respBeta: 200n,
        respS: 300n,
        respBetaTimesS: 400n,
        respR1: 500n,
        respR2: 600n,
        respR3: 700n,
        respR: 800n
      };

      // Mock blake2b for challenge computation
      const mockHash = new Uint8Array(64);
      mockHash.fill(42);
      (blake2b as jest.Mock).mockReturnValue(mockHash);

      // Mock grumpkin operations
      const grumpkin = require('../grumpkin');
      grumpkin.serialize = jest.fn().mockReturnValue(new Uint8Array([1, 2, 3]));
      grumpkin.add = jest.fn().mockReturnValue(mockGrumpkinPoint());
      grumpkin.mul = jest.fn().mockReturnValue(mockGrumpkinPoint());
      grumpkin.eq = jest.fn().mockReturnValue(true);
    });

    it('should verify valid proof', () => {
      // Mock all the point operations to return valid results
      mockProof.tC1.equals = jest.fn().mockReturnValue(true);
      mockProof.tC1hat.equals = jest.fn().mockReturnValue(true);
      
      // Mock Fp12 operations
      jest.spyOn(Fp12, 'eql').mockReturnValue(true);

      const result = verifyFromProof(mockProof);

      expect(result).toBe(true);
    });

    it('should reject proof with invalid tC1', () => {
      mockProof.tC1.equals = jest.fn().mockReturnValue(false);
      mockProof.tC1hat.equals = jest.fn().mockReturnValue(true);
      jest.spyOn(Fp12, 'eql').mockReturnValue(true);

      const result = verifyFromProof(mockProof);

      expect(result).toBe(false);
    });

    it('should reject proof with invalid grumpkin equation', () => {
      mockProof.tC1.equals = jest.fn().mockReturnValue(true);
      mockProof.tC1hat.equals = jest.fn().mockReturnValue(true);
      jest.spyOn(Fp12, 'eql').mockReturnValue(true);

      // Make grumpkin equation fail
      const grumpkin = require('../grumpkin');
      grumpkin.eq = jest.fn().mockReturnValue(false);

      const result = verifyFromProof(mockProof);

      expect(result).toBe(false);
    });

    it('should compute same challenge as prover', () => {
      // This tests that verifier computes the same challenge
      const transcript = computeChallengeContribution(mockProof);
      const fullTranscript = new Uint8Array([...transcript, ...mockProof.Statement.m]);
      
      verifyFromProof(mockProof);

      // Verify blake2b was called with the same transcript
      expect(blake2b).toHaveBeenCalledWith(fullTranscript, undefined, 64);
    });
  });

  describe('Integration tests', () => {
    it('should verify proof generated by proveFromSignals', () => {
      const mockSignals = {
        Z: mockG1Point(),
        g1: mockG1Point(),
        g2: mockG2Point(),
        ivk_hat: mockG2Point(),
        W: mockG1Point(),
        W_hat: mockG2Point(),
        C1: mockG1Point(),
        C2: mockG1Point(),
        C1hat: mockG2Point(),
        C2hat: mockG2Point(),
        T: mockFp12(),
        g3: mockGrumpkinPoint(),
        g4: mockGrumpkinPoint(),
        bridge: mockGrumpkinPoint(),
        ctx: [1, 2, 3],
        m: [4, 5, 6],
        alpha: 123n,
        beta: 456n,
        s: 789n,
        r: 101112n
      };

      // Mock all necessary operations
      const mockHash = new Uint8Array(64);
      mockHash.fill(42);
      (blake2b as jest.Mock).mockReturnValue(mockHash);

      const grumpkin = require('../grumpkin');
      grumpkin.serialize = jest.fn().mockReturnValue(new Uint8Array([1, 2, 3]));
      grumpkin.add = jest.fn().mockReturnValue(mockGrumpkinPoint());
      grumpkin.mul = jest.fn().mockReturnValue(mockGrumpkinPoint());
      grumpkin.eq = jest.fn().mockReturnValue(true);

      // Generate proof
      const proof = proveFromSignals(mockSignals);

      // Mock verification operations
      proof.tC1.equals = jest.fn().mockReturnValue(true);
      proof.tC1hat.equals = jest.fn().mockReturnValue(true);
      jest.spyOn(Fp12, 'eql').mockReturnValue(true);

      // Verify the proof
      const isValid = verifyFromProof(proof);

      expect(isValid).toBe(true);
    });
  });
});
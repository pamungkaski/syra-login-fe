use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar};
use std::embedded_curve_ops;

global MAX_SHARE: u32 = 3;
global SECRET_SHARE_T: u32 = 3;
global MAX_DATA_LENGTH: u32 = 1344;
global MAX_ISSUER_LENGTH: u32 = 100;
global MAX_AUDIENCE_LENGTH: u32 = 100;
global MAX_SUB_LENGTH: u32 = 100;

fn bounded_vec_to_field(vec: BoundedVec<u8, 100>) -> Field {
   let mut acc: Field = 0;

   for i in 0..MAX_SUB_LENGTH {
       if (i as u32) < vec.len {
           let digit = vec.get_unchecked(i);
           acc = acc * 256 + digit as Field;
       }
   }
   acc
}

fn main(
   // statement
   pubkey_modulus_limbs: pub [u128; 18],  // RSA modulus
   redc_params_limbs: pub [u128; 18],         // RSA reduction parameters
   domain: pub BoundedVec<u8, MAX_AUDIENCE_LENGTH>, // Expected audience
   issuer: pub BoundedVec<u8, MAX_ISSUER_LENGTH>,  // Expected issuer
   g3: pub EmbeddedCurvePoint,
   g4: pub EmbeddedCurvePoint,
   bridge: pub EmbeddedCurvePoint,

   //witness
   data: BoundedVec<u8, MAX_DATA_LENGTH>,  // Encoded JWT token
   signature_limbs: [u128; 18],           // RSA signature
   base64_decode_offset: u32,                        // Base64 offset for signature
   current_time: u64,                     // Current timestamp
   r: Field,
) {
    let sub = id_token::verify(
        data,
        base64_decode_offset,
        pubkey_modulus_limbs,
        redc_params_limbs,
        signature_limbs,
        domain,
        issuer,
        current_time
    );
    println("jwtVerified");
    let subField = bounded_vec_to_field(sub);
    let subScalar = EmbeddedCurveScalar::from_field(subField);
    let rScalar = EmbeddedCurveScalar::from_field(r);
    let sG3 =  embedded_curve_ops::multi_scalar_mul([g3], [subScalar]);
    let rG4 =  embedded_curve_ops::multi_scalar_mul([g4], [rScalar]);
    let C = embedded_curve_ops::embedded_curve_add(sG3, rG4);
    assert(C == bridge, "Bridge Fail");
}



pub fn shamir_reconstruct<let T: u32>(x_coords: [Field; T], y_coords: [Field; T]) -> Field {
    let mut secret = 0;

    for i in 0..T {
        let mut num = 1;
        let mut den = 1;
        for j in 0..T {
            if i != j {
                // num *= (0 - x_j)
                num = num * (0 - x_coords[j]);
                // den *= (x_i - x_j)
                den = den * (x_coords[i] - x_coords[j]);
            }
        }

        let den_inv = 1 / den;

        let term = y_coords[i] * num * den_inv;
        secret = secret + term;
    }

    secret
}
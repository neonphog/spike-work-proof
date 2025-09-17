#![deny(missing_docs)]
//! Argon2-based proof of work generation and validation system.
//!
//! Asymetric keypairs are trivial to generate. If you want to make this more
//! difficult, you can add proof-of-work that must be supplied with a public
//! key (or any other data) to add a requirement of cpu / memory making it
//! more difficult to generate large numbers of public keys.
//!
//! This platform takes a 32 byte hash (either the public key directly,
//! or, for example, a sha256 of the public key), and generates a proof
//! that when hashed with argon2 will generate a set of bytes interpreted
//! as a number. The closer those bytes are to the maximum number, the
//! more difficult (read unlikely) it is that you were able to generate
//! that hash. This difficulty is expressed as a log10 for ease of use
//! in human reasoning. I.e. if a difficulty of 1.0 takes on average 1 second
//! of hashing to reach, then a difficulty of 2.0 takes on average of
//! 10 seconds to reach.
//!
//! ## How
//!
//! Password hashing and proof-of-work are similar problem domains.
//!
//! We can take the Argon2 algorithm and adapt it for proof of work.
//!
//! - Use a 20 byte "password" that is the search space for the proof,
//!   - the first 16 bytes are incremented as a wrapping u128
//!   - the final 4 are used as a "node" id so parallel processing
//!     doesn't ever duplicate working on the same space
//! - Use the "hash" as the argon2 salt.
//!
//! The recommendation here is to use the folowing params:
//!
//! - mem limit: 16777216 bytes
//! - cpu limit: 1 iteration
//! - parallel count: 1
//! - output bytes: 16
//! - difficulty: log10(1.0 / (1.0 - (output bytes as LE u128 / u128::MAX)))
//!
//! The argon2 parameters were chosen to require an amount of work to be done
//! (the whole point of this excercise), while also making it not too onerous
//! to validate the proofs on whatever process is doing the validation.

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// Basic result type.
pub type Result<T> = std::result::Result<T, String>;

/// Block count / memory usage.
const BLOCK_COUNT: u32 = 16384;

/// We only want to build a single instance of our parameters.
static ARGON2: std::sync::LazyLock<argon2::Argon2<'static>> =
    std::sync::LazyLock::new(|| {
        let a = argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(BLOCK_COUNT, 1, 1, Some(16))
                .expect("valid argon2 params"),
        );
        debug_assert_eq!(BLOCK_COUNT as usize, a.params().block_count());
        a
    });

thread_local! {
    /// This is a decent amount of memory... Only allocate it once per
    /// thread that needs to do the hashing.
    static MEM: std::cell::RefCell<Vec<argon2::Block>> =
        std::cell::RefCell::new(
            vec![argon2::Block::default(); BLOCK_COUNT as usize]
        );
}

/// 128 bit jitter
const BIG_JITTER: &[u128] = &[
    232948893588309592072343451646495443470,
    241772077400251990428921465086427460406,
    135466609762431670297680858806122516196,
    23843965500601499676577714028275613566,
    3980925650203285922593180965914241295,
    276996438161600802308531502845602322760,
    102314981229339036363969651202596767324,
    173696929416818359727323669108240964699,
    248234049680437024180525977804398658061,
    182129205137478248958828934085226751428,
    226858282864963269134484634927244451740,
    317700656064443789738604527115780206566,
    257667444946452812601551143022268928116,
];

/// 32 bit jitter
const SM_JITTER: &[u32] = &[
    2633617217, 1710307616, 3543087939, 3370472175, 2302495969, 1171085216,
    3321642826, 3518920782, 1060944841, 2907445434, 2811178615, 2842243822,
    563823965,
];

/// Does the work of generating and validating proofs.
///
/// Usage:
///
/// - [WorkProof::init] to create new instances
/// - [WorkProof::next] to iterate the proof, trying for a better difficulty.
/// - [WorkProof::proof] to save the proof once you find an acceptable hash.
/// - [WorkProof::verify] to check validity of a previously generated proof.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct WorkProof {
    pwd: [u8; 20],
    salt: [u8; 32],
    difficulty: f64,
    iter: std::num::Wrapping<u128>,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl WorkProof {
    /// New [WorkProof] instances for generating work proofs.
    ///
    /// - count - the number of generator instances to produce
    ///           for running parallel generation tasks.
    /// - seed  - a pseudo random seed for starting the generation.
    ///           this need not be cryptographically secure assuming
    ///           the provided hash wash generated with a secure and
    ///           well distributed hashing function.
    /// - hash  - the hash to generate a proof against.
    pub fn init(count: usize, seed: &[u8], hash: &[u8]) -> Result<Vec<Self>> {
        // check sizes of input data
        if seed.is_empty() || seed.len() > 20 {
            return Err("seed should be between 1 and 20 bytes".into());
        }
        if hash.len() != 32 {
            return Err("hash must be 32 bytes".into());
        }

        let mut out = Vec::with_capacity(count);

        let mut pwd = [0; 20];

        // fill password with seed data
        pwd.copy_from_slice(
            &std::iter::repeat(seed.iter())
                .flatten()
                .cloned()
                .take(20)
                .collect::<Vec<_>>(),
        );

        let mut iter = std::num::Wrapping(u128::from_le_bytes(
            pwd[..16].try_into().unwrap(),
        ));
        let mut node = std::num::Wrapping(u32::from_le_bytes(
            pwd[16..].try_into().unwrap(),
        ));

        // use the hash as the salt
        let salt: [u8; 32] = hash.try_into().unwrap();

        // repeating jitter numbers, not needed mathematically,
        // but this is a low cost way of making the different
        // cores have very different starting iter + node bytes.
        let mut big = std::iter::repeat(BIG_JITTER.iter()).flatten();
        let mut sm = std::iter::repeat(SM_JITTER.iter()).flatten();

        for _ in 0..count {
            // iterate our starting bytes
            iter += u128::MAX / count as u128;
            iter += big.next().unwrap();
            node += u32::MAX / count as u32;
            node += sm.next().unwrap();

            // set our starting bytes
            pwd[..16].copy_from_slice(&iter.0.to_le_bytes());
            pwd[16..].copy_from_slice(&node.0.to_le_bytes());

            // get the starting difficulty
            let difficulty = Self::verify(&pwd, &salt)?;

            // create the output item
            out.push(WorkProof {
                pwd,
                salt,
                difficulty,
                iter,
            });
        }

        Ok(out)
    }

    /// Verify a [WorkProof] against a provided hash. Returns a log10
    /// difficulty.
    pub fn verify(proof: &[u8], hash: &[u8]) -> Result<f64> {
        let mut out = [0; 16];

        // access thread memory
        MEM.with_borrow_mut(|mem| {
            // do the actual hashing
            ARGON2.hash_password_into_with_memory(&proof, &hash, &mut out, mem)
        })
        .map_err(|err| err.to_string())?;

        // calculate the log10 difficulty number
        let pct = u128::from_le_bytes(out) as f64 / u128::MAX as f64;
        let dif = (1.0 / (1.0 - pct)).log10();

        Ok(dif)
    }

    /// Iterate this [WorkProof]. Returns a log10 difficulty.
    pub fn next(&mut self) -> Result<f64> {
        self.iter += 1;
        self.pwd[..16].copy_from_slice(&self.iter.0.to_le_bytes());
        self.difficulty = Self::verify(&self.pwd, &self.salt)?;
        Ok(self.difficulty)
    }

    /// Get the current proof.
    pub fn proof(&self) -> Vec<u8> {
        self.pwd.to_vec()
    }

    /// Returns a log10 difficulty.
    pub fn difficulty(&self) -> f64 {
        self.difficulty
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn simple() {
        let mut wp = WorkProof::init(2, &[0xdb; 20], &[0xdb; 32]).unwrap();
        let mut wp1 = wp.remove(0);
        let mut wp2 = wp.remove(0);

        let mut data = Vec::new();

        fn fuzz(f: f64) -> u32 {
            (f * 1000.0) as u32
        }

        data.push(fuzz(wp1.difficulty()));
        data.push(fuzz(wp2.difficulty()));

        wp1.next().unwrap();
        wp2.next().unwrap();

        data.push(fuzz(wp1.difficulty()));
        data.push(fuzz(wp2.difficulty()));

        let exp: Vec<u32> = vec![148, 249, 705, 70];

        assert_eq!(exp, data);
    }
}

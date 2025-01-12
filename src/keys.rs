use base64::prelude::*;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use std::fs::File;
use std::io::Write;
use std::io::{self, Read};
use curve25519_dalek::traits::VartimeMultiscalarMul;

/// Struct to hold public and private key pair
#[derive(Debug)]
pub struct KeyPair {
    pub private_key: Scalar,
    pub public_key: RistrettoPoint,
}

impl KeyPair {
    /// Generate a Schnorr signature key pair
    pub fn generate() -> KeyPair {
        let mut rng = OsRng;;
        let mut sk = Scalar::random(&mut rng);
        let pk = RISTRETTO_BASEPOINT_POINT * sk;

        KeyPair {
            private_key: sk,
            public_key: pk,
        }
    }

    /// Reads a private key and reconstructs the `KeyPair`
    pub fn from_file(sk_filepath: &str) -> io::Result<KeyPair> {
        let mut sk_file = File::open(sk_filepath)?;
        let mut sk_bytes = [0u8; 32];
        sk_file.read_exact(&mut sk_bytes)?;
        let private_key = Scalar::from_bytes_mod_order(sk_bytes);

        let public_key = private_key * RISTRETTO_BASEPOINT_POINT;

        Ok(KeyPair {
            private_key,
            public_key,
        })
    }

    /// Reads only the public key from a file
    pub fn pk_from_file(pk_filepath: &str) -> io::Result<RistrettoPoint> {
        let mut pk_file = File::open(pk_filepath)?;
        let mut pk_bytes = [0u8; 32];
        pk_file.read_exact(&mut pk_bytes)?;
        let compressed = CompressedRistretto(pk_bytes);
        compressed.decompress().ok_or(io::Error::new(
            io::ErrorKind::InvalidData,
            "Failed to decompress public key",
        ))
    }

    /// Writes the private key to a file
    pub fn write_sk_to_file(&self, filepath: &str) -> io::Result<()> {
        let mut file = File::create(filepath)?;
        let sk_bytes = self.private_key.to_bytes();
        file.write_all(&sk_bytes)?;
        Ok(())
    }

    /// Writes the public key to a file
    pub fn write_pk_to_file(&self, filepath: &str) -> io::Result<()> {
        let mut file = File::create(filepath)?;
        let pk_bytes = self.public_key.compress().to_bytes();
        file.write_all(&pk_bytes)?;
        Ok(())
    }

    /// Reads the private key from a file
    pub fn read_sk_from_file(filepath: &str) -> io::Result<Scalar> {
        let mut file = File::open(filepath)?;
        let mut sk_bytes = [0u8; 32];
        file.read_exact(&mut sk_bytes)?;
        Ok(Scalar::from_bytes_mod_order(sk_bytes))
    }

    /// Reads the public key from a file
    pub fn read_pk_from_file(filepath: &str) -> io::Result<RistrettoPoint> {
        let mut file = File::open(filepath)?;
        let mut pk_bytes = [0u8; 32];
        file.read_exact(&mut pk_bytes)?;
        let compressed = CompressedRistretto(pk_bytes);
        compressed.decompress().ok_or(io::Error::new(
            io::ErrorKind::InvalidData,
            "Failed to decompress public key",
        ))
    }
}

// Unit tests for keys module
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_generate_keypair() {
        let keypair = KeyPair::generate();
        assert!(
            keypair.public_key != RistrettoPoint::default(),
            "Public key should not be default"
        );
        assert!(
            keypair.private_key != Scalar::default(),
            "Private key should not be default"
        );
        assert!(
            keypair.private_key * &RISTRETTO_BASEPOINT_POINT == keypair.public_key,
            "Public key should be g^private_key"
        )
    }

    #[test]
    fn test_write_and_read_keypair() {
        let keypair = KeyPair::generate();
        let pk_filepath = "pk_test.txt";
        let sk_filepath = "sk_test.txt";

        // Write the keypair to a file
        keypair
            .write_sk_to_file(&sk_filepath)
            .expect("Failed to write sk to file");
        keypair
            .write_pk_to_file(&pk_filepath)
            .expect("Failed to write pk to file");

        // Read the keypair back from the file
        let read_keypair =
            KeyPair::from_file(&sk_filepath).expect("Failed to read keypair from file");

        let read_pk = KeyPair::pk_from_file(&pk_filepath).expect("Failed to read pk from file");

        // Check if the written and read key pairs are equal
        assert_eq!(
            keypair.private_key, read_keypair.private_key,
            "Private keys should match"
        );
        assert_eq!(
            keypair.public_key, read_keypair.public_key,
            "Public keys should match"
        );
        assert_eq!(keypair.public_key, read_pk, "Public keys should match");

        // Clean up the test file
        fs::remove_file(&sk_filepath).expect("Failed to remove sk test file");
        fs::remove_file(&pk_filepath).expect("Failed to remove pk test file");
    }
}

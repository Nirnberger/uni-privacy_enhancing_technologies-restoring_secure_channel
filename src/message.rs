use crate::hybrid_enc::HybridCiphertext;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use crate::keys::KeyPair;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use crate::schnorr::SchnorrSignature;
use crate::serializers::*;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use serde_json;
use std::fs::File;
use std::io::Read;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub version: u8, // The version number of the message (1 byte)

    #[serde(
        serialize_with = "serialize_base64",
        deserialize_with = "deserialize_base64"
    )]
    pub payload: Vec<u8>, // The message content (or payload) stored as a Base64-encoded string in JSON.
    #[serde(
        serialize_with = "serialize_fixed_base64",
        deserialize_with = "deserialize_fixed_base64"
    )]
    pub recipient: [u8; 32], // The recipient's identifier (stored as Vec<u8> to serialize easily)
    #[serde(
        serialize_with = "serialize_fixed_base64",
        deserialize_with = "deserialize_fixed_base64"
    )]
    pub sender: [u8; 32], // The recipient's identifier (stored as Vec<u8> to serialize easily)
    #[serde(
        serialize_with = "serialize_schnorr_signature",
        deserialize_with = "deserialize_schnorr_signature"
    )]
    pub signature: SchnorrSignature,
}

impl Message {
    /// Creates a new message with a version, payload, and recipient (CompressedRistretto converted to Vec<u8>)
    pub fn new(
        version: u8,
        payload: Vec<u8>,
        sender: CompressedRistretto,
        recipient: CompressedRistretto,
        signature: SchnorrSignature,
    ) -> Self {
        Message {
            version,
            payload,
            sender: sender.to_bytes(),
            recipient: recipient.to_bytes(),
            signature,
        }
    }

    /// Writes the message to a JSON file
    pub fn to_file(&self, filepath: &str) -> std::io::Result<()> {
        let file = File::create(filepath)?;
        serde_json::to_writer_pretty(file, &self)?; // Write JSON in a human-readable format
        Ok(())
    }

    /// Encrypts the whole message using hybrid encryption
    pub fn encrypt(&mut self, elgamal_public_key: &RistrettoPoint) -> Result<(), String> {
        // Serialize the message
        let serialized_message = serialize_message_to_bytes(self)
            .map_err(|e| format!("Failed to serialize message: {}", e))?;

        // Perform hybrid encryption
        let hybrid_ciphertext = HybridCiphertext::encrypt(&serialized_message, elgamal_public_key)?;

        // Update the payload with the encrypted message
        self.payload = hybrid_ciphertext.serialize();
        self.version += 1;

        Ok(())
    }

    /// Decrypts the payload using hybrid decryption, sets version back to 0
    pub fn decrypt(&mut self, elgamal_private_key: &Scalar) -> Result<(), String> {
        // Deserialize the payload into a HybridCiphertext
        let hybrid_ciphertext = HybridCiphertext::deserialize(&self.payload)
            .map_err(|e| format!("Failed to deserialize payload: {}", e))?;

        // Decrypt the message
        let decrypted_message = hybrid_ciphertext.decrypt(elgamal_private_key)?;

        // Deserialize the decrypted message back into the Message struct
        let original_message = deserialize_message_from_bytes(&decrypted_message)
            .map_err(|e| format!("Failed to deserialize decrypted message: {}", e))?;

        // Update self with the original message's data
        self.version = original_message.version;
        self.payload = original_message.payload;
        self.sender = original_message.sender;
        self.recipient = original_message.recipient;
        self.signature = original_message.signature;

        Ok(())
    }

    /// signs the payload using Schnorr signatures, sets the signing public key as sender
    pub fn sign(&mut self, signing_key: &Scalar) {
        let signature = SchnorrSignature::sign(&self.payload, signing_key);
        self.signature = signature;

        // Set the sender as the public key corresponding to the signing key
        let signing_public_key = signing_key * RISTRETTO_BASEPOINT_POINT;
        self.sender = signing_public_key.compress().to_bytes();
    }

    /// Displays the message in a human-readable format
    pub fn display(&self) {
        println!("Message Version: {}", self.version);
        println!("Payload: {:?}", String::from_utf8_lossy(&self.payload));
        println!("Recipient: {:?}", base64::encode(&self.recipient));
        println!("Sender: {:?}", base64::encode(&self.sender));
        println!("Signature: R = {:?}, s = {:?}", 
            base64::encode(self.signature.R.compress().as_bytes()), 
            base64::encode(self.signature.s.to_bytes()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use rand::rngs::OsRng;
    use std::fs;

    #[test]
    fn test_message_creation() {
        // Create a sample payload and recipient
        let payload = b"Hello, this is a message!".to_vec();
        let mut csprng = OsRng;
        let recipient = RistrettoPoint::random(&mut csprng).compress();

        // Create a new message
        let version: u8 = 1;
        let message = Message::new(
            version,
            payload.clone(),
            recipient,
            recipient,
            SchnorrSignature::emty_signature(),
        );

        // Check if the fields match
        assert_eq!(message.version, version);
        assert_eq!(message.payload, payload);
        assert_eq!(message.recipient, recipient.to_bytes());

        // Display the message
        message.display();
    }

    #[test]
    fn test_message_encryption_and_decryption() {
        // Sample message to encrypt
        let payload = b"Hello, hybrid encryption!".to_vec();

        // Generate ElGamal keypair
        let keypair = KeyPair::generate();

        // Create a new message with version 0
        let mut message = Message::new(
            0,
            payload.clone(),
            keypair.public_key.compress(),
            keypair.public_key.compress(),
            SchnorrSignature::emty_signature(),
        );

        // Encrypt the message
        message
            .encrypt(&keypair.public_key)
            .expect("Encryption failed");

        // Ensure the message version is 1 after encryption
        assert_eq!(message.version, 1, "Version should be 1 after encryption");

        // Ensure the payload is not the same as the original (it should be encrypted)
        assert_ne!(
            message.payload, payload,
            "Encrypted payload should not match the original payload"
        );

        // Decrypt the message
        message
            .decrypt(&keypair.private_key)
            .expect("Decryption failed");

        // Ensure the message version is back to 0 after decryption
        assert_eq!(message.version, 0, "Version should be 0 after decryption");

        // Ensure the decrypted message matches the original payload
        assert_eq!(
            message.payload, payload,
            "Decrypted payload should match the original payload"
        );
    }
}

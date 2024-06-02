use ssh_encoding::Decode;
use ssh_key::{public::KeyData, PublicKey};

use crate::error::AgentError;

#[derive(Debug, PartialEq, Clone)]
pub struct SignRequest {
    pub pubkey: PublicKey,
    pub data: Vec<u8>,
    pub flags: u32,
}


impl Decode for SignRequest {
    type Error = AgentError;

    fn decode(reader: &mut impl ssh_encoding::Reader) -> core::result::Result<Self, Self::Error> {
        let pubkey = reader.read_prefixed(KeyData::decode).map_err(|x| AgentError::SshKey(x))?;
        let data = Vec::decode(reader)?;
        let flags = u32::decode(reader)?;

        Ok(Self {
            pubkey: pubkey.into(),
            data,
            flags
        })
    }
}
use ssh_encoding::{CheckedSum, Decode, Encode};
use ssh_key::{public::KeyData, Signature};

use crate::{error::AgentError, sign::SignRequest};

#[derive(Clone, PartialEq, Debug)]
pub enum Message {
    // Failure,
    // Success,
    RequestIdentities,
    SignRequest(SignRequest),
    Extension,
}

#[derive(Debug)]
pub struct IdentityBlob {
    pub pubkey: KeyData,
    pub comment: String,
}

#[derive(Debug)]
pub enum Response {
    Failure,
    Success,
    ListIdentities(Vec<IdentityBlob>),
    Signature(Signature),
}

impl Decode for Message {
    type Error = AgentError;

    fn decode(reader: &mut impl ssh_encoding::Reader) -> Result<Self, Self::Error> {
        let read = u8::decode(reader)?;

        dbg!(&read);

        match read {
            11 => Ok(Message::RequestIdentities),
            13 => SignRequest::decode(reader).map(Self::SignRequest),
            27 => Ok(Message::Extension),
            _ => Err(AgentError::NotFound),
        }
    }
}

impl Response {
    pub fn id(&self) -> u8 {
        match self {
            Self::Failure => 5,
            Self::Success => 6,
            Self::ListIdentities(_) => 12,
            Self::Signature(_) => 14,
        }
    }
}

impl Encode for Response {
    fn encoded_len(&self) -> Result<usize, ssh_encoding::Error> {
        let payload = match self {
            Self::ListIdentities(ids) => {
                let mut lengths = Vec::with_capacity(1 + ids.len());
                // Prefixed length
                lengths.push(4);

                for id in ids {
                    lengths.push(id.encoded_len()?);
                }

                lengths.checked_sum()?
            }
            Self::Signature(si) => si.encoded_len_prefixed()?,
            Self::Failure => 0,
            Self::Success => 0,
        };

        [1, payload].checked_sum()
    }

    fn encode(&self, writer: &mut impl ssh_encoding::Writer) -> Result<(), ssh_encoding::Error> {
        let id = self.id();
        id.encode(writer)?;

        match self {
            Self::Failure => {}
            Self::Success => {}
            Self::ListIdentities(ids) => {
                (ids.len() as u32).encode(writer)?;
                for id in ids {
                    id.encode(writer)?;
                }
            }
            Self::Signature(si) => si.encode_prefixed(writer)?,
        }

        Ok(())
    }
}

impl Encode for IdentityBlob {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        [
            self.pubkey.encoded_len_prefixed()?,
            self.comment.encoded_len()?,
        ]
        .checked_sum()
    }

    fn encode(&self, writer: &mut impl ssh_encoding::Writer) -> ssh_encoding::Result<()> {
        self.pubkey.encode_prefixed(writer)?;
        self.comment.encode(writer)?;

        Ok(())
    }
}

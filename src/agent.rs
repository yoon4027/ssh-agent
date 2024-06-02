use std::{marker::PhantomData, mem::size_of};


use async_trait::async_trait;
use ssh_encoding::{Decode,Encode};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{Decoder, Encoder};
use bytes::{Buf, BufMut, BytesMut};
use byteorder::{ BigEndian, ReadBytesExt };

use crate::error::AgentError;

#[derive(Debug)]
pub struct Codec<Input, Output>(PhantomData<Input>, PhantomData<Output>)
where
    Input: Decode,
    Output: Encode,
    AgentError: From<Input::Error>;

impl<Input, Output> Default for Codec<Input, Output>
where
    Input: Decode,
    Output: Encode,
    AgentError: From<Input::Error>,
{
    fn default() -> Self {
        Self(PhantomData, PhantomData)
    }
}

impl<Input, Output> Decoder for Codec<Input, Output>
where
    Input: Decode,
    Output: Encode,
    AgentError: From<Input::Error>,
{
    type Item = Input;
    type Error = AgentError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let mut bytes = &src[..];

        if bytes.len() < size_of::<u32>() {
            return Ok(None);
        }

        let length = bytes.read_u32::<BigEndian>()? as usize;

        if bytes.len() < length {
            return Ok(None);
        }

        let message = Self::Item::decode(&mut bytes)?;
        src.advance(size_of::<u32>() + length);
        Ok(Some(message))
    }
}

impl<Input, Output> Encoder<Output> for Codec<Input, Output>
where
    Input: Decode,
    Output: Encode,
    AgentError: From<Input::Error>,
{
    type Error = AgentError;

    fn encode(&mut self, item: Output, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let mut bytes = Vec::new();

        let len = item.encoded_len().unwrap() as u32;
        len.encode(&mut bytes).unwrap();

        item.encode(&mut bytes).unwrap();
        dst.put(&*bytes);

        Ok(())
    }
}



#[async_trait]
pub trait ListeningSocket {
    /// Stream type that represents an accepted socket.
    type Stream: std::fmt::Debug + AsyncRead + AsyncWrite + Send + Unpin + 'static;

    /// Waits until a client connects and returns connected stream.
    async fn accept(&mut self) -> std::io::Result<Self::Stream>;
}


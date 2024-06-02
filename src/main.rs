use agent::{Codec, ListeningSocket};
use futures::{SinkExt, TryStreamExt};
use messages::{IdentityBlob, Message, Response};
use sign::SignRequest;
use std::{
    path::Path,
    sync::{Arc, RwLock},
};

use async_trait::async_trait;
use eyre::Result;
use rsa::{
    pss::SigningKey,
    sha2::{Sha256, Sha512},
    signature::{RandomizedSigner, SignatureEncoding},
};
use sha1::Sha1;
use ssh_key::{private::KeypairData, Algorithm, PrivateKey, PublicKey, Signature};
use tokio::{
    fs::remove_file,
    net::{UnixListener, UnixStream},
};
use tokio_util::codec::Framed;

mod agent;
mod error;
mod messages;
mod sign;

use self::error::AgentError;

#[derive(Debug)]
struct Identity {
    pubkey: PublicKey,
    privkey: PrivateKey,
    comment: String,
}

#[async_trait]
impl ListeningSocket for UnixListener {
    type Stream = UnixStream;
    async fn accept(&mut self) -> std::io::Result<Self::Stream> {
        UnixListener::accept(&self).await.map(|(x, _)| x)
    }
}

impl Identity {
    fn new(key: &[u8]) -> Self {
        let p = PrivateKey::from_openssh(key).unwrap();

        Identity {
            pubkey: p.public_key().clone(),
            comment: p.comment().to_owned(),
            privkey: p,
        }
    }
}

struct KeyStorage {
    identifiers: RwLock<Vec<Identity>>,
}

impl KeyStorage {
    fn new() -> Self {
        Self {
            identifiers: RwLock::new(vec![Identity::new(include_bytes!("../key.txt"))]),
        }
    }

    fn identify_index_from_publickey(&self, key: &PublicKey) -> Option<usize> {
        let ident = self.identifiers.read().unwrap();

        let mut shut = PublicKey::new(key.key_data().to_owned(), "");

        ident.iter().position(|x| {
            shut.set_comment(&x.comment);

            shut == x.pubkey
        })
    }

    fn request_identities(&self) -> Vec<IdentityBlob> {
        let identities = self.identifiers.read().unwrap();

        let mut results = vec![];

        identities.iter().for_each(|x| {
            results.push(IdentityBlob {
                pubkey: x.pubkey.clone().into(),
                comment: x.comment.to_owned(),
            })
        });

        results
    }

    fn sign(&self, request: SignRequest) -> Result<Signature, AgentError> {
        let indentities = self.identifiers.read().unwrap();

        if let Some(i) = self.identify_index_from_publickey(&request.pubkey) {
            let key = &indentities[i];

            match key.privkey.key_data() {
                KeypairData::Rsa(ref key) => {
                    let mut rng = rand::thread_rng();
                    let private_key = key.try_into()?;
                    let data = &request.data;
                    let algorithm;

                    let signature = if request.flags & 0x04 != 0 {
                        algorithm = "rsa-sha2-512";
                        SigningKey::<Sha512>::new(private_key).sign_with_rng(&mut rng, data)
                    } else if request.flags & 0x02 != 0 {
                        algorithm = "rsa-sha2-256";
                        SigningKey::<Sha256>::new(private_key).sign_with_rng(&mut rng, data)
                    } else {
                        algorithm = "ssha";
                        SigningKey::<Sha1>::new(private_key).sign_with_rng(&mut rng, data)
                    };

                    Ok(Signature::new(
                        Algorithm::new(algorithm)?,
                        signature.to_bytes(),
                    )?)
                }
                _ => Err(AgentError::NotFound),
            }
        } else {
            Err(AgentError::NotFound)
        }
    }

    fn handle_message(&self, msg: Message) -> Result<Response, AgentError> {
        match msg {
            Message::RequestIdentities => Ok(Response::ListIdentities(self.request_identities())),
            Message::SignRequest(req) => Ok(Response::Signature(self.sign(req)?)),
            Message::Extension => Ok(Response::Success),
        }
    }

    async fn handle_socket<T: ListeningSocket>(
        &self,
        mut framed: Framed<T::Stream, Codec<Message, Response>>,
    ) -> Result<(), AgentError> {
        loop {
            let a = framed.try_next().await.unwrap();

            if let Some(msg) = a {
                let result = match self.handle_message(msg) {
                    Ok(response) => response,
                    Err(_) => Response::Failure,
                };

                dbg!(&result);

                framed.send(result).await?;
            }
        }
    }
}

struct Agent;

impl Agent {
    pub async fn listen<T>(mut socket: T) -> Result<()>
    where
        T: ListeningSocket + Send,
    {
        let sto = KeyStorage::new();

        let a = Arc::new(sto);
        loop {
            match socket.accept().await {
                Ok(b) => {
                    let storage = a.clone();
                    tokio::spawn(async move {
                        let frame = Framed::new(b, Codec::default());

                        if let Err(why) = storage.handle_socket::<T>(frame).await {
                            println!("fuck you {:?}", why);
                            Err(AgentError::NotFound)
                        } else {
                            Ok(())
                        }
                    });
                }
                Err(why) => println!("An eror occoured gang: {why}"),
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let soc = Path::new("gang.sock");

    if soc.exists() {
        remove_file(soc).await.unwrap();
    }

    let socket = UnixListener::bind(soc).unwrap();

    Agent::listen(socket).await.unwrap();
}

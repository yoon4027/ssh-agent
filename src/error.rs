use thiserror::Error;

#[derive(Error, Debug)]
pub enum AgentError {
    #[error("IO Error: {0}")]
    IOError(#[from] std::io::Error),

    #[error("Report Error")]
    ReportError(#[from] eyre::Report),

    #[error("Identity not found")]
    NotFound,

    #[error("SSH encoding error: {0}")]
    SshEncoding(#[from] ssh_encoding::Error),

    #[error("SSH key error")]
    SshKey(#[from] ssh_key::Error),
}

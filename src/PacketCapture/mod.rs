use crate::core::RunMode;

pub mod windivert;
pub use windivert_adapter::{CaptureError, ErrorKind};

/// No Debug: packet bytes and native metadata must not enter diagnostic logs.
pub struct CapturedPacket<A> {
    pub bytes: Vec<u8>,
    pub address: A,
}

pub enum ReceiveEvent<A> {
    Packet(CapturedPacket<A>),
    Idle,
    /// Only a successful shutdown followed by an empty queue is EOF.
    End,
}

/// receive returns periodically (100 ms in the real adapter).
/// Address equality includes all native bytes, including checksum/offload flags.
pub trait PacketCapture {
    type Address: Clone + PartialEq;
    fn mode(&self) -> RunMode;
    fn receive(&mut self) -> Result<ReceiveEvent<Self::Address>, CaptureError>;
    fn send(&mut self, packet: &CapturedPacket<Self::Address>) -> Result<(), CaptureError>;
    fn shutdown_receive(&mut self) -> Result<(), CaptureError>;
    /// Finish/cancel pending I/O, then close. Must be idempotent.
    fn close(&mut self) -> Result<(), CaptureError>;
}

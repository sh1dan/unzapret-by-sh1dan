use crate::capture::{CaptureError, CapturedPacket, PacketCapture, ReceiveEvent};
use crate::core::{phase2_config::Phase2Config, RunMode};
use windivert_adapter::{Address, Capture, Mode, Poll};

pub struct WinDivertCapture {
    inner: Capture,
    mode: RunMode,
}

impl WinDivertCapture {
    pub fn open(config: &Phase2Config, mode: RunMode) -> Result<Self, CaptureError> {
        let filter = config.filter()?;
        Self::open_filter(&filter, mode)
    }

    pub fn open_filter(filter: &str, mode: RunMode) -> Result<Self, CaptureError> {
        let native_mode = match mode {
            RunMode::Active => Mode::Active,
            RunMode::DryRun => Mode::Sniff,
        };
        Ok(Self { inner: Capture::open(filter, native_mode)?, mode })
    }
}

impl PacketCapture for WinDivertCapture {
    type Address = Address;
    fn mode(&self) -> RunMode { self.mode }
    fn receive(&mut self) -> Result<ReceiveEvent<Address>, CaptureError> {
        Ok(match self.inner.receive()? {
            Poll::Packet(packet) => ReceiveEvent::Packet(CapturedPacket {
                bytes: packet.bytes, address: packet.address,
            }),
            Poll::Idle => ReceiveEvent::Idle,
            Poll::End => ReceiveEvent::End,
        })
    }
    fn send(&mut self, packet: &CapturedPacket<Address>) -> Result<(), CaptureError> {
        self.inner.send(&packet.bytes, &packet.address)
    }
    fn shutdown_receive(&mut self) -> Result<(), CaptureError> { self.inner.shutdown_receive() }
    fn close(&mut self) -> Result<(), CaptureError> { self.inner.close() }
}

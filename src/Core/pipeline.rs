use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use crate::capture::{CaptureError, ErrorKind, PacketCapture, ReceiveEvent, CapturedPacket};
use crate::filtering::{DestinationFilter, FilterDecision, FilterEngine};
use crate::strategies::{Strategy, ProcessResult};
use super::{
    flow::{FlowClassification, FlowKey, FlowTable},
    parser::{self, ParseError, TransportMetadata},
    segment::split_tcp_packet,
    Counters, EngineError, InitialMetadata, PacketContext, PacketEngine, RunMode, Transport,
};

/// Active packet processing engine executing allowlist evaluation,
/// flow tracking, and evasion strategies (such as Split-TCP).
pub struct ActivePipelineEngine<C: PacketCapture> {
    capture: C,
    counters: Counters,
    filter_engine: FilterEngine,
    flow_table: FlowTable,
    strategy: Box<dyn Strategy>,
    report: fn(Counters),
}

impl<C: PacketCapture> ActivePipelineEngine<C> {
    pub fn new(
        capture: C,
        filter_engine: FilterEngine,
        flow_table: FlowTable,
        strategy: Box<dyn Strategy>,
        report: fn(Counters),
    ) -> Self {
        Self {
            capture,
            counters: Counters::default(),
            filter_engine,
            flow_table,
            strategy,
            report,
        }
    }

    fn pump(&mut self, mode: RunMode, stop: &AtomicBool) -> Result<Counters, EngineError> {
        if self.capture.mode() != mode { return Err(EngineError::InvalidConfiguration); }
        let mut stopping = None;
        let mut report_at = Instant::now();
        loop {
            if stop.load(Ordering::Acquire) && stopping.is_none() {
                self.capture.shutdown_receive().map_err(EngineError::Capture)?;
                stopping = Some(Instant::now());
            }
            if stopping.is_some_and(|start: Instant| start.elapsed() > Duration::from_secs(3)) {
                return Err(EngineError::Capture(CaptureError::new(ErrorKind::Shutdown, None)));
            }
            if report_at.elapsed() >= Duration::from_secs(5) {
                (self.report)(self.counters);
                report_at = Instant::now();
            }
            let event = match self.capture.receive() {
                Ok(event) => event,
                Err(error) => {
                    self.counters.receive_errors += 1;
                    self.counters.errors += 1;
                    if error.kind == ErrorKind::InvalidPacket && mode == RunMode::Active {
                        self.counters.dropped += 1;
                    }
                    return Err(EngineError::Capture(error));
                }
            };
            let packet = match event {
                ReceiveEvent::Idle => continue,
                ReceiveEvent::End if stopping.is_some() => return Ok(self.counters),
                ReceiveEvent::End => return Err(EngineError::Capture(
                    CaptureError::new(ErrorKind::Receive, None))),
                ReceiveEvent::Packet(packet) => packet,
            };
            self.counters.processed += 1;

            let metadata = match parser::parse(&packet.bytes) {
                Ok(meta) => {
                    match meta.version {
                        4 => self.counters.ipv4 += 1,
                        6 => self.counters.ipv6 += 1,
                        _ => unreachable!(),
                    }
                    match meta.transport {
                        TransportMetadata::Tcp { .. } => self.counters.tcp += 1,
                        TransportMetadata::Udp { .. } => self.counters.udp += 1,
                    }
                    meta
                }
                Err(ParseError::Malformed) => {
                    self.counters.malformed += 1;
                    self.reinject_unmodified(mode, &packet)?;
                    continue;
                }
                Err(ParseError::Unsupported) => {
                    self.counters.unsupported += 1;
                    self.reinject_unmodified(mode, &packet)?;
                    continue;
                }
            };

            let (src_port, dst_port, transport) = match metadata.transport {
                TransportMetadata::Tcp { source_port, destination_port, .. } => {
                    (source_port, destination_port, Transport::Tcp)
                }
                TransportMetadata::Udp { source_port, destination_port, .. } => {
                    (source_port, destination_port, Transport::Udp)
                }
            };

            // Flow classification
            let flow_key = FlowKey {
                src: metadata.source,
                dst: metadata.destination,
                src_port,
                dst_port,
                transport,
            };
            let flow_class = self.flow_table.classify(flow_key);
            let is_initial = flow_class == FlowClassification::InitialPayload;

            // Extract transport payload
            let payload_offset = match metadata.transport {
                TransportMetadata::Tcp { data_offset, .. } => metadata.header_length + usize::from(data_offset) * 4,
                TransportMetadata::Udp { .. } => metadata.header_length + 8,
            };
            let payload = if payload_offset <= packet.bytes.len() {
                &packet.bytes[payload_offset..]
            } else {
                &[]
            };

            // Inspect application-layer metadata (TLS ClientHello SNI, QUIC Initial)
            let mut server_name = None;
            let mut initial = InitialMetadata::Unknown;

            match transport {
                Transport::Tcp => {
                    if let Ok(Some(sni)) = super::tls::parse_client_hello(payload) {
                        server_name = Some(sni);
                        initial = InitialMetadata::TlsClientHello;
                    }
                }
                Transport::Udp => {
                    if let Ok(quic_hdr) = super::quic::parse_quic_initial(payload) {
                        initial = InitialMetadata::QuicInitial { version: quic_hdr.version };
                    } else if super::stun::parse_stun(payload).is_ok() {
                        initial = InitialMetadata::Stun;
                    }
                    // Note: RTP media streams (RFC 3550) remain InitialMetadata::Unknown and pass through unmodified
                }
            }

            // Initial context to evaluate destination filter
            let mut context = PacketContext {
                packet: &packet.bytes,
                destination: metadata.destination,
                destination_port: dst_port,
                transport,
                server_name,
                initial,
                initial_payload: is_initial,
                filter: FilterDecision::NoMatch,
            };

            // Destination filtering (now takes advantage of open SNI for domain allowlists!)
            context.filter = self.filter_engine.evaluate(&context);

            let plan = crate::strategies::evaluate(&*self.strategy, &context, mode);

            match plan {
                ProcessResult::PassThrough => {
                    self.reinject_unmodified(mode, &packet)?;
                }
                ProcessResult::WouldModify => {
                    // Dry-run mode: count modification intention, do not send
                    self.counters.modified += 1;
                }
                ProcessResult::SplitTcp { payload_offset } => {
                    // Active mode Split-TCP
                    match split_tcp_packet(&packet.bytes, payload_offset) {
                        Ok((seg1_bytes, seg2_bytes)) => {
                            self.counters.modified += 1;
                            let seg1 = CapturedPacket {
                                bytes: seg1_bytes,
                                address: packet.address.clone(),
                            };
                            let seg2 = CapturedPacket {
                                bytes: seg2_bytes,
                                address: packet.address,
                            };
                            if let Err(error) = self.capture.send(&seg1) {
                                self.counters.send_errors += 1;
                                self.counters.errors += 1;
                                self.counters.dropped += 1;
                                return Err(EngineError::Capture(error));
                            }
                            self.counters.reinserted += 1;

                            if let Err(error) = self.capture.send(&seg2) {
                                self.counters.send_errors += 1;
                                self.counters.errors += 1;
                                self.counters.dropped += 1;
                                return Err(EngineError::Capture(error));
                            }
                            self.counters.reinserted += 1;
                        }
                        Err(_) => {
                            // If split failed (e.g. payload too small), pass through safely
                            self.reinject_unmodified(mode, &packet)?;
                        }
                    }
                }
            }
        }
    }

    fn reinject_unmodified(&mut self, mode: RunMode, packet: &CapturedPacket<C::Address>) -> Result<(), EngineError> {
        if mode == RunMode::Active {
            if let Err(error) = self.capture.send(packet) {
                self.counters.send_errors += 1;
                self.counters.errors += 1;
                self.counters.dropped += 1;
                return Err(EngineError::Capture(error));
            }
            self.counters.reinserted += 1;
        }
        Ok(())
    }
}

impl<C: PacketCapture> PacketEngine for ActivePipelineEngine<C> {
    fn run(&mut self, mode: RunMode, stop: &AtomicBool) -> Result<Counters, EngineError> {
        let result = self.pump(mode, stop);
        let shutdown = self.capture.shutdown_receive().map_err(EngineError::Capture);
        let close = self.capture.close().map_err(EngineError::Capture);
        if shutdown.is_err() || close.is_err() { self.counters.errors += 1; }
        result.and(shutdown.map(|()| self.counters)).and(close.map(|()| self.counters))
    }
    fn counters(&self) -> Counters { self.counters }
}

// Keep PassThroughEngine backwards compatibility for existing contract tests
pub type PassThroughEngine<C> = ActivePipelineEngine<C>;

impl<C: PacketCapture> PassThroughEngine<C> {
    pub fn new_passthrough(capture: C, report: fn(Counters)) -> Self {
        use crate::filtering::engine::FilterEngine;
        use crate::strategies::PassThrough;
        Self::new(
            capture,
            FilterEngine::new(vec![], vec![], vec![]),
            FlowTable::with_defaults(),
            Box::new(PassThrough),
            report,
        )
    }
}

use itertools::Itertools;
use num_complex::Complex;

const CHANNELS: usize = 2048;
/// Size of the packet count header
const TIMESTAMP_SIZE: usize = 8;
/// FPGA UDP "Word" size (8 bytes as per CASPER docs)
const WORD_SIZE: usize = 8;
/// Total number of bytes in the spectra block of the UDP payload
const SPECTRA_SIZE: usize = 8192;
/// Total UDP payload size
pub const PAYLOAD_SIZE: usize = SPECTRA_SIZE + TIMESTAMP_SIZE;
// UDP Header size (spec-defined)
const UDP_HEADER_SIZE: usize = 42;

#[derive(Debug, Clone, Copy)]
pub struct Channel(Complex<i8>);

impl Default for Channel {
    fn default() -> Self {
        Self(Complex { re: 0, im: 0 })
    }
}

impl Channel {
    #[must_use]
    pub fn new(re: i8, im: i8) -> Self {
        Self(Complex::new(re, im))
    }

    #[allow(clippy::cast_sign_loss)]
    #[must_use]
    pub fn abs_squared(&self) -> u16 {
        let r = i16::from(self.0.re);
        let i = i16::from(self.0.im);
        (r * r + i * i) as u16
    }
}

pub type Channels = [Channel; CHANNELS];

#[derive(Debug, Clone)]
pub struct Payload {
    /// Number of packets since the first packet
    pub count: u64,
    pub pol_a: [Channel; CHANNELS],
    pub pol_b: [Channel; CHANNELS],
}

impl Default for Payload {
    fn default() -> Self {
        Self {
            count: Default::default(),
            pol_a: [Channel::default(); CHANNELS],
            pol_b: [Channel::default(); CHANNELS],
        }
    }
}

impl Payload {
    /// Construct a payload instance from a raw UDP payload
    #[allow(clippy::cast_possible_wrap)]
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut payload = Payload::default();
        for (i, word) in bytes[TIMESTAMP_SIZE..].chunks_exact(WORD_SIZE).enumerate() {
            // Each word contains two frequencies for each polarization
            // [A1 B1 A2 B2]
            // Where each channel is [Re Im] as FixedI8<7>
            payload.pol_a[2 * i] = Channel::new(word[0] as i8, word[1] as i8);
            payload.pol_a[2 * i + 1] = Channel::new(word[4] as i8, word[5] as i8);
            payload.pol_b[2 * i] = Channel::new(word[2] as i8, word[3] as i8);
            payload.pol_b[2 * i + 1] = Channel::new(word[6] as i8, word[7] as i8);
        }
        // Then unpack the timestamp/order
        payload.count = u64::from_be_bytes(
            bytes[0..TIMESTAMP_SIZE]
                .try_into()
                .expect("This is exactly 8 bytes"),
        );
        payload
    }
}

const CAP_PACKS: usize = 1_000_000;

fn main() {
    let device = pcap::Device::list()
        .expect("Error listing devices from Pcap")
        .into_iter()
        .find(|d| d.name == "enp129s0f0")
        .unwrap_or_else(|| panic!("Device not found"));
    // Create the "capture"
    let mut cap = pcap::Capture::from_device(device)
        .expect("Failed to create capture")
        .buffer_size(33_554_432) // Up to 20ms
        .open()
        .expect("Failed to open the capture")
        .setnonblock()
        .unwrap();
    // Add the port filter
    cap.filter("dst port 60000", true)
        .expect("Error creating port filter");

    let mut counts = vec![0u64; CAP_PACKS];
    let mut packets = 0usize;

    let mut last_dropped = 0;

    // Grab 10_000_000 payloads
    while packets < CAP_PACKS {
        if let Ok(p) = cap.next_packet() {
            if p.data.len() == (PAYLOAD_SIZE + UDP_HEADER_SIZE) {
                let pl = Payload::from_bytes(&p.data[UDP_HEADER_SIZE..]);
                counts[packets] = pl.count;
                packets += 1;
            } else {
                eprintln!("Bad packet???");
                continue;
            }
        }
        let stats = cap.stats().unwrap();
        let dropped = stats.dropped + stats.if_dropped;
        if dropped > last_dropped {
            eprintln!("Dropping packets!!");
            last_dropped = dropped;
        }
    }

    counts.sort();
    let mut deltas: Vec<_> = counts.windows(2).map(|x| x[1] - x[0]).collect();
    deltas.sort();
    let deltas: Vec<_> = deltas.iter().dedup_with_count().collect();
    dbg!(deltas);
}

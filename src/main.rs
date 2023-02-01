use itertools::Itertools;

/// Size of the packet count header
const TIMESTAMP_SIZE: usize = 8;
/// Total number of bytes in the spectra block of the UDP payload
const SPECTRA_SIZE: usize = 8192;
/// Total UDP payload size
pub const PAYLOAD_SIZE: usize = SPECTRA_SIZE + TIMESTAMP_SIZE;
// UDP Header size (spec-defined)
const UDP_HEADER_SIZE: usize = 42;

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
    while packets < CAP_PACKS {
        if let Ok(p) = cap.next_packet() {
            if p.data.len() == (PAYLOAD_SIZE + UDP_HEADER_SIZE) {
                counts[packets] = u64::from_be_bytes(p.data[..TIMESTAMP_SIZE].try_into().unwrap());
                packets += 1;
            } else {
                println!("Bad packet???");
                continue;
            }
        }
        let stats = cap.stats().unwrap();
        let dropped = stats.dropped + stats.if_dropped;
        if dropped > last_dropped {
            println!("Dropping packets!!");
            last_dropped = dropped;
        }
    }
    counts.sort();
    let mut deltas: Vec<_> = counts.windows(2).map(|x| x[1] - x[0]).collect();
    deltas.sort();
    let deltas: Vec<_> = deltas.iter().dedup_with_count().collect();
    dbg!(deltas);
}

pub mod byte_packet_buffer;
pub mod dns;
pub mod result_code;

use byte_packet_buffer::BytePacketBuffer;
use dns::packet::DnsPacket;
use std::fs::File;
use std::io::{Read, Result};

// Parse DNS response packet (from a text file) and print
// the results to the console. This function is intended for
// testing only.
pub fn parse_response_from_file(filep: &str) -> Result<()> {
    let mut f = File::open(filep)?;
    let mut buffer = BytePacketBuffer::new();

    // Read in file contents
    f.read(&mut buffer.buf)?;

    // generate DnsPacket from the buffer
    let packet = DnsPacket::from_buffer(&mut buffer)?;

    // Output
    println!("{:#?}", packet.header);

    for q in packet.questions {
        println!("{:#?}", q);
    }
    for rec in packet.answers {
        println!("{:#?}", rec);
    }
    for rec in packet.authorities {
        println!("{:#?}", rec);
    }
    for rec in packet.resources {
        println!("{:#?}", rec);
    }

    Ok(())
}

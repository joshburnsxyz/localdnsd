use crate::byte_packet_buffer::BytePacketBuffer;
use crate::dns::packet::DnsPacket;
use crate::dns::question::{DnsQuestion, QueryType};

use std::io::{Result, Error, ErrorKind};
use std::net::UdpSocket;

// Parse DNS response packet (from a text file) and print
// the results to the console. This function is intended for
// testing only.
pub fn print_response(packet: DnsPacket) -> Result<()> {
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


// Perform a generic DNS lookup query
pub fn lookup(qname: &str, qtype: QueryType) -> Result<DnsPacket> {
    // Define a target DNS server and a UdpSocket to connect to interact with it.
    let server = ("8.8.8.8", 53); // Target googles public DNS server.
    let socket = UdpSocket::bind(("0.0.0.0", 43210))?; // Bind to arbitrary UDP port.
    let mut packet = DnsPacket::new();

    packet.header.id = 12345;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet.questions.push(DnsQuestion::new(qname.to_string(), qtype));

    // Write packet to a new buffer
    let mut req_buffer = BytePacketBuffer::new();
    match packet.write(&mut req_buffer) {
        Err(err) => {return Err(Error::new(ErrorKind::Other, err))},
        Ok(_) =>  {/* Do not handle successful write*/}
    }

    // Relay to server using the socket
    socket.send_to(&req_buffer.buf[0..req_buffer.pos], server)?;

    // Create a buffer to hold response
    let mut res_buffer = BytePacketBuffer::new();
    match socket.recv_from(&mut res_buffer.buf) {
        Err(err) => {return Err(Error::new(ErrorKind::Other, err))},
        Ok(_) =>  {
            // Parse response using DnsPacket::from_buffer()
            let res_packet = DnsPacket::from_buffer(&mut res_buffer)?;
            Ok(res_packet)
        }
    }

}
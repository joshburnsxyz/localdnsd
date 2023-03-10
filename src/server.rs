use std::io::Error;
use std::net::UdpSocket;
use crate::byte_packet_buffer::BytePacketBuffer;
use crate::dns::packet::DnsPacket;
use crate::result_code::ResultCode;
use crate::utility::recursive_lookup;

pub fn handle_query(socket: &UdpSocket) -> Result<(), Error> {
  let mut req_buffer = BytePacketBuffer::new();
  let (_,src) = socket.recv_from(&mut req_buffer.buf)?;
  let mut request = DnsPacket::from_buffer(&mut req_buffer)?;

  // Create response packet
  let mut packet = DnsPacket::new();
  packet.header.id = 12345;
  packet.header.recursion_desired = true;
  packet.header.recursion_available = true;
  packet.header.response = true;

  if let Some(question) = request.questions.pop() {
    println!("Recieved Query: {:?}", question);

    if let Ok(result) = recursive_lookup(&question.name, question.qtype) {
      packet.questions.push(question.clone());
      packet.header.rescode = result.header.rescode;

      for rec in result.answers {
        println!("Answer: {:?}", rec);
        packet.answers.push(rec);
      }

      for rec in result.authorities {
        println!("Authority: {:?}", rec);
        packet.authorities.push(rec);
      }

      for rec in result.resources {
        println!("Resource: {:?}", rec);
        packet.resources.push(rec);
      }
    } else {
      // Error is set when query fails.
      packet.header.rescode = ResultCode::SERVFAIL;
    }
  } else {
    // If no question is present, set error
    packet.header.rescode = ResultCode::FORMERR;
  }

  // Encode response and sent it off
  let mut res_buffer = BytePacketBuffer::new();
  packet.write(&mut res_buffer)?;

  let len = res_buffer.pos();
  let data = res_buffer.get_range(0, len)?;

  socket.send_to(data, src)?;

  Ok(())
}


pub fn listen() -> Result<(), Error> {
  let socket = UdpSocket::bind(("0.0.0.0", 2053));
  loop {
    match handle_query(&socket.as_ref().unwrap()) {
      Ok(_) => {},
      Err(e) => eprintln!("An error occured: {}", e),
    }
  }
}
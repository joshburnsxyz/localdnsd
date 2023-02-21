use std::io;

pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}

#[allow(dead_code)]
impl BytePacketBuffer {
    // Construct new buffer
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; 512],
            pos: 0,
        }
    }

    // Return current position value
    pub fn pos(&self) -> usize {
        return self.pos;
    }

    // Move forward in the buffer X steps.
    pub fn step(&mut self, steps: usize) -> io::Result<()> {
        self.pos += steps;

        Ok(())
    }

    // Goto specific buffer position
    pub fn seek(&mut self, pos: usize) -> io::Result<()> {
        self.pos = pos;

        Ok(())
    }

    // Read a single byte and step forward
    pub fn read(&mut self) -> io::Result<u8> {
        // if we are at or over 512 bytes, bail out.
        if self.pos >= 512 {
            return Err(io::Error::new(io::ErrorKind::Other, "End of buffer"));
        }

        let res: u8 = self.buf[self.pos];
        self.pos += 1;

        return Ok(res);
    }

    // Get a single byte value without changing buffer position
    pub fn get(&self, pos: usize) -> io::Result<u8> {
        if self.pos >= 512 {
            return Err(io::Error::new(io::ErrorKind::Other, "End of buffer"));
        }

        let res: u8 = self.buf[pos];
        Ok(res)
    }

    // Read a range of byte values
    pub fn get_range(&mut self, start: usize, len: usize) -> io::Result<&[u8]> {
        if start + len >= 512 {
            return Err(io::Error::new(io::ErrorKind::Other, "End of buffer"));
        }

        Ok(&self.buf[start..start + len as usize])
    }

    pub fn read_u16(&mut self) -> io::Result<u16> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);
        Ok(res)
    }

    pub fn read_u32(&mut self) -> io::Result<u32> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | ((self.read()? as u32) << 0);

        Ok(res)
    }

    /// Read a qname
    ///
    /// The tricky part: Reading domain names, taking labels into consideration.
    /// Will take something like [3]www[6]google[3]com[0] and append
    /// www.google.com to outstr.
    pub fn read_qname(&mut self, outstr: &mut String) -> io::Result<()> {
        // Since we might encounter jumps, we'll keep track of our position
        // locally as opposed to using the position within the struct. This
        // allows us to move the shared position to a point past our current
        // qname, while keeping track of our progress on the current qname
        // using this variable.
        let mut pos = self.pos();

        // track whether or not we've jumped
        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;

        // Our delimiter which we append for each label. Since we don't want a
        // dot at the beginning of the domain name we'll leave it empty for now
        // and set it to "." at the end of the first iteration.
        let mut delim = "";
        loop {
            // Dns Packets are untrusted data, so we need to be paranoid. Someone
            // can craft a packet with a cycle in the jump instructions. This guards
            // against such packets.
            if jumps_performed > max_jumps {
                return Err(io::Error::new(io::ErrorKind::Other, format!("Limit of {} jumps exceeded", max_jumps)));
            }

            // At this point, we're always at the beginning of a label. Recall
            // that labels start with a length byte.
            let len = self.get(pos)?;

            // If len has the two most significant bit are set, it represents a
            // jump to some other offset in the packet:
            if (len & 0xC0) == 0xC0 {
                // Update the buffer position to a point past the current
                // label. We don't need to touch it any further.
                if !jumped {
                    self.seek(pos + 2)?;
                }

                // Read another byte, calculate offset and perform the jump by
                // updating our local position variable
                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                // Indicate that a jump was performed.
                jumped = true;
                jumps_performed += 1;

                continue;
            }
            // The base scenario, where we're reading a single label and
            // appending it to the output:
            else {
                // Move a single byte forward to move past the length byte.
                pos += 1;

                // Domain names are terminated by an empty label of length 0,
                // so if the length is zero we're done.
                if len == 0 {
                    break;
                }

                // Append the delimiter to our output buffer first.
                outstr.push_str(delim);

                // Extract the actual ASCII bytes for this label and append them
                // to the output buffer.
                let str_buffer = self.get_range(pos, len as usize)?;
                outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

                delim = ".";

                // Move forward the full length of the label.
                pos += len as usize;
            }
        }

        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }
}

use nom::{be_u8,be_u16,be_u32,rest};

use {ParseOps,ConvError};
use packet_writer::{PacketWriter,WriteFields};

named!(bytes_to_ip<&[u8], IPHdr>, do_parse!(
    version_and_length: be_u8 >>
    qos: be_u8 >>
    pk_length: be_u16 >>
    ident: be_u16 >>
    flags_and_offset: be_u16 >>
    ttl: be_u8 >>
    proto: be_u8 >>
    checksum: be_u16 >>
    source_ip: be_u32 >>
    dest_ip: be_u32 >>
    options: rest >>
    (IPHdr { version: (version_and_length & 0xf0) >> 4, hdr_length: (version_and_length & 0x0f),
             qos, pk_length, ident, do_not_fragment: (1 << 14) & flags_and_offset == (1 << 14),
             more_packets: (1 << 13) & flags_and_offset == (1 << 13),
             packet_offset: flags_and_offset & 0x1fff, ttl, proto, checksum, source_ip,
             dest_ip, options: options.to_vec() })
));
named!(strip_ip<&[u8]>, do_parse!(
    version_and_length: be_u8 >>
    take!(((version_and_length & 0x0f) * 4) - 1) >>
    inner_bytes: rest >>
    (inner_bytes)
));

struct IPHdr {
    version: u8,
    hdr_length: u8,
    qos: u8,
    pk_length: u16,
    ident: u16,
    do_not_fragment: bool,
    more_packets: bool,
    packet_offset: u16,
    ttl: u8,
    proto: u8,
    checksum: u16,
    source_ip: u32,
    dest_ip: u32,
    options: Vec<u8>,
}

impl<'a> ParseOps<'a> for IPHdr {
    fn to_bytes(self) -> Result<Vec<u8>, ConvError> {
        let mut pw = PacketWriter::new();
        pw.write_u8(((self.version & 0x0f) << 4) | (self.hdr_length & 0x0f))?;
        pw.write_u8(self.qos)?;
        pw.write_u16(self.pk_length)?;
        pw.write_u16(self.ident)?;
        let do_not_fragment_bin = if self.do_not_fragment { 1 } else { 0 };
        let more_packets_bin = if self.more_packets { 1 } else { 0 };
        pw.write_u16(((0xfffe & do_not_fragment_bin) << 14) | ((0xfffe & more_packets_bin) << 13)
                     | (0x1fff & self.packet_offset))?;
        pw.write_u8(self.ttl)?;
        pw.write_u8(self.proto)?;
        pw.write_u16(self.checksum)?;
        pw.write_u32(self.source_ip)?;
        pw.write_u32(self.dest_ip)?;
        pw.write_bytes(self.options.as_slice())?;
        Ok(pw.get_result())
    }

    fn from_bytes(buf: &[u8]) -> Result<Self, ConvError> {
        match bytes_to_ip(buf) {
            Ok((_, ip)) => Ok(ip),
            Err(e) => {
                Err(ConvError(
                    format!("Failed to parse - here is the remaining output: {:?}", e)
                ))
            },
        }
    }

    fn strip_header(buf: &[u8]) -> Result<&[u8], ConvError> {
        match strip_ip(buf) {
            Ok((_, stripped)) => Ok(stripped),
            Err(e) => {
                Err(ConvError(
                    format!("Failed to parse - here is the remaining output: {:?}", e)
                ))
            },
        }
    }
}

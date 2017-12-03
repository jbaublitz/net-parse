use nom::{rest,be_u16};

use {ParseOps,ConvError};
use packet_writer::{PacketWriter,WriteFields};

named!(bytes_to_ethernet<&[u8], EthHdr>, do_parse!(
    src: take!(6) >>
    dest: take!(6) >>
    eth_type: be_u16 >>
    (EthHdr { mac_src: src, mac_dest: dest, eth_type })
));
named!(strip_ethernet<&[u8]>, do_parse!(
    take!(14) >>
    rest: rest >>
    (rest)
));

pub struct EthHdr<'a> {
    mac_src: &'a [u8],
    mac_dest: &'a [u8],
    eth_type: u16,
}

impl<'a> ParseOps<'a> for EthHdr<'a> {
    fn to_bytes(self) -> Result<Vec<u8>, ConvError> {
        let mut pw = PacketWriter::new();
        try!(pw.write_bytes(self.mac_src));
        try!(pw.write_bytes(self.mac_dest));
        try!(<PacketWriter as WriteFields<Vec<u8>>>::write_u16::<u16>(&mut pw, self.eth_type));
        Ok(pw.get_result())
    }

    fn from_bytes(buf: &'a [u8]) -> Result<Self, ConvError> {
        Ok(try!(bytes_to_ethernet(buf).to_result()))
    }

    fn strip_header(buf: &[u8]) -> Result<&[u8], ConvError> {
        Ok(try!(strip_ethernet(buf).to_result()))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_strip_header() {
        let s = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17];
        assert_eq!(EthHdr::strip_header(s).unwrap(), &[15, 16, 17])
    }
}

use nom::{rest,be_u16};

use {ParseOps,ConvError};
use packet_writer::{PacketWriter,WriteFields};

named!(bytes_to_ethernet<&[u8], EthHdr>, do_parse!(
    src: take!(6) >>
    dest: take!(6) >>
    eth_type: be_u16 >>
    (EthHdr { mac_src: src, mac_dest: dest, eth_type: EthType::from(eth_type) })
));
named!(strip_ethernet<&[u8]>, do_parse!(
    take!(14) >>
    inner_bytes: rest >>
    (inner_bytes)
));

c_enum!(EthType, u16, {
    IPv4 => 0x0800
});

#[derive(Debug,PartialEq)]
pub struct EthHdr<'a> {
    mac_src: &'a [u8],
    mac_dest: &'a [u8],
    eth_type: EthType,
}

impl<'a> ParseOps<'a> for EthHdr<'a> {
    fn to_bytes(self) -> Result<Vec<u8>, ConvError> {
        let mut pw = PacketWriter::new();
        pw.write_bytes(self.mac_src)?;
        pw.write_bytes(self.mac_dest)?;
        <PacketWriter as WriteFields<Vec<u8>>>::write_u16::<u16>(
            &mut pw, self.eth_type as u16
        )?;
        Ok(pw.get_result())
    }

    fn from_bytes(buf: &'a [u8]) -> Result<Self, ConvError> {
        match bytes_to_ethernet(buf) {
            Ok((_, ip)) => Ok(ip),
            Err(e) => {
                Err(ConvError(
                    format!("Failed to parse - here is the remaining output: {:?}", e)
                ))
            },
        }
    }

    fn strip_header(buf: &[u8]) -> Result<&[u8], ConvError> {
        match strip_ethernet(buf) {
            Ok((_, eth)) => Ok(eth),
            Err(e) => {
                Err(ConvError(
                    format!("Failed to parse - here is the remaining output: {:?}", e)
                ))
            },
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_write_header() {
        assert_eq!(EthHdr { mac_src: &[1, 2, 3, 4, 5, 6],
                            mac_dest: &[7, 8, 9, 10, 11, 12],
                            eth_type: EthType::IPv4,
        }.to_bytes().unwrap(), &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0x08, 0x00])
    }

    #[test]
    fn test_parse_header() {
        let s = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0x08, 0x00, 15, 16, 17];
        assert_eq!(EthHdr { mac_src: &[1, 2, 3, 4, 5, 6],
                            mac_dest: &[7, 8, 9, 10, 11, 12],
                            eth_type: EthType::IPv4 },
                   EthHdr::from_bytes(s).unwrap())
    }

    #[test]
    fn test_strip_header() {
        let s = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17];
        assert_eq!(EthHdr::strip_header(s).unwrap(), &[15, 16, 17])
    }
}

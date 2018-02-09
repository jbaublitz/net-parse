use std::io::{self,Cursor,Write};

use byteorder::{BigEndian,WriteBytesExt};

use ConvError;

pub trait WriteFields<T>: WriteBytesExt {
    fn write_u8<I>(&mut self, v: I) -> Result<(), ConvError> where I: Into<u8> {
        Ok(WriteBytesExt::write_u8(self, v.into())?)
    }

    fn write_u16<I>(&mut self, v: I) -> Result<(), ConvError> where I: Into<u16> {
        Ok(WriteBytesExt::write_u16::<BigEndian>(self, v.into())?)
    }

    fn write_u32<I>(&mut self, v: I) -> Result<(), ConvError> where I: Into<u32> {
        Ok(WriteBytesExt::write_u32::<BigEndian>(self, v.into())?)
    }

    fn write_bytes<'a, I>(&mut self, v: I) -> Result<(), ConvError> where I: Into<&'a [u8]> {
        let _ = self.write(v.into())?;
        Ok(())
    }

    fn get_result(self) -> T;
}

pub struct PacketWriter(Cursor<Vec<u8>>);

impl PacketWriter {
    pub fn new() -> Self {
        PacketWriter(Cursor::new(Vec::new()))
    }
}

impl Write for PacketWriter {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        self.0.write(buf)
    }
    
    fn flush(&mut self) -> Result<(), io::Error> {
        Ok(())
    }
}

impl WriteFields<Vec<u8>> for PacketWriter {
    fn get_result(self) -> Vec<u8> {
        self.0.into_inner()
    }
}

#[macro_use]
extern crate nom;
extern crate byteorder;

use std::error::Error;
use std::fmt::{self,Display};
use std::io;


mod packet_writer;
pub mod l2;
pub mod l3;
pub mod l4;

macro_rules! from_error {
    ( $name:ident, $( $from_name:path ),* ) => (
        $(
            impl From<$from_name> for $name {
                fn from(v: $from_name) -> Self {
                    ConvError(v.description().to_string())
                }
            }
        )*
    );
}

#[derive(Debug)]
pub struct ConvError(String);

from_error!(ConvError, nom::ErrorKind, io::Error);

impl Display for ConvError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for ConvError {
    fn description(&self) -> &str {
        self.0.as_str()
    }
}

pub trait ParseOps<'a>: Sized {
    fn to_bytes(self) -> Result<Vec<u8>, ConvError>;
    fn from_bytes(&'a [u8]) -> Result<Self, ConvError>;
    fn strip_header(&[u8]) -> Result<&[u8], ConvError>;
}

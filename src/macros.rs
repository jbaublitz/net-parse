macro_rules! c_enum {
    ( $name:ident, $from_ty:ty, { $( $var:ident => $val:tt ),* } ) => {
        #[derive(Debug,PartialEq)]
        pub enum $name {
            $(
                $var = $val,
            )*
        }

        impl From<$from_ty> for $name {
            fn from(v: $from_ty) -> Self {
                match v {
                    $(
                        i if i == $val => $name::$var,
                    )*
                    _ => panic!("Invalid binary value for enum type, {}: {}",
                                stringify!($name), v),
                }
            }
        }
    }
}

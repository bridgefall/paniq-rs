pub const PROTOCOL_VERSION: u8 = 0x01;

pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

pub const ADDR_TYPE_IPV4: u8 = 0x01;
pub const ADDR_TYPE_DOMAIN: u8 = 0x03;
pub const ADDR_TYPE_IPV6: u8 = 0x04;

pub const REPLY_SUCCESS: u8 = 0x00;
pub const REPLY_GENERAL_FAILURE: u8 = 0x01;

pub const DOMAIN_LEN_SIZE: usize = 1;
pub const IPV4_ADDR_SIZE: usize = 4;
pub const IPV6_ADDR_SIZE: usize = 16;
pub const PORT_SIZE: usize = 2;

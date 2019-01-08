
use std::rc::{Rc};
use std::cell::{RefCell};

use flow::{Packet, PacketData};
use tools::{read_u8_from_slice, read_u16_from_networkendian_slice, read_u32_from_networkendian_slice};
use ::tcp_stream::{TCP_SSN_NONE};
use ::eth::{Eth};

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

pub struct Ipv4{
    pub eth: Rc<RefCell<Eth>>,
    pub buf: Rc<Vec<u8>>,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub protocol: u8,
}

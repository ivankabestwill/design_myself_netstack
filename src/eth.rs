
use std::fmt::{Display,Formatter, Result};
use std::rc::{Rc};

use ::data::{Data};
use ::flow::{FlowHash};
use ::packet::{Packet, PacketData, PACKET_FLAGS_NONE, new_packet, LayerDataLink, LayerNetwork};
use ::tools::{read_u8_from_slice, read_u32_from_networkendian_slice};
use ::ipv4::{Ipv4};

pub struct Eth{
    pub data_offset: usize,
    pub dst_mac: Vec<u8>,
    pub src_mac: Vec<u8>,
}

impl Display for Eth{
    fn fmt(&self, f: &mut Formatter) -> Result{
        write!(f, "Eth dst_mac [{:?}] src_mac [{:?}]", self.dst_mac, self.src_mac)
    }
}
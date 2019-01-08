
use std::rc::{Rc};

use ::packet::{Packet, PacketData, LayerDataLink, LayerNetwork};
use ::tools::{read_u8_from_slice, read_u16_from_networkendian_slice, read_u32_from_networkendian_slice};
use ::tcp_stream::{TCP_SSN_NONE};
use ::eth::{Eth};

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

pub struct Ipv4{
    pub data_offset: usize,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub protocol: u8,
}

fn new_ipv4() -> Ipv4{
    Ipv4{
        data_offset: 0,
        src_ip: 0,
        dst_ip: 0,
        protocol: 0,
    }
}


impl Packet {

    pub fn decode_to_ipv4(&mut self) -> bool{

        let mut protocol: u8 = 0;
        let mut src_ip: u32 = 0;
        let mut dst_ip: u32 = 0;

        if let Some(ref data) = self.data.data{

                    read_u8_from_slice(&data.buf[9..10], &mut protocol);
                    read_u32_from_networkendian_slice(&data.buf[12..16], &mut src_ip);
                    read_u32_from_networkendian_slice(&data.buf[16..20], &mut dst_ip);

                    let ipv4 = new_ipv4();

                    {
                        self.data.layer_network = Some(LayerNetwork::data_ipv4(Rc::new(ipv4)));
                    }

                    if let Some(ref flowhash) = self.flow_hash {
                        flowhash.borrow_mut().src_ip = src_ip;
                        flowhash.borrow_mut().dst_ip = dst_ip;
                        flowhash.borrow_mut().protocol = protocol;
                    } else {
                        error!("decode_to_ipv4, flow_hash of Packet is None, error.");
                        return false;
                    }

                    return true;

        }

        return false;
    }
}
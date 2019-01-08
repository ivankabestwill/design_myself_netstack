

use std::rc::{Rc};
use std::cell::{RefCell};

use ::data::{Data};
use flow::{Packet, PacketData, PACKET_FLAGS_NONE, new_packet, FlowHash};
use ::tools::{read_u8_from_slice, read_u32_from_networkendian_slice};
use ::ipv4::{Ipv4};

pub struct Eth{
    pub data: Rc<RefCell<Data>>,
    pub buf: Rc<Vec<u8>>,
    pub dst_mac: Vec<u8>,
    pub src_mac: Vec<u8>,
}

impl Packet {

    pub fn decode_to_ipv4(&mut self, eth: Rc<RefCell<Eth>>) -> bool{

            let buf = Rc::clone(&eth.borrow().buf);
            let buf = &buf[20..];
            let buf: Vec<u8> = buf.to_vec();
            let buf = Rc::new(buf);

            let mut protocol: u8 = 0;
            let mut src_ip: u32 = 0;
            let mut dst_ip: u32 = 0;


            read_u8_from_slice(&eth.borrow().buf[9..10], &mut protocol);
            read_u32_from_networkendian_slice(&eth.borrow().buf[12..16], &mut src_ip);
            read_u32_from_networkendian_slice(&eth.borrow().buf[16..20], &mut dst_ip);

            let ipv4 = Ipv4 {
                protocol: protocol,
                src_ip: src_ip,
                dst_ip: dst_ip,
                eth: Rc::clone(&eth),
                buf: buf,
            };

            self.data = Some(PacketData::PacketIpv4(Rc::new(RefCell::new(ipv4))));
            self.flow_hash.src_ip = src_ip;
            self.flow_hash.dst_ip = dst_ip;
            self.flow_hash.protocol = protocol;

            return true;

    }
}
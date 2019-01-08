
use std::fmt::{Display,Formatter, Result};
use std::rc::{Rc};

use ::packet::{Packet, PacketData, LayerDataLink, LayerNetwork, LayerTransport};
use ::tools::{read_u8_from_slice, read_u16_from_networkendian_slice, read_u32_from_networkendian_slice, print_addr};
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

impl Display for Ipv4{
    fn fmt(&self, f: &mut Formatter) -> Result{
        write!(f, "Ipv4 dst_ip [{}] src_ip [{}] protocol [{}]",
            print_addr(self.dst_ip), print_addr(self.src_ip), self.protocol)
    }
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

        let eth_data_offset = if let Some(ref ldl) = self.data.layer_data_link{
            match ldl{
                LayerDataLink::data_eth(ref eth) => {eth.data_offset},
                _ => {
                    error!("decode_to_ipv4, Packet.data.layer_data_link is not eth.");
                    return false;
                },
            }
        }else{
            error!("decode_to_ipv4, Packet.data.layer_data_link is None.");
            return false;
        };

        if let Some(ref data) = self.data.data{

                    read_u8_from_slice(&data.buf[eth_data_offset+9..eth_data_offset+10], &mut protocol);
                    read_u32_from_networkendian_slice(&data.buf[eth_data_offset+12..eth_data_offset+16], &mut src_ip);
                    read_u32_from_networkendian_slice(&data.buf[eth_data_offset+16..eth_data_offset+20], &mut dst_ip);

                    let mut ipv4 = new_ipv4();
                    ipv4.data_offset = eth_data_offset + 20;
                    ipv4.src_ip = src_ip;
                    ipv4.dst_ip = dst_ip;
                    ipv4.protocol = protocol;
                    debug!("{}", ipv4);

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


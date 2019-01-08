

use std::sync::{Arc,RwLock};
use std::cell::{RefCell};
use std::rc::Rc;
use std::fmt::{Display,Formatter, Result};

use ::data::{Data};
use ::eth::{Eth};
use ::ipv4::{Ipv4};
use ::tcp::{Tcp};
use ::flow::{Flow, FlowHash, new_flow_hash};
use ::thread::{ThreadVar};


pub enum LayerDataLink{
    data_eth(Rc<Eth>),
}

pub enum LayerNetwork{
    data_ipv4(Rc<Ipv4>),
}

pub enum LayerTransport{
    data_tcp(Rc<Tcp>),
    data_udp,
}

pub struct PacketData{
    pub data: Option<Rc<Data>>,
    pub layer_data_link: Option<LayerDataLink>,
    pub layer_network: Option<LayerNetwork>,
    pub layer_transport: Option<LayerTransport>,
}

pub type PACKET_FLAGS_TYPE = u64;
pub const PACKET_FLAGS_NONE: PACKET_FLAGS_TYPE = 0;
pub const PACKET_FLAGS_TOSERVER: PACKET_FLAGS_TYPE = 1<<0;
pub const PACKET_FLAGS_TOCLIENT: PACKET_FLAGS_TYPE = 1<<1;
pub const PACKET_FLAGS_TOSERVER_FIRST: PACKET_FLAGS_TYPE = 1<<2;
pub const PACKET_FLAGS_TOCLIENT_FIRST: PACKET_FLAGS_TYPE = 1<<3;
pub const PACKET_FLAGS_PSEUDO_STREAM_END: PACKET_FLAGS_TYPE = 1<<4;
pub const PACKET_FLAGS_DETECTLOG_FLUSH: PACKET_FLAGS_TYPE = 1<<5;
pub const PACKET_FLAGS_WANTS_FLOW: PACKET_FLAGS_TYPE = 1<<6;
pub const PACKET_FLAGS_HAS_FLOW: PACKET_FLAGS_TYPE = 1<<7;
pub const PACKET_FLAGS_TO_DST_SEEN: PACKET_FLAGS_TYPE = 1<<8;
pub const PACKET_FLAGS_TO_SRC_SEEN: PACKET_FLAGS_TYPE = 1<<9;
pub const PACKET_FLAGS_DETECT_IS_DONE : PACKET_FLAGS_TYPE = 1<<10;
pub const PACKET_FLAGS_ESTABLISHED: PACKET_FLAGS_TYPE = 1<<11;
pub const PACKET_FLAGS_NOPACKET_INSPECTION: PACKET_FLAGS_TYPE = 1<<12;
pub const PACKET_FLAGS_NOPAYLOAD_INSPECTION: PACKET_FLAGS_TYPE = 1<<13;
pub const PACKET_FLAGS_IGNORE_CHECKSUM: PACKET_FLAGS_TYPE= 1<<14;

pub struct Packet{
    pub flags: PACKET_FLAGS_TYPE,
    pub data: PacketData,
    pub flow: Option<Arc<RwLock<Flow>>>,
    pub flow_hash: Option<Rc<RefCell<FlowHash>>>,
    pub ts: usize,
    pub pkt_len: usize,
}

impl Display for Packet{
    fn fmt(&self, f: &mut Formatter) -> Result{

        let fh = if let Some(ref flow_hash) = self.flow_hash{
            format!("src_ip {} src_port {} dst_ip {} dst_port {} protocol {}", flow_hash.borrow().src_ip,
            flow_hash.borrow().src_port,
            flow_hash.borrow().dst_ip,
            flow_hash.borrow().dst_port,
            flow_hash.borrow().protocol)
        }else{
            format!("none")
        };

        write!(f, "Packet flowhash[{}] ", fh)
    }
}


#[macro_export]
macro_rules! PKT_IS_TOSERVER{
    ($pkt: expr) => {
        if check_flag!($pkt.flags,PACKET_FLAGS_TOSERVER){
            true
        }else{
            false
        }
    }
}

#[macro_export]
macro_rules! PKT_IS_TOCLIENT{
    ($pkt: expr) => {
        if check_flag!($pkt.flags,PACKET_FLAGS_TOCLIENT){
            true
        }else{
            false
        }
    }
}


#[macro_export]
macro_rules! PKT_IS_ICMPV4{
    ($pkt: expr) => {
        if let Some(ref fh) = $pkt.flow_hash{
            if fh.borrow().protocol == IPPROTO_ICMP{
                true
            }else{
                false
            }
        }else{
            false
        }
    }
}

#[macro_export]
macro_rules! ICMPV4_IS_ERROR_MSG{
    ($pkt: expr) => {
        false
    }
}

pub fn new_packetdata_none() -> PacketData{
    PacketData{
        data: None,
        layer_transport: None,
        layer_network: None,
        layer_data_link: None,
    }
}

pub fn new_packetdata_data(data: Data) -> PacketData{
    PacketData{
        data: Some(Rc::new(data)),
        layer_transport: None,
        layer_network: None,
        layer_data_link: None,
    }
}

pub fn new_packet(thread: Rc<ThreadVar>) -> Packet{
    Packet{
        flags: PACKET_FLAGS_NONE,
        data: new_packetdata_none(),
        flow: None,
        flow_hash: None,
        ts: 0,
        pkt_len: 0,
    }
}


impl Packet{

    pub fn reset_to_none(&mut self){
        self.data = new_packetdata_none();
    }

    pub fn switch_dir(&mut self){

        if check_flag!(self.flags, PACKET_FLAGS_TOSERVER){

            del_flag!(self.flags, PACKET_FLAGS_TOSERVER);
            add_flag!(self.flags, PACKET_FLAGS_TOCLIENT);

            if check_flag!(self.flags, PACKET_FLAGS_TOSERVER_FIRST){

                del_flag!(self.flags, PACKET_FLAGS_TOSERVER_FIRST);
                add_flag!(self.flags, PACKET_FLAGS_TOCLIENT_FIRST);
            }

        }else{

            del_flag!(self.flags, PACKET_FLAGS_TOCLIENT);
            add_flag!(self.flags, PACKET_FLAGS_TOSERVER);

            if check_flag!(self.flags, PACKET_FLAGS_TOCLIENT_FIRST){

                del_flag!(self.flags, PACKET_FLAGS_TOCLIENT_FIRST);
                add_flag!(self.flags, PACKET_FLAGS_TOSERVER_FIRST);
            }
        }
    }
}


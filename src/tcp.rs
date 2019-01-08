

use std::borrow::BorrowMut;
use std::rc::Rc;
use std::cell::{RefCell};
use std::sync::{Arc,RwLock};
use flow::{Flow, FlowHash, Session, get_flow, insert_flow, FLOW_STATE_NEW};

use config::{tcp_assem_config, CONFIG_FLAGS_CHECKSUM_VALIDATION};
use tools::{get_u32_from_networkendian_slice, get_u16_from_networkendian_slice, read_u16_from_networkendian_slice, read_u8_from_slice, read_u32_from_networkendian_slice};
use thread::ThreadVar;
use ::flow::{};
use ::packet::{Packet, PacketData, LayerDataLink, LayerNetwork, LayerTransport, PACKET_FLAGS_WANTS_FLOW, PACKET_FLAGS_TOSERVER_FIRST, PACKET_FLAGS_TOCLIENT_FIRST,
PACKET_FLAGS_IGNORE_CHECKSUM, PACKET_FLAGS_PSEUDO_STREAM_END};
use ::tcp_stream::{TCP_SSN_STATE,TCP_SSN_NONE, tcp_session_hand};
use ::ipv4::{Ipv4, IPPROTO_TCP};

use self::Session::{tcp_session, udp_session};

pub type TCP_FLAGS_TYPE = u8;
pub const TCP_FLAGS_NONE: TCP_FLAGS_TYPE = 0;
pub const TCP_FLAGS_URG: TCP_FLAGS_TYPE = 1;
pub const TCP_FLAGS_ACK: TCP_FLAGS_TYPE = 2;
pub const TCP_FLAGS_PSH: TCP_FLAGS_TYPE = 4;
pub const TCP_FLAGS_RST: TCP_FLAGS_TYPE = 8;
pub const TCP_FLAGS_SYN: TCP_FLAGS_TYPE = 16;
pub const TCP_FLAGS_FIN: TCP_FLAGS_TYPE = 32;


pub struct TcpOption{
    pub ts: Option<Vec<u32>>,
    pub sackok: bool,
    pub sack: Option<Vec<u32>>,
    pub ws: Option<u8>,
    pub mss: Option<u16>,
}

pub const TCP_WSCALE_MAX: u8 = 14;

macro_rules! TCP_GET_TS{
    ($tcp: expr) => {
        if let Some(ref option) = $tcp.tcp_option{
            if let Some(ref ts) = option.ts{
                if ts.len() == 2{
                    ts[0].clone() as usize
                }else{
                    panic!("TCP_GET_TS");
                }
            }else{
                panic!("TCP_GET_TS");
            }
        }else{
            panic!("TCP_GET_TS");
        }
    }
}

macro_rules! TCP_GET_TSECR {
    ($tcp: expr) => {
        if let Some(ref option) = $tcp.tcp_option{
            if let Some(ref ts) = option.ts{
                if ts.len() == 2{
                    ts[1].clone() as usize
                }else{
                    panic!("TCP_GET_TSECR");
                }
            }else{
                panic!("TCP_GET_TSECR");
            }
        }else{
            panic!("TCP_GET_TSECR");
        }
    }
}

macro_rules! TCP_GET_SACKOK{
    ($tcp: expr) => {
        if let Some(ref option) = $tcp.tcp_option{
            option.sackok.clone()
        }else{
            panic!("TCP_GET_WSCALE");
        }
    }
}
macro_rules! TCP_GET_WSCALE{
    ($tcp: expr) => {
        if let Some(ref option) = $tcp.tcp_option{
            if let Some(ref wscale) = option.ws{
                wscale.clone()
            }else{
                panic!("TCP_GET_WSCALE");
            }
        }else{
            panic!("TCP_GET_WSCALE");
        }
    }
}
macro_rules! TCP_HAS_SACKOK{
    ($tcp:expr) => {
        if let Some(ref option) = $tcp.tcp_option{
            if option.sackok{
                true
            }else{
                false
            }
        }else{
            false
        }
    }
}
macro_rules! TCP_HAS_TS{
    ($tcp:expr) => {
        if let Some(ref option) = $tcp.tcp_option{
            if let Some(ref _ts) = option.ts{
                true
            }else{
                false
            }
        }else{
            false
        }
    }
}
macro_rules! TCP_HAS_MSS{
    ($tcp:expr) => {
        if let Some(ref option) = $tcp.tcp_option{
            if let Some(_mss) = option.mss{
                true
            }else{
                false
            }
        }else{
            false
        }
    }
}
macro_rules! TCP_HAS_SACK{
    ($tcp:expr) => {
        if let Some(ref option) = $tcp.tcp_option{
            if let Some(_sack) = option.sack{
                true
            }else{
                false
            }
        }else{
            false
        }
    }
}
macro_rules! TCP_HAS_WSCALE{
    ($tcp:expr) => {
        if let Some(ref option) = $tcp.tcp_option{
            if let Some(_) = option.ws{
                true
            }else{
                false
            }
        }else{
            false
        }
    }
}

pub struct Tcp{
    pub data_offset: usize,
    pub payload: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub win: u16,
    pub flags: TCP_FLAGS_TYPE,
    pub ssn_state: TCP_SSN_STATE,
    pub tcp_option: Option<TcpOption>,
}

pub fn flow_hand_tcp(packet: &mut Packet, flow: &Arc<RwLock<Flow>>) -> bool{

    let tcp = if let Some(ref lt)  = packet.data.layer_transport{
        if let LayerTransport::data_tcp(ref rc_tcp) = lt {
            Rc::clone(rc_tcp)
        }else{
            error!("flow_hand_tcp, but PacketData layer_transport is not data_tcp.");
            return false;
        }
    }else{
        error!("flow_hand_tcp, but PacketData layer_transport None.");
        return false;
    };

    if !(check_flag!(packet.flags, PACKET_FLAGS_PSEUDO_STREAM_END)) {
        if check_flag!(tcp_assem_config.flags, CONFIG_FLAGS_CHECKSUM_VALIDATION) {
            ;//StreamTcpValidateCheckSum check the tcp packet checksum, follow suricata .
        } else {
            add_flag!(packet.flags, PACKET_FLAGS_IGNORE_CHECKSUM);
        }
    } else {
        add_flag!(packet.flags, PACKET_FLAGS_IGNORE_CHECKSUM);
    }

    // ApplayerProfillingReset() for applayer, follow suricata.

    return tcp_session_hand(packet, tcp, &flow);
}

const TCP_OPTION_WS_LEN: u8 = 3;
const TCP_OPTION_MSS_LEN: u8 = 4;
const TCP_OPTION_SACKOK_LEN: u8 = 2;
const TCP_OPTION_TS_LEN: u8 = 10;
const TCP_OPTION_SACK_MIN_LEN: u8 = 10; // at least one pair seq index
const TCP_OPTION_SACK_MAX_LEN: u8 = 34; // max 4 pair seq index

const TCP_OPTION_EOL: u8 = 0;
const TCP_OPTION_NOP: u8 = 1;
const TCP_OPTION_MSS: u8 = 2;
const TCP_OPTION_WS: u8 = 3;
const TCP_OPTION_SACKOK: u8 = 4;
const TCP_OPTION_SACK: u8 = 5;
const TCP_OPTION_TS: u8 = 8;

fn decode_tcp_options(data: &[u8]) -> Option<TcpOption>{
    let mut options = &data[..];
    let mut plen = options.len();
    let mut tcp_opt_cnt = 0;
    let mut tcp_option = TcpOption{
        ts: None,
        sack: None,
        sackok: false,
        ws: None,
        mss: None,
    };

    loop{
        if plen <= 0{
            break;
        }
        if options[0] == TCP_OPTION_EOL{
            break;
        }else if options[0] == TCP_OPTION_NOP{
            options = &options[1..];
            plen -= 1;
        }else{
            if plen < 2{
                break;
            }

            if(options[1] > plen as u8) || (options[1] < 2){
                return None;
            }

            tcp_opt_cnt += 1;
            let tlv_len = options[1];

            match options[0]{
                TCP_OPTION_WS => {
                    if options[1] != TCP_OPTION_WS_LEN{
                        return None;
                    }else{
                        if let None = tcp_option.ws{
                            // duplicated tcp option
                            return None;
                        }else{
                            tcp_option.ws = Some(options[2]);
                        }
                    }
                },
                TCP_OPTION_MSS => {
                    if options[1] != TCP_OPTION_MSS_LEN{
                        return None;
                    }else{
                        if let None = tcp_option.mss{
                            // duplicated tcp option
                            return None;
                        }else {
                            tcp_option.mss = Some(get_u16_from_networkendian_slice(&options[2..4]));
                        }
                    }
                },
                TCP_OPTION_SACKOK => {
                    if options[1] != TCP_OPTION_SACKOK_LEN{
                        return None;
                    }else{
                        if tcp_option.sackok == true{
                            // duplicated tcp option
                            return None;
                        }else{
                            tcp_option.sackok = true;
                        }
                    }
                },
                TCP_OPTION_SACK => {
                    let tmp_len = (tlv_len -2) % 8;

                    if (tlv_len < TCP_OPTION_SACK_MIN_LEN) ||
                        (tlv_len > TCP_OPTION_SACK_MAX_LEN) ||
                        (tmp_len != 0) ||
                        tmp_len > 8{
                        return None;
                    }else{
                        if let None = tcp_option.sack {
                            return None;
                        }else {
                            let mut sack: Vec<u32> = Vec::new();

                            for i in 0..tmp_len {
                                let s: usize = 2 + 4 * i as usize;
                                let e: usize = 2 + 4 * i as usize + 4;
                                sack.push(get_u32_from_networkendian_slice(&options[s..e]));
                            }
                            tcp_option.sack = Some(sack);
                        }
                    }
                },
                TCP_OPTION_TS => {
                    if options[1] != TCP_OPTION_TS_LEN{
                        return None;
                    }else{
                        if let None = tcp_option.ts{
                            return None;
                        }else{
                            let mut ts: Vec<u32> = Vec::new();
                            ts.push(get_u32_from_networkendian_slice(&options[2..6]));
                            ts.push(get_u32_from_networkendian_slice(&options[6..10]));
                            tcp_option.ts = Some(ts);
                        }
                    }
                },
                _ => {},
            }

            plen -= tlv_len as usize;
            options = &options[tlv_len as usize..];
        }
    }

    return Some(tcp_option);
}

impl Packet {
    pub fn decode_to_tcp(&mut self) -> bool {


        let data = match self.data.data {
            Some(ref t) => { Rc::clone(t) },
            None => {
                error!("decode_to_tcp, but Packet.data.data is None.");
                return false;
            },
        };

        if let Some(ref op_ln) = self.data.layer_network{

            match op_ln{
                LayerNetwork::data_ipv4(ref ipv4) => {
                    let mut src_port: u16 = 0;
                    let mut dst_port: u16 = 0;
                    let mut flag: u8 = 0;
                    let mut flags: u8 = 0;
                    let mut seq: u32 = 0;
                    let mut ack: u32 = 0;
                    let mut hlen: u8 = 0;

                    let mut data_offset = ipv4.data_offset;
                    read_u16_from_networkendian_slice(&data.buf[data_offset..(data_offset + 2)], &mut src_port);
                    read_u16_from_networkendian_slice(&data.buf[(data_offset + 2)..(data_offset + 4)], &mut dst_port);
                    read_u8_from_slice(&data.buf[(data_offset + 13)..(data_offset + 14)], &mut flag);
                    read_u32_from_networkendian_slice(&data.buf[(data_offset + 4)..(data_offset + 8)], &mut seq);
                    read_u32_from_networkendian_slice(&data.buf[(data_offset + 8)..(data_offset + 12)], &mut ack);
                    read_u8_from_slice(&data.buf[(data_offset + 12)..(data_offset + 13)], &mut hlen);

                    if flag & 0x01 != 0 {
                        flags |= TCP_FLAGS_FIN;
                    }
                    if flag & 0x02 != 0 {
                        flags |= TCP_FLAGS_SYN;
                    }
                    if flag & 0x04 != 0 {
                        flags |= TCP_FLAGS_RST;
                    }
                    if flag & 0x08 != 0 {
                        flags |= TCP_FLAGS_PSH;
                    }
                    if flag & 0x10 != 0 {
                        flags |= TCP_FLAGS_ACK;
                    }
                    if flag & 0x20 != 0 {
                        flags |= TCP_FLAGS_URG;
                    }

                    hlen &= 0xf0;
                    hlen = hlen >> 4;
                    hlen = hlen * 4;

                    let tcp_option = if hlen > 20 {
                        decode_tcp_options(&data.buf[(data_offset + 20)..(data_offset + hlen as usize)])
                    } else {
                        None
                    };

                    let data_offset = data_offset + hlen as usize;
                    let payload = self.pkt_len - data_offset;
                    let tcp = Tcp {
                        src_port: src_port,
                        dst_port: dst_port,
                        flags: flags,
                        seq: seq,
                        ack: ack,
                        ssn_state: TCP_SSN_NONE,
                        tcp_option: tcp_option,
                        data_offset: data_offset,
                        payload: payload as u32,
                        win: 0,
                    };

                    {
                        //let test = packet_data.borrow_mut().layer_transport;

                        //= Some(LayerTransport::data_tcp(Box::new(tcp)));
                        //if let Some(ref flowhash) = self.flow_hash{
                        //   *(*(*flowhash).borrow_mut()).src_port = src_port;
                        //  *(*flowhash).borrow_mut().dst_port = dst_port;
                        // }
                    }

                    add_flag!(self.flags,PACKET_FLAGS_WANTS_FLOW);
                    return true;
                },
                _ => {
                    error!("decode_to_tcp, but Packet.data.LayerNetwork is not ipv4");
                    return false;
                },
        }
    }
            error!("decode_to_tcp fail.");
            return false;
    }
}
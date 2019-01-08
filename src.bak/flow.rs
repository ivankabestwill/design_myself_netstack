extern crate libc;

use std::fmt::{Display,Formatter, Result};

use libc::timeval;
use std::collections::{hash_map::DefaultHasher, HashMap};
use std::hash::{Hash, Hasher};
use std::cmp::{Eq, PartialEq};
use std::rc::{Rc};
use std::cell::{RefCell};
use std::thread::ThreadId;

use ::tcp_stream::{TcpSession, tcp_session_hand, tcp_stream_release_segment};
use ::thread::{ThreadVar, new_thread_var};
use ::tcp::{Tcp, flow_hand_tcp};
use ::eth::{Eth};
use ::ipv4::{Ipv4, IPPROTO_ICMP, IPPROTO_TCP};
use ::config::{tcp_assem_config};
use ::applayer::{ApplayerProto, new_applayer_proto};

#[derive(Eq,Clone)]
pub struct FlowHash{
    pub src_ip: u32,
    pub dst_ip : u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

impl PartialEq for FlowHash{
    fn eq(&self, other: &FlowHash) -> bool{
        if (((self.src_ip == other.src_ip &&
            self.dst_ip == other.dst_ip &&
            self.src_port == other.src_port &&
            self.dst_port == other.dst_port ) ||
            (self.src_ip == other.dst_ip &&
            self.dst_ip == other.src_ip &&
            self.src_port == other.dst_port &&
            self.dst_port == other.src_port)) &&
            self.protocol == other.protocol ){

            return true;
        }

        return false;
    }
}

impl Hash for FlowHash{
    fn hash<H: Hasher>(&self, state: &mut H){
        if self.src_ip <= self.dst_ip{
            self.src_ip.hash(state);
            self.dst_ip.hash(state);
        }else{
            self.dst_ip.hash(state);
            self.src_ip.hash(state);
        }

        self.protocol.hash(state);

        if self.src_port <= self.dst_port{
            self.src_port.hash(state);
            self.dst_port.hash(state);
        }else{
            self.dst_port.hash(state);
            self.src_port.hash(state);
        }
    }
}

pub enum ModuleCode{
    MC_OK,
    MC_FAIL,
    MC_DONE,
}

use self::ModuleCode::{MC_OK, MC_FAIL, MC_DONE};

pub enum TransportInfo{
    TransportTcp(Rc<RefCell<TcpSession>>),
    TransportUdp,
    TransportNone,
}
use self::TransportInfo::{TransportTcp, TransportUdp, TransportNone};

pub type FLOW_STATE = u8;

pub const FLOW_STATE_NEW:FLOW_STATE = 1;
pub const FLOW_STATE_ESTABLISHED:FLOW_STATE = 2;
pub const FLOW_STATE_CLOSED:FLOW_STATE = 3;
pub const FLOW_STATE_LOCAL_BYPASSED:FLOW_STATE = 4;
pub const FLOW_STATE_CAPTURE_BYPASSED:FLOW_STATE = 5;

pub struct FlowStatistic{
    toDestPktCnt: usize,
    toDestByteCnt: usize,
    toSrcPktCnt: usize,
    toSrcByteCnt: usize,
}

pub type FLOW_FLAGS_TYPE = u64;
pub const FLOW_FLAGS_NONE: FLOW_FLAGS_TYPE = 0;
pub const FLOW_FLAGS_DETECT_IS_DONE: FLOW_FLAGS_TYPE = 1<<0;
pub const FLOW_FLAGS_TO_DST_SEEN: FLOW_FLAGS_TYPE = 1<<1;
pub const FLOW_FLAGS_TO_SRC_SEEN: FLOW_FLAGS_TYPE = 1<<2;
pub const FLOW_FLAGS_NOPACKET_INSPECTION: FLOW_FLAGS_TYPE = 1<<3;
pub const FLOW_FLAGS_NOPAYLOAD_INSPECTION: FLOW_FLAGS_TYPE = 1<<4;
pub const FLOW_FLAGS_CHANGE_PROTOCOL: FLOW_FLAGS_TYPE = 1<<5;


pub struct Flow{
    pub src_ip: u32,
    pub dst_ip : u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub thread_id: ThreadId,
    pub state: FLOW_STATE,
    pub transport_info: TransportInfo,
    pub lastts: usize,
    pub next_ts: usize,
    pub statistic: FlowStatistic,
    pub flags: FLOW_FLAGS_TYPE,
    pub id: ThreadId,
    pub alproto: ApplayerProto,
    pub alproto_ts: ApplayerProto,
    pub alproto_tc: ApplayerProto,
    pub alproto_orig: ApplayerProto,
    pub alproto_expect: ApplayerProto,
}


impl Display for Flow{
    fn fmt(&self, f: &mut Formatter) -> Result{
        write!(f, "Flow [{} {} <-> {} {} : {}]",
               self.src_ip,
               self.src_port,
               self.dst_ip,
               self.dst_port,
               self.protocol)
    }
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


pub enum PacketData{
    PacketEth(Rc<RefCell<Eth>>),
    PacketIpv4(Rc<RefCell<Ipv4>>),
    PacketTcp(Rc<RefCell<Tcp>>),
    PacketUdp,
    PacketNone,
}

pub struct Packet{
    pub flags: PACKET_FLAGS_TYPE,
    pub data: Option<PacketData>,
    pub flow: Option<Rc<RefCell<Flow>>>,
    pub threadvar: Rc<RefCell<ThreadVar>>,
    pub flow_hash: FlowHash,
    pub ts: usize,
    pub pkt_len: usize,
}

impl Display for Packet{
    fn fmt(&self, f: &mut Formatter) -> Result{
        write!(f, "Packet [{} {} {} {} {}]",
               self.flow_hash.src_ip,
                self.flow_hash.src_port,
            self.flow_hash.dst_ip,
            self.flow_hash.dst_port,
            self.flow_hash.protocol)
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
        if $pkt.flow_hash.protocol == IPPROTO_ICMP{
            true
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

const FLOW_BYPASSED_TIMEOUT : usize = 6;

use self::PacketData::{PacketIpv4, PacketTcp, PacketNone, PacketUdp};

impl Packet{

    pub fn reset_to_none(&mut self){
        self.data = None;
    }

}
pub fn packet_switch_dir(packet: &mut Packet){

    if check_flag!(packet.flags, PACKET_FLAGS_TOSERVER){

        del_flag!(packet.flags, PACKET_FLAGS_TOSERVER);
        add_flag!(packet.flags, PACKET_FLAGS_TOCLIENT);

        if check_flag!(packet.flags, PACKET_FLAGS_TOSERVER_FIRST){

            del_flag!(packet.flags, PACKET_FLAGS_TOSERVER_FIRST);
            add_flag!(packet.flags, PACKET_FLAGS_TOCLIENT_FIRST);
        }

    }else{

        del_flag!(packet.flags, PACKET_FLAGS_TOCLIENT);
        add_flag!(packet.flags, PACKET_FLAGS_TOSERVER);

        if check_flag!(packet.flags, PACKET_FLAGS_TOCLIENT_FIRST){

            del_flag!(packet.flags, PACKET_FLAGS_TOCLIENT_FIRST);
            add_flag!(packet.flags, PACKET_FLAGS_TOSERVER_FIRST);
        }
    }
}

pub fn find_flow(flowhash: &FlowHash, hashmap: &HashMap<FlowHash, Rc<RefCell<Flow>>>) -> Option<Rc<RefCell<Flow>>>{

    let option_rc_ref_flow = hashmap.get(flowhash);

    match option_rc_ref_flow{
        None => {return None;},
        Some(s) => {return Some(Rc::clone(s))},
    }
}

pub fn new_flow_statistic() -> FlowStatistic{
    FlowStatistic{
        toDestByteCnt: 0,
        toDestPktCnt: 0,
        toSrcByteCnt: 0,
        toSrcPktCnt: 0,
    }
}

fn build_flow(packet: &mut Packet, flow_hash: &FlowHash, id: &ThreadId) -> Option<Flow>{

    let flow = Flow{
      src_ip: flow_hash.src_ip,
        dst_ip: flow_hash.dst_ip,
        src_port: flow_hash.src_port,
        dst_port: flow_hash.dst_port,
        protocol: flow_hash.protocol,
        thread_id: id.clone(),
        state: FLOW_STATE_NEW,
        transport_info: TransportNone,
        flags: FLOW_FLAGS_NONE,
        lastts: 0,
        next_ts: 0,
        statistic: new_flow_statistic(),
        id: std::thread::current().id(),
        alproto: new_applayer_proto(),
        alproto_orig: new_applayer_proto(),
        alproto_tc: new_applayer_proto(),
        alproto_ts: new_applayer_proto(),
        alproto_expect: new_applayer_proto(),
    };

    add_flag!(packet.flags, PACKET_FLAGS_TOSERVER_FIRST);
    return Some(flow);
}

pub fn get_flow(packet: &mut Packet, flow_hash: FlowHash) -> Option<Rc<RefCell<Flow>>>{

    let rc_ref_threadvar = Rc::clone(&packet.threadvar);
    let threadvar = &(*rc_ref_threadvar.borrow_mut());

    match find_flow(&flow_hash, &threadvar.flowhash) {
        None => {
            match build_flow(packet, &flow_hash,  &threadvar.id) {
                Some(t) => {
                    let flow = Rc::new(RefCell::new(t));
                    insert_flow(flow_hash, Rc::clone(&flow), &mut (rc_ref_threadvar.borrow_mut().flowhash));
                    add_flag!(packet.flags, PACKET_FLAGS_HAS_FLOW);
                    return Some(Rc::clone(&flow));
                },
                None => {
                    return None;
                },
            }
        },
        Some(t) => {
            add_flag!(packet.flags, PACKET_FLAGS_HAS_FLOW);
            Some(t)
        },
    }
}

pub fn insert_flow(flowhash: FlowHash, flow: Rc<RefCell<Flow>>, hashmap: &mut HashMap<FlowHash, Rc<RefCell<Flow>>>){
    hashmap.insert(flowhash, flow);
}


pub fn new_packet() -> Packet{
    Packet{
        flags: PACKET_FLAGS_NONE,
        data: None,
        flow: None,
        threadvar: Rc::new(RefCell::new(new_thread_var())),
        flow_hash: FlowHash{
            src_ip: 0,
            dst_ip: 0,
            src_port: 0,
            dst_port: 0,
            protocol: 0,
        },
        ts: 0,
        pkt_len: 0,
    }
}

fn packet_direction_set(packet: &mut Packet, flow: &Flow){

    if packet.flow_hash.src_ip == flow.src_ip{
        add_flag!(packet.flags, PACKET_FLAGS_TOSERVER);
        del_flag!(packet.flags, PACKET_FLAGS_TOCLIENT);

        if flow.state == FLOW_STATE_NEW {
            add_flag!(packet.flags, PACKET_FLAGS_TOSERVER_FIRST);
        }
    }else{
        add_flag!(packet.flags, PACKET_FLAGS_TOCLIENT);
        del_flag!(packet.flags, PACKET_FLAGS_TOSERVER);

        if flow.state == FLOW_STATE_NEW {
            add_flag!(packet.flags, PACKET_FLAGS_TOCLIENT_FIRST);
        }
    }
}

pub fn flow_update_state(flow: &mut Flow, state: FLOW_STATE){
    flow.state = state;
    flow.next_ts = 0;
}


fn flow_update_seen_flag(packet: &Packet) -> bool{
    if PKT_IS_ICMPV4!(packet){
        if ICMPV4_IS_ERROR_MSG!(packet){
            return false;
        }
    }

    return true;
}

pub fn flow_update(packet: &mut Packet, flow: Rc<RefCell<Flow>>) -> ModuleCode{
    flow_hand_pkt_update(packet, &flow);

    match flow.borrow().state{
        FLOW_STATE_CAPTURE_BYPASSED | FLOW_STATE_LOCAL_BYPASSED => {return MC_DONE;},
        _ => {return MC_OK;},
    }
}
pub fn flow_hand_pkt_update(packet: &mut Packet, flow: &Rc<RefCell<Flow>>){

    if flow.borrow().state != FLOW_STATE_CAPTURE_BYPASSED{
        flow.borrow_mut().lastts = packet.ts;
    }else{
        if (packet.ts - flow.borrow().lastts) > (FLOW_BYPASSED_TIMEOUT/2) {
            flow.borrow_mut().lastts = packet.ts;
            flow_update_state(&mut(*flow.borrow_mut()), FLOW_STATE_LOCAL_BYPASSED);
        }
    }

    if check_flag!(packet.flags, PACKET_FLAGS_TOSERVER){
        flow.borrow_mut().statistic.toDestPktCnt += 1;
        flow.borrow_mut().statistic.toDestByteCnt += packet.pkt_len;

        if !check_flag!(flow.borrow().flags, FLOW_FLAGS_TO_DST_SEEN){
            if flow_update_seen_flag(packet){
                add_flag!(flow.borrow_mut().flags, FLOW_FLAGS_TO_DST_SEEN);
                add_flag!(packet.flags, PACKET_FLAGS_TOSERVER_FIRST);
            }
        }
        if check_flag!(flow.borrow().flags, FLOW_FLAGS_DETECT_IS_DONE){
            del_flag!(flow.borrow_mut().flags, FLOW_FLAGS_DETECT_IS_DONE);
            add_flag!(packet.flags, PACKET_FLAGS_DETECT_IS_DONE);
        }
    }else{
        flow.borrow_mut().statistic.toSrcPktCnt += 1;
        flow.borrow_mut().statistic.toSrcByteCnt += packet.pkt_len;

        if !check_flag!(flow.borrow().flags, FLOW_FLAGS_TO_SRC_SEEN){
            if flow_update_seen_flag(packet){
                add_flag!(flow.borrow_mut().flags, FLOW_FLAGS_TO_SRC_SEEN);
                add_flag!(packet.flags, PACKET_FLAGS_TO_SRC_SEEN);
            }
        }

        if check_flag!(flow.borrow().flags, (FLOW_FLAGS_TO_SRC_SEEN|FLOW_FLAGS_TO_DST_SEEN)){
            info!("pkt {} PACKET_FLAGS_ESTABLISHED", packet);
            add_flag!(packet.flags, PACKET_FLAGS_ESTABLISHED);

            if flow.borrow().protocol == IPPROTO_TCP{
                flow_update_state(&mut (*flow.borrow_mut()), FLOW_STATE_ESTABLISHED);
            }
        }

        if check_flag!(flow.borrow().flags, FLOW_FLAGS_NOPACKET_INSPECTION){
            debug!("set FLOW_FLAGS_NOPACKET_INSPECTION on flow {}", flow.borrow());
            add_flag!(packet.flags, PACKET_FLAGS_NOPACKET_INSPECTION);
        }

        if check_flag!(flow.borrow().flags, FLOW_FLAGS_NOPAYLOAD_INSPECTION){
            debug!("set FLOW_FLAGS_NOPAYLOAD_INSPECTION on flow {}", flow.borrow());
            add_flag!(packet.flags, PACKET_FLAGS_NOPAYLOAD_INSPECTION);
        }
    }

    return;
}

pub fn flow_change_protocol(flow: &Flow) -> bool{
    if check_flag!(flow.flags, FLOW_FLAGS_CHANGE_PROTOCOL){
        true
    }else{
        false
    }
}

pub fn flow_hand(packet: &mut Packet){

    if check_flag!(packet.flags, PACKET_FLAGS_PSEUDO_STREAM_END|PACKET_FLAGS_DETECTLOG_FLUSH){
            ;//TimeSetByThread
    }

    let flow_hash = packet.flow_hash.clone();

    let flow = if check_flag!(packet.flags, PACKET_FLAGS_WANTS_FLOW) {

        let flow = match get_flow(packet, flow_hash) {
            None => {
                warn!("flow_hand: get_flow for new packet failed.");
                return;
            }
            Some(t) => { t },
        };

        packet_direction_set(packet, &(*flow.borrow()));

        if let MC_DONE = flow_update(packet, Rc::clone(&flow)){
            return;
        }

        flow
    }else if check_flag!(packet.flags, PACKET_FLAGS_HAS_FLOW){
        match packet.flow{
            Some(ref f) => {Rc::clone(f)},
            None => {error!("flow_hand packet with HAS_FLOW but packet.flow is None, error.");return;},
        }
    }else{
        error!("flow_hand packet neigh WANTS_FLOW nor HAS_FLOW, error.");
        return;
    };

    debug!("flow_hand: {} {} ", packet, flow.borrow());

    if packet.threadvar.borrow().id != flow.borrow().id {
        error!("flow thread id != local process thread id.");
    }

    // ndpi

    match packet.flow_hash.protocol {
        IPPROTO_TCP => {
            debug!("{} is tcp, dir {}", packet, if check_flag!(packet.flags, PACKET_FLAGS_TOSERVER) {"to server"}else{"to client"});

            if !(tcp_assem_config.detect_enable) &&
                ((PKT_IS_TOSERVER!(packet) && check_flag!(packet.flags, PACKET_FLAGS_TOSERVER_FIRST)) ||
                    (PKT_IS_TOCLIENT!(packet) && check_flag!(packet.flags, PACKET_FLAGS_TOCLIENT_FIRST))) {
                    ;//DisableDetectFlowFileFlags()    follow suricata, is detect is disable, flow file track reset.
            }

            flow_hand_tcp(packet, Rc::clone(&flow));

            if flow_change_protocol(&(*flow.borrow())){
                ;//StreamTcpDetectLogFlush()  follow suricata, here must flush the detect log, because we have known the protocol of the flow.
            }
        },
        _ => {return;},
        // flow_udp
    }

    // output
    // handl detect

    match packet.flow_hash.protocol {
        IPPROTO_TCP => {
            // release tcp stream seg
            tcp_stream_release_segment(packet);
        },
        _ => {},
    }
}


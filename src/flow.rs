extern crate libc;


//use std::borrow::{Borrow,BorrowMut};
use std::fmt::{Display,Formatter, Result};

use std::cell::{RefCell};
use libc::timeval;
use std::collections::{hash_map::DefaultHasher, HashMap};
use std::hash::{Hash, Hasher};
use std::cmp::{Eq, PartialEq};
use std::rc::{Rc};
use std::sync::{RwLock, Arc, RwLockWriteGuard};
use std::thread::{ThreadId};

use ::tools::{EXIT};
use ::tcp_stream::{TcpSession, tcp_session_hand, tcp_stream_release_segment};
use ::thread::{ThreadVar, new_thread_var, threadvar};
use ::tcp::{Tcp, flow_hand_tcp};
use ::eth::{Eth};
use ::ipv4::{Ipv4, IPPROTO_ICMP, IPPROTO_TCP};
use ::config::{tcp_assem_config};
use ::applayer::{ApplayerProto, new_applayer_proto};
use ::packet::{Packet, PACKET_FLAGS_TYPE, PACKET_FLAGS_TOSERVER_FIRST,
               PACKET_FLAGS_HAS_FLOW, PACKET_FLAGS_TOSERVER, PACKET_FLAGS_TOCLIENT,PACKET_FLAGS_ESTABLISHED,
               PACKET_FLAGS_TOCLIENT_FIRST, PACKET_FLAGS_DETECT_IS_DONE, PACKET_FLAGS_TO_SRC_SEEN,
               PACKET_FLAGS_NOPACKET_INSPECTION, PACKET_FLAGS_NOPAYLOAD_INSPECTION, PACKET_FLAGS_PSEUDO_STREAM_END,
               PACKET_FLAGS_DETECTLOG_FLUSH, PACKET_FLAGS_WANTS_FLOW};

thread_local! {
    static ALL_FLOW: RefCell<HashMap<FlowHash, Arc<RwLock<Flow>>>> = RefCell::new(HashMap::new());
}

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

pub enum Session{
    tcp_session(Rc<RefCell<TcpSession>>),
    udp_session,
}
use self::Session::{tcp_session, udp_session};

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
    pub session: Option<Session>,
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

#[macro_export]
macro_rules! flow_rwlock_error{
    () => {
        error!("Arc<RwLock<Flow>> RwLock write err.");
        EXIT();
    }
}



const FLOW_BYPASSED_TIMEOUT : usize = 6;


pub fn find_flow(flowhash: Rc<RefCell<FlowHash>>, hashmap: &HashMap<FlowHash, Arc<RwLock<Flow>>>) -> Option<Arc<RwLock<Flow>>>{

    let option_rc_ref_flow = hashmap.get(&(*flowhash.borrow()));

    match option_rc_ref_flow{
        None => {return None;},
        Some(s) => {return Some(Arc::clone(s))},
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

fn new_flowhash_from_flow(flow: &Arc<RwLock<Flow>>) -> Option<FlowHash> {
    match flow.read(){
        Ok(t) =>{
            Some(FlowHash{
                src_ip: t.src_ip,
                src_port: t.src_port,
                dst_ip: t.dst_ip,
                dst_port: t.dst_port,
                protocol: t.protocol,
            })
        },
        Err(_) => {flow_rwlock_error!(); return None;},
    }


}

fn new_flow_from_flowhash(flowhash: Rc<RefCell<FlowHash>>) -> Flow{
    Flow{
        src_ip: flowhash.borrow().src_ip,
        dst_ip: flowhash.borrow().dst_ip,
        src_port: flowhash.borrow().src_port,
        dst_port: flowhash.borrow().dst_port,
        protocol: flowhash.borrow().protocol,
        thread_id: threadvar.with(|f| { f.id.clone()}),
        state: FLOW_STATE_NEW,
        session: None,
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
    }
}

fn build_flow(packet_flags: &mut PACKET_FLAGS_TYPE, flow_hash: Rc<RefCell<FlowHash>>) -> Option<Flow>{

    let flow = new_flow_from_flowhash(flow_hash);

    add_flag!(*packet_flags, PACKET_FLAGS_TOSERVER_FIRST);

    return Some(flow);
}

pub fn get_flow(packet: &mut Packet, flow_hashmap: &mut HashMap<FlowHash, Arc<RwLock<Flow>>>, flow_hash: Rc<RefCell<FlowHash>>) -> Option<Arc<RwLock<Flow>>>{

    match find_flow(Rc::clone(&flow_hash), flow_hashmap) {
        None => {
            match build_flow(&mut packet.flags, Rc::clone(&flow_hash)) {
                Some(t) => {
                    let flow = Arc::new(RwLock::new(t));
                    let fh = flow_hash.borrow().clone();

                    insert_flow(fh, Arc::clone(&flow), flow_hashmap);
                    add_flag!(packet.flags, PACKET_FLAGS_HAS_FLOW);

                    return Some(flow);
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

pub fn insert_flow(flowhash: FlowHash, flow: Arc<RwLock<Flow>>, hashmap: &mut HashMap<FlowHash, Arc<RwLock<Flow>>>){
    hashmap.insert(flowhash, flow);
}

pub fn new_flow_hash() -> FlowHash{
    FlowHash{
        src_ip: 0,
        dst_ip: 0,
        src_port: 0,
        dst_port: 0,
        protocol: 0,
    }
}

fn packet_direction_set(packet: &mut Packet, flow: &Arc<RwLock<Flow>>){

    if let Some(ref flowhash) = packet.flow_hash{

        let r_flow = match flow.read(){
            Ok(t) => {t},
            Err(_) => {error!("Arc<RwLock<Flow>> read err."); EXIT(); return;},
        };

        if flowhash.borrow().src_ip == r_flow.src_ip {
            add_flag!(packet.flags, PACKET_FLAGS_TOSERVER);
            del_flag!(packet.flags, PACKET_FLAGS_TOCLIENT);

            if r_flow.state == FLOW_STATE_NEW {
                add_flag!(packet.flags, PACKET_FLAGS_TOSERVER_FIRST);
            }
        } else {
            add_flag!(packet.flags, PACKET_FLAGS_TOCLIENT);
            del_flag!(packet.flags, PACKET_FLAGS_TOSERVER);

            if r_flow.state == FLOW_STATE_NEW {
                add_flag!(packet.flags, PACKET_FLAGS_TOCLIENT_FIRST);
            }
        }
    }else{
        warn!("packet_direction_set, but Packet flow_hash is None.");
    }
}

pub fn flow_update_state(flow: & Arc<RwLock<Flow>>, state: FLOW_STATE){
    rw_lock_write!(flow, ()).state = state;
    rw_lock_write!(flow, ()).next_ts = 0;
}


fn flow_update_seen_flag(packet: &Packet) -> bool{
    if PKT_IS_ICMPV4!(packet){
        if ICMPV4_IS_ERROR_MSG!(packet){
            return false;
        }
    }

    return true;
}

pub fn flow_update(packet: &mut Packet, flow: &Arc<RwLock<Flow>>) -> ModuleCode{
    flow_hand_pkt_update(packet, flow);

    let r_flow = match flow.read(){
        Ok(t) => {t},
        Err(_) => { error!("Arc<RwLock<Flow>> RwLock read err."); EXIT(); return MC_DONE; },
    };

    match r_flow.state{
        FLOW_STATE_CAPTURE_BYPASSED | FLOW_STATE_LOCAL_BYPASSED => {return MC_DONE;},
        _ => {return MC_OK;},
    }
}

pub fn flow_hand_pkt_update(packet: &mut Packet, flow: &Arc<RwLock<Flow>>){

    if rw_lock_read!(flow, ()).state != FLOW_STATE_CAPTURE_BYPASSED{
        rw_lock_write!(flow, ()).lastts = packet.ts;
    }else{
        if (packet.ts - rw_lock_read!(flow, ()).lastts) > (FLOW_BYPASSED_TIMEOUT/2) {
            rw_lock_write!(flow, ()).lastts = packet.ts;
            flow_update_state(flow, FLOW_STATE_LOCAL_BYPASSED);
        }
    }

    if check_flag!(packet.flags, PACKET_FLAGS_TOSERVER){
        rw_lock_write!(flow,()).statistic.toDestPktCnt += 1;
        rw_lock_write!(flow,()).statistic.toDestByteCnt += packet.pkt_len;

        if !check_flag!(rw_lock_read!(flow,()).flags, FLOW_FLAGS_TO_DST_SEEN){
            if flow_update_seen_flag(packet){
                add_flag!(rw_lock_write!(flow,()).flags, FLOW_FLAGS_TO_DST_SEEN);
                add_flag!(packet.flags, PACKET_FLAGS_TOSERVER_FIRST);
            }
        }
        if check_flag!(rw_lock_read!(flow,()).flags, FLOW_FLAGS_DETECT_IS_DONE){
            del_flag!(rw_lock_write!(flow,()).flags, FLOW_FLAGS_DETECT_IS_DONE);
            add_flag!(packet.flags, PACKET_FLAGS_DETECT_IS_DONE);
        }
    }else{
        rw_lock_write!(flow,()).statistic.toSrcPktCnt += 1;
        rw_lock_write!(flow,()).statistic.toSrcByteCnt += packet.pkt_len;

        if !check_flag!(rw_lock_read!(flow,()).flags, FLOW_FLAGS_TO_SRC_SEEN){
            if flow_update_seen_flag(packet){
                add_flag!(rw_lock_write!(flow,()).flags, FLOW_FLAGS_TO_SRC_SEEN);
                add_flag!(packet.flags, PACKET_FLAGS_TO_SRC_SEEN);
            }
        }

        if check_flag!(rw_lock_read!(flow,()).flags, (FLOW_FLAGS_TO_SRC_SEEN|FLOW_FLAGS_TO_DST_SEEN)){
            info!("pkt {} PACKET_FLAGS_ESTABLISHED", packet);
            add_flag!(packet.flags, PACKET_FLAGS_ESTABLISHED);

            if rw_lock_read!(flow,()).protocol == IPPROTO_TCP{
                flow_update_state(flow, FLOW_STATE_ESTABLISHED);
            }
        }

        if check_flag!(rw_lock_read!(flow,()).flags, FLOW_FLAGS_NOPACKET_INSPECTION){
            debug!("set FLOW_FLAGS_NOPACKET_INSPECTION on flow {}", rw_lock_read!(flow,()));
            add_flag!(packet.flags, PACKET_FLAGS_NOPACKET_INSPECTION);
        }

        if check_flag!(rw_lock_read!(flow,()).flags, FLOW_FLAGS_NOPAYLOAD_INSPECTION){
            debug!("set FLOW_FLAGS_NOPAYLOAD_INSPECTION on flow {}", rw_lock_read!(flow,()));
            add_flag!(packet.flags, PACKET_FLAGS_NOPAYLOAD_INSPECTION);
        }
    }

    return;
}

pub fn flow_change_protocol(flow: &Arc<RwLock<Flow>>) -> bool{

    if check_flag!(rw_lock_read!(flow, false).flags, FLOW_FLAGS_CHANGE_PROTOCOL){
        true
    }else{
        false
    }

}

pub fn flow_hand(packet: &mut Packet){

    if check_flag!(packet.flags, PACKET_FLAGS_PSEUDO_STREAM_END|PACKET_FLAGS_DETECTLOG_FLUSH){
            ;//TimeSetByThread
    }

    let flow_hash: Rc<RefCell<FlowHash>> = if let Some(ref fh) = packet.flow_hash {
        Rc::clone(fh)
    }else{
        error!("flow_hand, flow_hash of Packet is None, error.");
        return;
    };

    let flow = if check_flag!(packet.flags, PACKET_FLAGS_WANTS_FLOW) {

        let flow = match ALL_FLOW.with(|f|{
            return get_flow(packet, &mut (*f.borrow_mut()), Rc::clone(&flow_hash));
        }){
            Some(t) => {t},
            None => {
                warn!("flow_hand: get_flow for new packet failed.");
                return;
            }
        };


        packet_direction_set(packet, &flow);

        if let MC_DONE = flow_update(packet, &flow){
            return;
        }

        flow
    }else if check_flag!(packet.flags, PACKET_FLAGS_HAS_FLOW){
        match packet.flow{
            Some(ref f) => {Arc::clone(f)},
            None => {error!("flow_hand packet with HAS_FLOW but packet.flow is None, error.");return;},
        }
    }else{
        error!("flow_hand packet neigh WANTS_FLOW nor HAS_FLOW, error.");
        return;
    };

    debug!("flow_hand: {}", packet);

    match flow.read(){
        Ok(t) => {
            if threadvar.with(|f|{ f.id != t.id}){
               warn!("flow_hand, flow thread id != local thread id.");
            }
        },
        Err(_) => {error!("Arc<RwLock<Flow>> RwLock read err."); EXIT(); return;},
    }

    // ndpi

    match flow_hash.borrow().protocol {
        IPPROTO_TCP => {
            debug!("{} is tcp, dir {}", packet, if check_flag!(packet.flags, PACKET_FLAGS_TOSERVER) {"to server"}else{"to client"});

            if !(tcp_assem_config.detect_enable) &&
                ((PKT_IS_TOSERVER!(packet) && check_flag!(packet.flags, PACKET_FLAGS_TOSERVER_FIRST)) ||
                    (PKT_IS_TOCLIENT!(packet) && check_flag!(packet.flags, PACKET_FLAGS_TOCLIENT_FIRST))) {
                    ;//DisableDetectFlowFileFlags()    follow suricata, is detect is disable, flow file track reset.
            }

            flow_hand_tcp(packet, &flow);

            if flow_change_protocol(&flow){
                ;//StreamTcpDetectLogFlush()  follow suricata, here must flush the detect log, because we have known the protocol of the flow.
            }
        },
        _ => {return;},
        // flow_udp
    };

    // output
    // handl detect

    match flow_hash.borrow().protocol {
        IPPROTO_TCP => {
            // release tcp stream seg
            tcp_stream_release_segment(packet);
        },
        _ => {},
    };
}


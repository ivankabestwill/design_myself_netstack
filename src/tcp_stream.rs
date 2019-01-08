

use std::collections::LinkedList;

use std::fmt::{Display, Result, Formatter};
use std::hash::{Hash};
use std::cell::{RefCell};
use std::rc::Rc;
use std::sync::{Arc, RwLock};


use ::config::{tcp_assem_config};
use ::tools::{EXIT};
use ::tcp::{Tcp, TCP_WSCALE_MAX, TCP_FLAGS_NONE, TCP_FLAGS_SYN, TCP_FLAGS_RST, TCP_FLAGS_URG,
            TCP_FLAGS_FIN, TCP_FLAGS_ACK, TCP_FLAGS_PSH, TCP_FLAGS_TYPE};
use ::data::{Data};
use ::thread::{ThreadVar};
use ::flow::{Flow, Session, FLOW_STATE_ESTABLISHED, FLOW_STATE_CLOSED};
use ::packet::{PacketData, new_packetdata_none};
use self::Session::{tcp_session, udp_session};
use ::packet::{Packet, PACKET_FLAGS_TOSERVER, PACKET_FLAGS_TOCLIENT, PACKET_FLAGS_TOCLIENT_FIRST,
             PACKET_FLAGS_TOSERVER_FIRST, PACKET_FLAGS_PSEUDO_STREAM_END};

use ::tcp_stream_state::{stream_state_syn_sent, stream_state_syn_recv, stream_state_established,
                         stream_state_fin_wait1, stream_state_fin_wait2, stream_state_closing,
                         stream_state_close_wait, stream_state_last_ack, stream_state_time_wait,
                         stream_state_closed, os_policy_type};

use ::applayer::{ stream_applayer_hand_tcp_data, APPLAYER_DATA,
                 get_applayer_flag_from_stream, APPLAYER_FLAGS_STREAM_GAP};


use self::os_policy_type::{OS_POLICY_NONE};


pub type TCP_SSN_STATE = u8;

pub const TCP_SSN_NONE: TCP_SSN_STATE = 1;
pub const TCP_SSN_LISTEN: TCP_SSN_STATE = 2;
pub const TCP_SSN_SYN_SENT: TCP_SSN_STATE = 3;
pub const TCP_SSN_SYN_RECV: TCP_SSN_STATE = 4;
pub const TCP_SSN_ESTABLISHED: TCP_SSN_STATE = 5;
pub const TCP_SSN_FIN_WAIT1: TCP_SSN_STATE = 6;
pub const TCP_SSN_FIN_WAIT2: TCP_SSN_STATE = 7;
pub const TCP_SSN_TIME_WAIT: TCP_SSN_STATE = 8;
pub const TCP_SSN_LAST_ACK: TCP_SSN_STATE = 9;
pub const TCP_SSN_CLOSE_WAIT: TCP_SSN_STATE = 10;
pub const TCP_SSN_CLOSING: TCP_SSN_STATE = 11;
pub const TCP_SSN_CLOSED: TCP_SSN_STATE = 12;

type STREAM_OFFSET_TYPE = u32;


pub struct StreamSeg{
    pub buf: Rc<Data>,
    pub seq: u32,
    range_start: u32,
    range_end: u32,
    payload: u32,
}

enum FIRST_DIR{
    FIRST_TOSERVER,
    FIRST_TOCLIENT,
    FIRST_NONE,
}

use self::FIRST_DIR::{FIRST_NONE, FIRST_TOCLIENT, FIRST_TOSERVER};

pub struct TcpSsnStatistic{
    pub SynAckCnt: usize,
    pub SynCnt: usize,
    pub RstCnt: usize,
}

pub struct TcpSession{
    pub state: TCP_SSN_STATE,
    pub pstate: TCP_SSN_STATE,
    first_ssn_dir: FIRST_DIR,
    pub server_stream: Rc<RefCell<Stream>>,/*ssn stream send from server to client*/
    pub client_stream: Rc<RefCell<Stream>>,/*ssn stream send from client to server*/
    pub stream_flags: STREAM_FLAGS_TYPE,
    pub tcp_flags: TCP_FLAGS_TYPE,
    pub ssn_static: TcpSsnStatistic,
}

fn show_tcp_ssn_first_ssn_dir(dir: &FIRST_DIR) -> String{
    match dir{
        FIRST_TOCLIENT => {"FIRST_TOCLIENT".to_string()},
        FIRST_TOSERVER => {"FIRST_TOSERVER".to_string()},
        FIRST_NONE => {"FIRST_NONE".to_string()},
    }
}

fn show_tcp_ssn_state(state: TCP_SSN_STATE) -> String{
    if state == TCP_SSN_NONE{
        return "TCP_SSN_NONE".to_string();
    }else if state == TCP_SSN_LISTEN{
        return "TCP_SSN_LISTEN".to_string();
    }else if state == TCP_SSN_SYN_SENT{
        return "TCP_SSN_SYN_SENT".to_string();
    }else if state == TCP_SSN_SYN_RECV{
        return "TCP_SSN_SYN_RECV".to_string();
    }else if state == TCP_SSN_ESTABLISHED{
        return "TCP_SSN_ESTABLISHED".to_string();
    }else if state == TCP_SSN_FIN_WAIT1{
        return "TCP_SSN_FIN_WAIT1".to_string();
    }else if state == TCP_SSN_FIN_WAIT2{
        return "TCP_SSN_FIN_WAIT2".to_string();
    }else if state == TCP_SSN_TIME_WAIT{
        return "TCP_SSN_TIME_WAIT".to_string();
    }else if state == TCP_SSN_LAST_ACK{
        return "TCP_SSN_LAST_ACK".to_string();
    }else if state == TCP_SSN_CLOSE_WAIT{
        return "TCP_SSN_CLOSE_WAIT".to_string();
    }else if state == TCP_SSN_CLOSING{
        return "TCP_SSN_CLOSING".to_string();
    }else if state == TCP_SSN_CLOSED{
        return "TCP_SSN_CLOSED".to_string();
    }

    return "tcp ssn state error".to_string();
}

impl Display for TcpSession{

    fn fmt(&self, f: &mut Formatter) -> Result{
        write!(f, "TcpSession state {} first_ssn_dir {}",
               show_tcp_ssn_state(self.state),
                show_tcp_ssn_first_ssn_dir(& self.first_ssn_dir))
    }
}

pub type STREAM_FLAGS_TYPE = u64;
pub const STREAM_FLAGS_NONE: STREAM_FLAGS_TYPE = 0;
pub const STREAM_FLAGS_DEPTH_REACHED: STREAM_FLAGS_TYPE = 1<<0;
pub const STREAM_FLAGS_NO_REASSEMBLY: STREAM_FLAGS_TYPE = 1<<1;
pub const STREAM_FLAGS_GAP: STREAM_FLAGS_TYPE =             1<<2;
pub const STREAM_FLAGS_APPLAYER_DISABLED: STREAM_FLAGS_TYPE = 1<<3;
pub const STREAM_FLAGS_DISABLE_RAW: STREAM_FLAGS_TYPE = 1<<4;
pub const STREAM_FLAGS_MIDSTREAM_SYNACK: STREAM_FLAGS_TYPE = 1<<5;
pub const STREAM_FLAGS_KEEPALIVE: STREAM_FLAGS_TYPE = 1<<6;
pub const STREAM_FLAGS_RST_RECV: STREAM_FLAGS_TYPE = 1<<7;
pub const STREAM_FLAGS_ASYNC: STREAM_FLAGS_TYPE = 1<<8;
pub const STREAM_FLAGS_SERVER_WSCALE: STREAM_FLAGS_TYPE = 1<<9;
pub const STREAM_FLAGS_SACKOK: STREAM_FLAGS_TYPE = 1<<10;
pub const STREAM_FLAGS_4WHS: STREAM_FLAGS_TYPE = 1<<11;
pub const STREAM_FLAGS_TIMESTAMP: STREAM_FLAGS_TYPE = 1<<12;
pub const STREAM_FLAGS_ZERO_TIMESTAMP: STREAM_FLAGS_TYPE = 1<<13;
pub const STREAM_FLAGS_DETECTION_EVASION_ATTEMPT: STREAM_FLAGS_TYPE = 1<<14;
pub const STREAM_FLAGS_CLIENT_SACKOK: STREAM_FLAGS_TYPE = 1<<15;
pub const STREAM_FLAGS_NOREASSEMBLY: STREAM_FLAGS_TYPE = 1<<16;
pub const STREAM_FLAGS_MIDSTREAM: STREAM_FLAGS_TYPE = 1<<17;
pub const STREAM_FLAGS_MIDSTREAM_ESTABLISHED: STREAM_FLAGS_TYPE = 1<<18;
pub const STREAM_FLAGS_APPPROTO_DETECTION_COMPLETED: STREAM_FLAGS_TYPE = 1<<19;

pub struct Stream{
    pub seg_list: LinkedList<StreamSeg>,
    pub wscale: u8,
    pub window: u16,
    pub isn: u32,
    pub reassemble_depth: u32, // bytes for this stream reassemble depths.
    pub base_seq: u32,
    pub next_seq: u32,
    pub last_ts: usize,
    pub last_pkt_ts: usize,
    pub last_ack: u32, // this stream side last received ack.
    pub next_win: u32,
    //pub win: u32, // this stream side get win from remote. means the other party tell us it,s window size.
    pub base_offset: u32, // befor this, data has been progress by all other, so release it.
    pub app_progress_real: u32,
    //pub log_progress_real: u32, mabe some other mode interested in it.
    pub stream_flags: STREAM_FLAGS_TYPE,
    pub tcp_flags: TCP_FLAGS_TYPE,
    pub os_policy: os_policy_type,
}

impl Display for Stream{

    fn fmt(&self, f: &mut Formatter) -> Result{
        write!(f, "Stream isn {} base_seq {} next_seq {} last_ts {}",
            self.isn, self.base_seq, self.next_seq, self.last_ts)
    }
}

pub fn tcp_new_stream(tcp: &Rc<Tcp>) -> Stream{
    Stream{
        seg_list: LinkedList::new(),
        next_seq: 0,
        isn: tcp.seq,
        base_seq: tcp.seq + 1,
        last_ack: 0,
        reassemble_depth: tcp_assem_config.tcp_assemble_depth,
        stream_flags: STREAM_FLAGS_NONE,
        app_progress_real: 0,
        base_offset: 0,
        last_pkt_ts: 0,
        last_ts: 0,
        next_win: 0,
        os_policy: OS_POLICY_NONE,
        tcp_flags: TCP_FLAGS_NONE,
        window: 0,
        wscale: 0,
    }
}

pub fn tcp_new_session(tcp: &Rc<Tcp>) -> Option<TcpSession>{

    let mut stream_from_server = tcp_new_stream(tcp);
    let mut stream_from_client = tcp_new_stream(tcp);

    Some(TcpSession{
        state: TCP_SSN_NONE,
        pstate: TCP_SSN_NONE,
        first_ssn_dir: FIRST_NONE,
        server_stream: Rc::new(RefCell::new(stream_from_server)),
        client_stream: Rc::new(RefCell::new(stream_from_client)),
        stream_flags: STREAM_FLAGS_NONE,
        tcp_flags: TCP_FLAGS_NONE,
        ssn_static: TcpSsnStatistic{
            SynAckCnt: 0,
            SynCnt: 0,
            RstCnt: 0
        },
    })
}

/*{
let stream = tcp_new_stream(tcp);

flow.transport_info = TransportInfo::transport_tcp(steam);

return;

}*/

pub fn ssn_set_packet_state(flow: & Arc<RwLock<Flow>>, ssn: & Rc<RefCell<TcpSession>>, state: TCP_SSN_STATE){
    ssn.borrow_mut().pstate = ssn.borrow().state;
    ssn.borrow_mut().state = state;
    match ssn.borrow().state{
        TCP_SSN_ESTABLISHED|TCP_SSN_FIN_WAIT1|TCP_SSN_FIN_WAIT2|TCP_SSN_CLOSING|TCP_SSN_CLOSE_WAIT => {
            rw_lock_write!(flow, ()).state = FLOW_STATE_ESTABLISHED;
        },
        TCP_SSN_LAST_ACK|TCP_SSN_TIME_WAIT|TCP_SSN_CLOSED => {
            rw_lock_write!(flow, ()).state = FLOW_STATE_CLOSED;
        },
        _ => {},
    }
}

fn new_stream_seg_from_seg(seg: &StreamSeg) -> StreamSeg{
    StreamSeg{
        buf: Rc::clone(&seg.buf),
        seq: seg.seq,
        range_start: seg.range_start,
        range_end: seg.range_end,
        payload: seg.range_end - seg.range_start,
    }
}

fn stream_seg_befor_offset(stream_seg: &StreamSeg, stream: &Rc<RefCell<Stream>>, offset: u32) -> bool{

    let data = &stream_seg.buf.buf;

    if stream_get_seg_offset(stream, stream_seg) +data.len() as u32 <= offset {
        return true;
    } else {
        return false;
    }
}

fn stream_get_seg_offset(stream: &Rc<RefCell<Stream>>, stream_seg: &StreamSeg) -> STREAM_OFFSET_TYPE{
    return stream_seg.seq - stream.borrow().base_seq - stream.borrow().base_offset;
}

fn stream_get_applayer_progress_offset(stream: &Rc<RefCell<Stream>>) -> STREAM_OFFSET_TYPE{
    return stream.borrow().base_offset + stream.borrow().app_progress_real;
}

fn stream_get_applayer_data(stream: &Stream, app_progress: STREAM_OFFSET_TYPE) -> Rc<Vec<u8>>{

    Rc::new(Vec::new())
}

enum STREAM_TO_APPLAYER{
    None, // no new data, mabe a gap
    Gap(STREAM_OFFSET_TYPE), // gap happened, value means gap len
    Seg(StreamSeg), // data
}

fn stream_get_one_seg_from_offset(stream: &Rc<RefCell<Stream>>, offset: STREAM_OFFSET_TYPE) ->STREAM_TO_APPLAYER{
    if offset < stream.borrow().base_offset{
        // suricata return. ignore anything.
        // this mabe some probrem. we need return gap, and reset offset to base_offset
        return STREAM_TO_APPLAYER::Gap(stream.borrow().base_offset-offset);
    }else{
        let ref_stream = stream.borrow();
        let mut seg_iter = ref_stream.seg_list.iter();
        while let Some(ref seg) = seg_iter.next(){
            let seg_offset= stream_get_seg_offset(stream, seg);
            if seg_offset > offset{
                return STREAM_TO_APPLAYER::Gap(seg_offset - offset);
            }

            let seg_len = seg.buf.buf.len() as u32;

            if offset >= (seg_offset + seg_len){
                continue;
            }

            let range_start = offset - seg_offset;

            let mut reg_to_applayer = new_stream_seg_from_seg(seg);
            reg_to_applayer.range_start = range_start;

            return STREAM_TO_APPLAYER::Seg(reg_to_applayer);
        }

        return STREAM_TO_APPLAYER::None;
    }
}


// this_dir: which dir to update.
fn stream_reassemble_applayer(packet: &Packet, flow:& Arc<RwLock<Flow>>, ssn: &Rc<RefCell<TcpSession>>, stream: & Rc<RefCell<Stream>>, this_dir: bool) -> bool{

    if check_flag!(ssn.borrow().stream_flags, STREAM_FLAGS_APPLAYER_DISABLED) ||
        check_flag!(stream.borrow().stream_flags, STREAM_FLAGS_NO_REASSEMBLY){
        return true;
    }

    let ref_stream = stream.borrow();
    let mut seg_tail = ref_stream.seg_list.back();

    if let None = seg_tail {
        if (ssn.borrow().state >= TCP_SSN_CLOSED) || (check_flag!(packet.flags, PACKET_FLAGS_PSEUDO_STREAM_END)) {
            let tmp_flags = get_applayer_flag_from_stream(packet, ssn, stream, this_dir);
            stream_applayer_hand_tcp_data(flow, ssn, stream, tmp_flags, APPLAYER_DATA::APPLAYER_DATA_NONE);
            return true;
        }
    }else if let Some(ref seg_tail) = seg_tail{
        if stream_seg_befor_offset(&seg_tail, stream, stream_get_applayer_progress_offset(stream)) {
            if (ssn.borrow().state >= TCP_SSN_CLOSED) || (check_flag!(packet.flags, PACKET_FLAGS_PSEUDO_STREAM_END)) {
                let tmp_flags = get_applayer_flag_from_stream(packet, ssn, stream, this_dir);
                stream_applayer_hand_tcp_data(flow, ssn, stream, tmp_flags, APPLAYER_DATA::APPLAYER_DATA_NONE);
                return true;
            }
        }
    }

    let mut app_progress = stream_get_applayer_progress_offset(stream);
    let mut data_len = 0;

    loop {

        let (stream_seg, seg_gap_len) = stream_get_seg_by_offset(stream, app_progress);
        if let Some(seg) = stream_seg {

            data_len = seg.range_end - seg.range_start;
            if !stream_applayer_hand_one_seg(packet, flow, ssn, stream, &seg, app_progress, data_len, this_dir){
                return false;
            }

            break;
        } else if let Some(gap_len) = seg_gap_len {
            let tmp_flags = get_applayer_flag_from_stream(packet, ssn, stream, this_dir)|APPLAYER_FLAGS_STREAM_GAP;

            stream_applayer_hand_tcp_data(flow, ssn, stream, tmp_flags, APPLAYER_DATA::APPLAYER_DATA_GAP(gap_len));

            stream.borrow_mut().app_progress_real += gap_len;
            app_progress += data_len;
        }else{
            let tmp_flags = get_applayer_flag_from_stream(packet, ssn, stream, this_dir);
            stream_applayer_hand_tcp_data(flow, ssn, stream, tmp_flags, APPLAYER_DATA::APPLAYER_DATA_NONE);
            return true;
        }
    }

    return true;
}

fn stream_applayer_hand_one_seg(packet:&Packet, flow: & Arc<RwLock<Flow>>, ssn: & Rc<RefCell<TcpSession>>, stream: & Rc<RefCell<Stream>>, seg: &StreamSeg, app_progress: u32, mut data_len: u32, this_dir: bool) -> bool {
    let buf = &seg.buf.buf;

    let data = &buf[seg.range_start as usize..seg.range_end as usize];

    if !check_flag!(packet.flags, PACKET_FLAGS_PSEUDO_STREAM_END) {
        let mut last_ack_abs = app_progress;
        if stream_lastack_great_than_baseseq(stream) {
            let delta = stream.borrow().last_ack - stream.borrow().base_seq;
            if delta > 10000000 && delta > stream.borrow().window as u32 {
                error!("suricata exit here, some error must happened.");
                return false;
            }
            last_ack_abs += delta;
        }

        if app_progress + data_len > last_ack_abs {
            let check = data_len;
            data_len = last_ack_abs - app_progress;
            if data_len > check {
                error!("suricata exit here, some error must happened.");
                return false;
            }
        }
    }

    let tmp_flags = get_applayer_flag_from_stream(packet, ssn, stream, this_dir);

    if stream_applayer_hand_tcp_data(flow, ssn, stream, tmp_flags, APPLAYER_DATA::APPLAYER_DATA_SLICE(data)){

        if (data_len > 0) && check_flag!(stream.borrow().stream_flags, STREAM_FLAGS_APPPROTO_DETECTION_COMPLETED){

            stream.borrow_mut().app_progress_real += data_len;
            debug!("app progress now {}", stream.borrow().app_progress_real);
        }else{
            debug!("NOT UPDATED app progress still {}", app_progress);
        }
    }

    return true;
}

fn stream_get_seg_by_offset(stream: &Rc<RefCell<Stream>>, offset: STREAM_OFFSET_TYPE) -> (Option<StreamSeg>, Option<STREAM_OFFSET_TYPE>){
    if offset < stream.borrow().base_offset{

        return (None, Some(stream.borrow().base_offset-offset));
    }else{

        let ref_stream = stream.borrow();
        let mut seg_iter = ref_stream.seg_list.iter();

        while let Some(seg) = seg_iter.next(){

            let seg_offset = stream_get_seg_offset(stream, &seg);
            let seg_len = seg.buf.buf.len() as u32;

            if (offset >= seg_offset) && (offset < seg_offset+seg_len){
                let mut r_seg: StreamSeg = new_stream_seg_from_seg(seg);

                // send to applayer stream seg may be part of this real seg
                r_seg.range_start = offset - seg_offset;

                return (Some(r_seg), None);
            }else if seg_offset > offset{
                return (None, Some(seg_offset - offset));
            }
        }
    }

    return (None, None);
}

fn stream_depth_check(stream_seg: &mut StreamSeg, stream: & Rc<RefCell<Stream>>){

}

fn stream_handle_segment_insert(packet: &mut Packet, tcp: &Rc<Tcp>, stream: &Rc<RefCell<Stream>>, mut stream_seg: StreamSeg) -> bool{



    // suricata os policy


    // reassemble depth check
    stream_depth_check(&mut stream_seg, stream);

    let insert_seg_len = stream_seg.buf.buf.len() as u32;

    let tmp_stream = Rc::clone(stream);
    let mut ref_stream = tmp_stream.borrow_mut();
    let mut seg_iter = ref_stream.seg_list.iter_mut();
/*
    while let Some(ref seg) = seg_iter.peek_next(){

        let (pre_seq,pre_len) = (seg.seq, seg.buf.buf.len());

        if stream_seg.seq < seg.seq{

            let list_seg_len = seg.buf.buf.len() as u32;

            if (stream_seg.seq + insert_seg_len) <= (seg.seq + list_seg_len){
                if stream_seg.seq + insert_seg_len > seg.seq{
                    let cut_len = stream_seg.seq + insert_seg_len - seg.seq;
                    stream_seg.range_end -= cut_len;
                }

                break;
                //seg_iter.insert_next(stream_seg);
                //return true;
            }

            return false;
        }else if (stream_seg.seq >= seg.seq) &&
            (stream_seg.seq < (seg.seq + seg.buf.buf.len() as u32)){
            return false;
        }

        match seg_iter.next(){_ => {},}
    }

    // just insert into the end.
    seg_iter.insert_next(stream_seg);
    */
    return true;
}

fn stream_handle_segment_update_by_ack(packet: &Packet, flow:& Arc<RwLock<Flow>>, ssn: & Rc<RefCell<TcpSession>>, stream: &Rc<RefCell<Stream>>) -> bool{
    return stream_reassemble_applayer(packet, flow, ssn, stream, false);
}

fn new_stream_seg(packet: &Packet, tcp: &Tcp, data: &Rc<Data>) -> StreamSeg{
    StreamSeg{
        buf: Rc::clone(data),
        seq: tcp.seq,
        range_start: tcp.data_offset as u32,
        range_end: packet.pkt_len as u32,
        payload: packet.pkt_len as u32 - tcp.data_offset as u32,
    }
}

/*
1. insert new seg with data into streamseg
2. triggered by ACK, update streamseg to applayer
*/
pub fn session_handle_stream_segment(packet: &mut Packet, tcp: &Rc<Tcp>, flow:& Arc<RwLock<Flow>>,
                                     ssn: & Rc<RefCell<TcpSession>>){

    //debug!("{} {}", ssn, packet);

    let mut stream_push_to_applayer = false;

    let operation_stream = if (packet.flags & PACKET_FLAGS_TOSERVER)!=0{
        Rc::clone(&ssn.borrow().server_stream)
    }else{
        Rc::clone(&ssn.borrow().client_stream)
    };

    if check_flag!(packet.flags, PACKET_FLAGS_PSEUDO_STREAM_END){
        stream_push_to_applayer = true;
    }else if check_flag!(tcp.flags, TCP_FLAGS_RST){
        stream_push_to_applayer = true;
    }else if ((tcp.flags & TCP_FLAGS_FIN) != 0) && (ssn.borrow().state > TCP_SSN_TIME_WAIT){
        stream_push_to_applayer = true;
    }

    let stream_seg = if let Some(ref data) = packet.data.data{
        new_stream_seg(packet, tcp, data)
    }else{
        error!("session_handle_stream_segment, but Packet data.data is None.");
        return;
    };

    if !stream_push_to_applayer{
        if let false = stream_handle_segment_update_by_ack(packet, flow, ssn, &operation_stream){
            println!("session_handle_segment_update_by_ack fail.");
            return;
        }
    }

    if tcp.payload > 0 && check_flag!(operation_stream.borrow().stream_flags, STREAM_FLAGS_NOREASSEMBLY) {
        if let false = stream_handle_segment_insert(packet, tcp, &operation_stream, stream_seg) {
            error!("session_handle_segment_insert fail.");
            return;
        }
    }else{
        warn!("{} {} not calling stream_handle_segment_insert.", ssn.borrow(), packet)
    }

    if stream_push_to_applayer{
        if let false = stream_reassemble_applayer(packet, flow, ssn, &operation_stream, true){
            println!("stream_reassemble_applayer fail.");
            return;
        }
    }

    return;
}

fn get_operation_stream(packet: &Packet, ssn: &Rc<RefCell<TcpSession>>) -> Option<Rc<RefCell<Stream>>>{

    if (packet.flags & PACKET_FLAGS_TOSERVER) != 0{
        Some(Rc::clone(&ssn.borrow().server_stream))
    }else if (packet.flags & PACKET_FLAGS_TOCLIENT) != 0{
        Some(Rc::clone(&ssn.borrow().client_stream))
    }else{
        None
    }
}

// for a new stream or closed stream.
fn session_handle_state_none(packet: &mut Packet, tcp: & Rc<Tcp>, flow: &Arc<RwLock<Flow>>, ssn: &Rc<RefCell<TcpSession>>) -> bool{

    if check_flag!(tcp.flags, TCP_FLAGS_RST) {
        //StreamTcpSetEvent(tcp,STREAM_RST_BUT_NO_SESSION); follow suricata
        debug!("RST packet received, but session is none");
        return false;
    }else if check_flag!(tcp.flags, TCP_FLAGS_FIN){
        //StreamTcpSetEvent(tcp, STREAM_FIN_BUT_NO_SESSION); follow suricata
        debug!("FIN packet received, but session is none");
        return false;
    }else if (tcp.flags & ( TCP_FLAGS_SYN | TCP_FLAGS_ACK )) == ( TCP_FLAGS_SYN | TCP_FLAGS_ACK ){

        if !tcp_assem_config.mid_stream &&
            !tcp_assem_config.async_oneside{
            return false;
        }

        ssn_set_packet_state( flow, ssn, TCP_SSN_SYN_RECV);
        {add_flag!(ssn.borrow_mut().stream_flags, STREAM_FLAGS_MIDSTREAM);}
        {add_flag!(ssn.borrow_mut().stream_flags, STREAM_FLAGS_MIDSTREAM_SYNACK);}

        if tcp_assem_config.async_oneside{
            {add_flag!(ssn.borrow_mut().stream_flags, STREAM_FLAGS_ASYNC);}
        }


        add_eq_b_bw!(ssn, server_stream, isn, tcp.seq);
        add_eq_b_bw!(ssn, server_stream, base_seq, tcp.seq + 1);
        add_eq_b_bw!(ssn, server_stream, next_seq, tcp.seq + 1);
        add_eq_b_bw!(ssn, server_stream, window, tcp.win);

        add_eq_b_bw!(ssn, client_stream, isn, tcp.ack - 1);
        add_eq_b_bw!(ssn, client_stream, base_seq, tcp.ack);
        add_eq_b_bw!(ssn, client_stream, next_seq, tcp.ack);

        add_eq_b_bw!(ssn, client_stream, last_ack, tcp.ack);
        add_eq_b_bw!(ssn, server_stream, last_ack, tcp.seq);

        add_eq_b_bw!(ssn, server_stream, next_win, get_ref_b_b!(ssn, server_stream, last_ack)  + get_ref_b_b!(ssn, server_stream, window) as u32);

        if TCP_HAS_WSCALE!(tcp){
            add_eq_b_bw!(ssn, client_stream, wscale, TCP_GET_WSCALE!(tcp));
            add_eq_b_bw!(ssn, server_stream, wscale, TCP_WSCALE_MAX);
            debug!("{} wscale enabled, client {} server {}", ssn.borrow(),
                get_ref_b_b!(ssn, client_stream, wscale), get_ref_b_b!(ssn, server_stream, wscale));
        }

        debug!("{} client isn {} next_seq {}", ssn.borrow(), get_ref_b_b!(ssn, client_stream, isn),
                get_ref_b_b!(ssn, client_stream, next_seq));
        debug!("{} server isn {} next_seq {}", ssn.borrow(), get_ref_b_b!(ssn, server_stream, isn),
               get_ref_b_b!(ssn, server_stream, next_seq));

        if TCP_HAS_TS!(tcp){
            add_eq_b_bw!(ssn, server_stream, last_ts, TCP_GET_TS!(tcp));
            add_eq_b_bw!(ssn, client_stream, last_ts, TCP_GET_TSECR!(tcp));

            debug!("{} server last_ts {} client last_ts {}", ssn.borrow(),
                get_ref_b_b!(ssn, server_stream, last_ts), get_ref_b_b!(ssn, client_stream, last_ts));

            add_flag!(ssn.borrow_mut().stream_flags, STREAM_FLAGS_TIMESTAMP);

            add_eq_b_bw!(ssn, server_stream, last_pkt_ts, packet.ts);

            if check_eq_b_b!(ssn, server_stream, last_ts, 0){
                add_contain_b_bw!(ssn, server_stream, stream_flags, STREAM_FLAGS_ZERO_TIMESTAMP);
            }
            if check_eq_b_b!(ssn, client_stream, last_ts, 0) {
                add_eq_b_bw!(ssn, client_stream, stream_flags, STREAM_FLAGS_ZERO_TIMESTAMP);
            }
        }else{

            add_eq_b_bw!(ssn, server_stream, last_ts, 0);
            add_eq_b_bw!(ssn, client_stream, last_ts, 0);
        }

        if TCP_HAS_SACKOK!(tcp){
            add_flag!(ssn.borrow_mut().stream_flags, STREAM_FLAGS_SACKOK);
        }

        packet.switch_dir();

    }else if (tcp.flags & TCP_FLAGS_SYN) != 0{

        ssn_set_packet_state( flow, ssn, TCP_SSN_SYN_SENT);

        if tcp_assem_config.async_oneside{
            debug!("{} ASYNC", ssn.borrow());
            add_flag!(ssn.borrow_mut().stream_flags, STREAM_FLAGS_ASYNC);
        }

        add_eq_b_bw!(ssn, client_stream, isn, tcp.seq);
        add_eq_b_bw!(ssn, client_stream, base_seq, tcp.seq + 1);
        add_eq_b_bw!(ssn, client_stream, next_seq, tcp.seq + 1);

        if TCP_HAS_TS!(tcp){
            add_eq_b_bw!(ssn, client_stream, last_ts, TCP_GET_TS!(tcp));
            if check_eq_b_b!(ssn, client_stream, last_ts, 0){
                add_contain_b_bw!(ssn, client_stream, stream_flags, STREAM_FLAGS_ZERO_TIMESTAMP);
            }

            add_eq_b_bw!(ssn, client_stream, last_pkt_ts, packet.ts);
            add_contain_b_bw!(ssn, client_stream, stream_flags, STREAM_FLAGS_TIMESTAMP);
        }

        add_eq_b_bw!(ssn, server_stream, window, tcp.win);

        if TCP_HAS_WSCALE!(tcp){
            add_flag!(ssn.borrow_mut().stream_flags, STREAM_FLAGS_SERVER_WSCALE);
            add_eq_b_bw!(ssn, server_stream, wscale, TCP_GET_WSCALE!(tcp));
        }

        if TCP_HAS_SACKOK!(tcp){
            {add_flag!(ssn.borrow_mut().stream_flags, STREAM_FLAGS_CLIENT_SACKOK);}
        }

        debug!("{} client isn {} next_seq {} last_ack {}", ssn.borrow(),
            get_ref_b_b!(ssn, client_stream, isn), get_ref_b_b!(ssn, client_stream, next_seq),
               get_ref_b_b!(ssn, client_stream, last_ack));

    }else if (tcp.flags & TCP_FLAGS_ACK) != 0{

        if !tcp_assem_config.mid_stream{
            return false;
        }

        ssn_set_packet_state( flow, ssn, TCP_SSN_ESTABLISHED);

        {add_flag!(ssn.borrow_mut().stream_flags, STREAM_FLAGS_MIDSTREAM);}
        {add_flag!(ssn.borrow_mut().stream_flags, STREAM_FLAGS_MIDSTREAM_ESTABLISHED);}

        if tcp_assem_config.async_oneside{
            {add_flag!(ssn.borrow_mut().stream_flags, STREAM_FLAGS_ASYNC);}
        }

        add_eq_b_bw!(ssn, client_stream, wscale, TCP_WSCALE_MAX);
        add_eq_b_bw!(ssn, server_stream, wscale, TCP_WSCALE_MAX);

        add_eq_b_bw!(ssn, client_stream, isn, tcp.seq - 1);
        add_eq_b_bw!(ssn, client_stream, base_seq, tcp.seq);
        add_eq_b_bw!(ssn, client_stream, next_seq, tcp.seq + tcp.payload);
        add_eq_b_bw!(ssn, client_stream, window, tcp.win << get_ref_b_b!(ssn, client_stream, wscale));
        add_eq_b_bw!(ssn, client_stream, last_ack, tcp.seq);
        add_eq_b_bw!(ssn, client_stream, next_win, get_ref_b_b!(ssn, client_stream, last_ack) + get_ref_b_b!(ssn, client_stream, window) as u32);

        debug!("{} client isn {} next_seq {}", ssn.borrow(),
               get_ref_b_b!(ssn, client_stream, isn), get_ref_b_b!(ssn, client_stream, next_seq));

        add_eq_b_bw!(ssn, server_stream, isn, tcp.ack - 1);
        add_eq_b_bw!(ssn, server_stream, base_seq, tcp.ack);
        add_eq_b_bw!(ssn, server_stream, next_seq, tcp.ack);
        add_eq_b_bw!(ssn, server_stream, last_ack, tcp.ack);
        add_eq_b_bw!(ssn, server_stream, next_win, get_ref_b_b!(ssn, server_stream, last_ack));

        debug!("{} client next_win {} server next_win {}", ssn.borrow(),
            get_ref_b_b!(ssn, client_stream, next_win), get_ref_b_b!(ssn, server_stream, next_win));

        debug!("{} client last_ack {} server last_ack {}", ssn.borrow(),
            get_ref_b_b!(ssn, client_stream, last_ack), get_ref_b_b!(ssn, server_stream, last_ack));

        if TCP_HAS_TS!(tcp){
            add_eq_b_bw!(ssn, client_stream, last_ts, TCP_GET_TS!(tcp));
            add_eq_b_bw!(ssn, server_stream, last_ts, TCP_GET_TSECR!(tcp));
            debug!("{} server last_ts {} client last_ts {}", ssn.borrow(),
                get_ref_b_b!(ssn, server_stream, last_ts), get_ref_b_b!(ssn, client_stream, last_ts));

            add_flag!(ssn.borrow_mut().stream_flags, STREAM_FLAGS_TIMESTAMP);

            add_eq_b_bw!(ssn, client_stream, last_pkt_ts, packet.ts);
            if check_eq_b_b!(ssn, server_stream, last_ts, 0){
                add_contain_b_bw!(ssn, server_stream, stream_flags, STREAM_FLAGS_ZERO_TIMESTAMP);
            }
            if check_eq_b_b!(ssn, client_stream, last_ts, 0){
                add_contain_b_bw!(ssn, client_stream, stream_flags, STREAM_FLAGS_ZERO_TIMESTAMP);
            }
        }else{
            add_eq_b_bw!(ssn, server_stream, last_ts, 0);
            add_eq_b_bw!(ssn, client_stream, last_ts, 0);
        }

        session_handle_stream_segment(packet, tcp, flow, ssn);

        add_flag!(ssn.borrow_mut().stream_flags, STREAM_FLAGS_SACKOK);
    }else{
        debug!("default case");
    }

    return true;
}

fn stream_packet_is_keepalive_ack(packet: &Packet, tcp: &Rc<Tcp>, ssn: &Rc<RefCell<TcpSession>>) -> bool{
    return true;
}
fn stream_packet_is_keepalive(packet: &Packet, tcp: &Rc<Tcp>, ssn: &Rc<RefCell<TcpSession>>, stream: & Rc<RefCell<Stream>>) -> bool{
    if tcp.payload > 0{
        return false;
    }

    if (tcp.flags & (TCP_FLAGS_SYN|TCP_FLAGS_FIN|TCP_FLAGS_RST)) != 0{
        return false;
    }

    let seq = tcp.seq;
    let ack = tcp.ack;

    if check_flag!(packet.flags, PACKET_FLAGS_TOSERVER){
        if check_eq_b_b!(ssn, server_stream, last_ack, ack) &&
            (seq == get_ref_b_b!(ssn, client_stream, next_seq) - 1){
            add_flag!(stream.borrow_mut().stream_flags, STREAM_FLAGS_KEEPALIVE);
            return true;
        }
    }

    return false;
}

pub fn tcp_session_hand(packet: &mut Packet, tcp: Rc<Tcp>, flow: &Arc<RwLock<Flow>>) -> bool {

    {
        let mut build_new_session = false;

        match rw_lock_write!(flow, false).session {
            None => {
                build_new_session = true;
            },

            Some(ref ssn) => {
                if let tcp_session(_) = ssn {
                    ;// only check is tcp ssn?
                } else {
                    error!("tcp_session_hand flow.session is neight None nor TcpSession");
                    return false;
                }
            },
        }

        if build_new_session{
            let tcp_ssn = match tcp_new_session(&tcp) {
                Some(t) => { t },
                None => {
                    error!("tcp_new_session fail.");
                    return false;
                },
            };
            rw_lock_write!(flow, false).session = Some(tcp_session(Rc::new(RefCell::new(tcp_ssn))));
        }
    }

    let ssn = match rw_lock_read!(flow, false).session{
        Some(ref session) => {
            match session {
                tcp_session(ref t) => {Rc::clone(t)},
                _ => {
                    error!("tcp_session_hand, but flow.session is not tcp_session");
                    return false;
                },
            }
        },
        None => {
            error!("tcp_session_hand, but flow.session is None");
            return false;
        },
    };

    let operation_stream = match get_operation_stream(packet, &ssn){
        Some(t) => {t},
        None => {
            error!("get_operation_stream failed.");
            return false;
        },
    };

    ssn.borrow_mut().tcp_flags |= tcp.flags;
    if check_flag!(packet.flags, PACKET_FLAGS_TOSERVER){
        add_contain_b_bw!(ssn, server_stream, tcp_flags, tcp.flags);
    }else{
        add_contain_b_bw!(ssn, client_stream, tcp_flags, tcp.flags);
    }

    if check_flag!(ssn.borrow().stream_flags, STREAM_FLAGS_ASYNC) &&
        !check_eq_b_b!(ssn, client_stream, tcp_flags, 0) &&
        !check_eq_b_b!(ssn, server_stream, tcp_flags, 0){

        debug!("{} removing ASYNC flag as we have packets on both sides.", ssn.borrow());
        {del_flag!(ssn.borrow_mut().stream_flags, STREAM_FLAGS_ASYNC);}
    }

    if check_flag!(tcp.flags, TCP_FLAGS_SYN|TCP_FLAGS_ACK){
        {ssn.borrow_mut().ssn_static.SynAckCnt += 1;}
    }else if check_flag!(tcp.flags, TCP_FLAGS_SYN){
        {ssn.borrow_mut().ssn_static.SynCnt += 1;}
    }

    if check_flag!(tcp.flags, TCP_FLAGS_RST){
        {ssn.borrow_mut().ssn_static.RstCnt += 1;}
    }

    if !check_flag!(tcp.flags, TCP_FLAGS_ACK) &&
        tcp.ack != 0{
        ; // StreamTcpSetEvent(tcp,STREAM_PKT_BROKEN_ACK)  follow suricata
    }

    // check ips mode follow suricata

    if ssn.borrow().first_ssn_dir == FIRST_DIR::FIRST_NONE{
        if check_flag!(packet.flags, PACKET_FLAGS_TOSERVER){
            {ssn.borrow_mut().first_ssn_dir = FIRST_DIR::FIRST_TOSERVER;}
        }else if check_flag!(packet.flags, PACKET_FLAGS_TOCLIENT){
            {ssn.borrow_mut().first_ssn_dir = FIRST_DIR::FIRST_TOCLIENT;}
        }else{
            error!("tcp_session_hand: packet dir is not set, error.");
            return false;
        }
    }

    if ssn.borrow().state == TCP_SSN_NONE{

        if!(session_handle_state_none(packet,&tcp, &flow, &ssn)){
            return false;
        }
    }else{
        let stream = if (packet.flags & PACKET_FLAGS_TOSERVER) != 0{
            Rc::clone(&ssn.borrow().server_stream)
        }else if (packet.flags & PACKET_FLAGS_TOCLIENT) != 0{
            Rc::clone(&ssn.borrow().client_stream)
        }else{
            println!("tcp_session_hand: packet dir is not set, error.");
            return false;
        };

        ssn.borrow_mut().tcp_flags |= tcp.flags;
        operation_stream.borrow_mut().tcp_flags |= tcp.flags;


        if check_flag!(ssn.borrow().stream_flags, STREAM_FLAGS_ASYNC) &&
            !check_eq_b_b!(ssn, server_stream, tcp_flags, 0) &&
            !check_eq_b_b!(ssn, client_stream, tcp_flags, 0) {

            del_flag!(ssn.borrow_mut().stream_flags, STREAM_FLAGS_ASYNC);
        }

        if check_flag!(ssn.borrow().stream_flags, STREAM_FLAGS_MIDSTREAM_SYNACK){
            packet.switch_dir();
        }

        if stream_packet_is_keepalive(packet, &tcp, &ssn, &stream){
            stream_packet_check_post_rst(&tcp, &ssn, &stream);
            return false;
        }

        if(stream_packet_is_keepalive_ack(packet, &tcp, &ssn)){
            del_flag!(stream.borrow_mut().stream_flags, STREAM_FLAGS_KEEPALIVE);
            stream_packet_check_post_rst(&tcp, &ssn, &stream);
            return false;
        }

        if stream_packet_is_fin_shutdown_ack(packet,&tcp, &ssn){
            if stream_packet_is_window_update(packet, &tcp, &ssn ) {
                if stream_packet_is_bad_window_update(packet, &tcp, &ssn ) {
                    stream_packet_check_post_rst(&tcp, &ssn, &stream);
                    return false;
                }
            }
        }
        if check_flag!(stream.borrow().stream_flags, STREAM_FLAGS_KEEPALIVE){
            del_flag!(stream.borrow_mut().stream_flags, STREAM_FLAGS_KEEPALIVE);
        }

        if !(stream_state_dispatch(packet, &tcp, &flow,&ssn, &stream)) {
            return false;
        }

        stream_packet_check_post_rst(&tcp, & ssn, &stream);
    }

    return false;
}

fn stream_packet_is_window_update(packet: &Packet, tcp: &Rc<Tcp>, ssn: &Rc<RefCell<TcpSession>>) -> bool{
    if ssn.borrow().state < TCP_SSN_ESTABLISHED{
        return false;
    }

    if tcp.payload > 0{
        return false;
    }

    if check_flag!(tcp.flags,(TCP_FLAGS_SYN|TCP_FLAGS_FIN|TCP_FLAGS_RST)){
        return false;
    }

    if tcp.win == 0{
        return false;
    }

    let seq = tcp.seq;
    let ack = tcp.ack;

    let (stream, ostream) = if check_flag!(packet.flags, PACKET_FLAGS_TOSERVER){
        (Rc::clone(&ssn.borrow().server_stream), Rc::clone(&ssn.borrow().client_stream))
    }else{
        (Rc::clone(&ssn.borrow().client_stream), Rc::clone(&ssn.borrow().server_stream))
    };

    let pkt_win = tcp.win << ostream.borrow().wscale;
    if pkt_win == ostream.borrow().window{
        return false;
    }

    if ack == ostream.borrow().last_ack &&
        seq == stream.borrow().next_seq{
        return true;
    }

    return false;
}

fn stream_packet_is_bad_window_update(packet: &Packet, tcp: &Rc<Tcp>, ssn: &Rc<RefCell<TcpSession>>) -> bool{
    if (ssn.borrow().state < TCP_SSN_ESTABLISHED) || (ssn.borrow().state == TCP_SSN_CLOSED){
        return false;
    }

    if check_flag!(tcp.flags, (TCP_FLAGS_SYN|TCP_FLAGS_FIN|TCP_FLAGS_RST)){
        return false;
    }

    let seq = tcp.seq;
    let ack = tcp.ack;

    let (stream, ostream) = if check_flag!(packet.flags, PACKET_FLAGS_TOSERVER){
        (Rc::clone(&ssn.borrow().server_stream), Rc::clone(&ssn.borrow().client_stream))
    }else{
        (Rc::clone(&ssn.borrow().client_stream), Rc::clone(&ssn.borrow().server_stream))
    };

    let pkt_win = tcp.win << ostream.borrow().wscale;

    if pkt_win < ostream.borrow().window{
        let diff = ostream.borrow().window - pkt_win;
        if (diff > tcp.payload as u16) &&
            (ack > ostream.borrow().next_seq) &&
            (seq > stream.borrow().next_seq){
            let adiff = ack - ostream.borrow().last_ack;
            if ((pkt_win > 1024) && (diff >(adiff as u16 + 32))) ||
                ((pkt_win <= 1024) && (diff > adiff as u16)){
                return true;
            }
        }
    }

    return false;
}

fn stream_packet_is_fin_shutdown_ack(packet: &Packet, tcp: &Rc<Tcp>, ssn: &Rc<RefCell<TcpSession>>) -> bool{

    if!(ssn.borrow().state == TCP_SSN_TIME_WAIT ||
            ssn.borrow().state == TCP_SSN_CLOSE_WAIT ||
                ssn.borrow().state == TCP_SSN_LAST_ACK){
        return false;
    }

    if (tcp.flags != TCP_FLAGS_ACK){
        return false;
    }

    if(tcp.payload > 0){
        return false;
    }

    let seq = tcp.seq;
    let ack = tcp.ack;

    let (stream, ostream) = if check_flag!(packet.flags, PACKET_FLAGS_TOSERVER){
        (Rc::clone(&ssn.borrow().server_stream), Rc::clone(&ssn.borrow().client_stream))
    }else{
        (Rc::clone(&ssn.borrow().client_stream), Rc::clone(&ssn.borrow().server_stream))
    };


    if((stream.borrow().next_seq + 1)==seq) &&
        (ack == (ostream.borrow().next_seq + 1)){
        return true;
    }

    return false;
}

fn stream_packet_check_post_rst(tcp: &Rc<Tcp>, ssn: &Rc<RefCell<TcpSession>>, stream: &Rc<RefCell<Stream>>){
    if check_flag!(tcp.flags, TCP_FLAGS_RST){
        return;
    }

    if check_flag!(stream.borrow().stream_flags, STREAM_FLAGS_RST_RECV) {
        del_flag!(stream.borrow_mut().stream_flags, STREAM_FLAGS_RST_RECV);
        return;
    }

    return;
}

fn stream_release_all_segment(stream: & Rc<RefCell<Stream>>){

    while let Some(_) = stream.borrow_mut().seg_list.pop_front(){
        ;
    }
}

// check app progress and raw progress and progresses if needed. gets rid of segments
pub fn tcp_stream_release_segment(packet: &Packet){

    let flow = match packet.flow{
        Some(ref t) => {Arc::clone(t)},
        None => {return;},
    };

    let ssn = match rw_lock_read!(flow, ()).session{
        Some(ref t) => {
            match t{
                tcp_session(ref tcp_ssn) => {Rc::clone(tcp_ssn)},
                _ => {return;},
            }
        },
        None => {return;},
    };

    let stream = if (packet.flags & PACKET_FLAGS_TOSERVER) != 0{
        Rc::clone(&ssn.borrow().server_stream)
    }else{
        Rc::clone(&ssn.borrow().client_stream)
    };

    if (stream.borrow().stream_flags & STREAM_FLAGS_NO_REASSEMBLY) != 0{
        return;
    }

    if check_flag!(stream.borrow().stream_flags, STREAM_FLAGS_DEPTH_REACHED){

        add_flag!(stream.borrow_mut().stream_flags, STREAM_FLAGS_NO_REASSEMBLY);
        stream_release_all_segment(&stream);
        return;
    }else if (check_flag!(stream.borrow().stream_flags, STREAM_FLAGS_GAP) ||
        check_flag!(ssn.borrow().stream_flags, STREAM_FLAGS_APPLAYER_DISABLED)) &&
        check_flag!(stream.borrow().stream_flags, STREAM_FLAGS_DISABLE_RAW){

        add_flag!(stream.borrow_mut().stream_flags, STREAM_FLAGS_NO_REASSEMBLY);
        stream_release_all_segment(&stream);
        return;
    }

    let move_len = get_stream_move_len(&ssn, &stream);
    if (move_len > 0) {
        stream.borrow_mut().base_seq += move_len;

        if move_len <= stream.borrow().app_progress_real {
            stream.borrow_mut().app_progress_real -= move_len;
        } else {
            stream.borrow_mut().app_progress_real = 0;
        }
    }

    let mut tmp_seg_list = LinkedList::new();
    while let Some(seg) = stream.borrow_mut().seg_list.pop_front(){

        if stream_seg_check(&stream, &seg){
            continue;// here, we could break, then we have two LinkedList, then append it.
        }

        tmp_seg_list.push_back(seg);
    }

    stream.borrow_mut().seg_list.append(&mut tmp_seg_list);

    return;
}

fn get_stream_move_len(ssn: & Rc<RefCell<TcpSession>>, stream: &Rc<RefCell<Stream>>)-> u32{
    return 1;
}

// ret true, cannot del seg
fn stream_seg_check(stream: &Rc<RefCell<Stream>>, stream_seg: &StreamSeg) -> bool{
    if stream_seg_in_use(stream){
        return true;
    }

    if stream_seg.seq + stream_seg.payload <= stream.borrow().base_seq{
        return false;
    }

    return true;
}

fn stream_seg_in_use(stream: & Rc<RefCell<Stream>>)->bool{

    if !check_flag!(stream.borrow().stream_flags, (STREAM_FLAGS_GAP|STREAM_FLAGS_NOREASSEMBLY)){
        if !check_flag!(stream.borrow().stream_flags, STREAM_FLAGS_APPPROTO_DETECTION_COMPLETED){
            return true;
        }
    }

    return false;
}

fn stream_state_dispatch(packet: &mut Packet, tcp: & Rc<Tcp>, flow:& Arc<RwLock<Flow>>, ssn: & Rc<RefCell<TcpSession>>, stream: & Rc<RefCell<Stream>>) -> bool{

    match ssn.borrow().state{
        TCP_SSN_SYN_SENT => { return stream_state_syn_sent(packet, tcp, flow, ssn, stream); },
        TCP_SSN_RECV => { return stream_state_syn_recv(packet, tcp, flow, ssn, stream); },
        TCP_SSN_ESTABLISHED => { return stream_state_established(); },
        TCP_SSN_FIN_WAIT1 => { return stream_state_fin_wait1(); },
        TCP_SSN_FIN_WAIT2 => { return stream_state_fin_wait2(); },
        TCP_SSN_CLOSING => { return stream_state_closing(); },
        TCP_SSN_CLOSE_WAIT => { return stream_state_close_wait(); },
        TCP_SSN_LAST_ACK => { return stream_state_last_ack(); },
        TCP_SSN_TIME_WAIT => { return stream_state_time_wait(); },
        TCP_SSN_CLOSED => { return stream_state_closed(); },
    }

    return true;
}


fn stream_lastack_great_than_baseseq(stream: &Rc<RefCell<Stream>>) -> bool{
    if stream.borrow().last_ack == 0{
        return false;
    }

    if stream.borrow().last_ack > stream.borrow().base_seq{
        return true;
    }

    return false;
}

/***************************************************************************************************/


impl PartialEq for FIRST_DIR{
    fn eq(&self, other: &FIRST_DIR) -> bool{
        match self{
            FIRST_NONE => {if let FIRST_NONE = other{true}else{false}},
            FIRST_TOSERVER => {if let FIRST_TOSERVER = other{true}else{false}},
            FIRST_TOCLIENT => {if let FIRST_TOCLIENT = other{true}else{false}},
        }
    }
}

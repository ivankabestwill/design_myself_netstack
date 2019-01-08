

use std::fmt::{Display, Result, Formatter};
use std::hash::{Hash};
use std::rc::Rc;
use std::cell::RefCell;

use ::config::{tcp_assem_config};
use ::tcp::{Tcp, TCP_WSCALE_MAX, TCP_FLAGS_NONE, TCP_FLAGS_SYN, TCP_FLAGS_RST, TCP_FLAGS_URG,
            TCP_FLAGS_FIN, TCP_FLAGS_ACK, TCP_FLAGS_PSH, TCP_FLAGS_TYPE};
use ::thread::{ThreadVar};
use ::flow::{Flow, TransportInfo, FLOW_STATE_ESTABLISHED, FLOW_STATE_CLOSED};

use self::TransportInfo::{TransportTcp, TransportUdp, TransportNone};
use ::flow::{Packet, PACKET_FLAGS_TOSERVER, PACKET_FLAGS_TOCLIENT, PACKET_FLAGS_TOCLIENT_FIRST,
             PACKET_FLAGS_TOSERVER_FIRST, PACKET_FLAGS_PSEUDO_STREAM_END, packet_switch_dir};

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
    pub buf: Rc<Vec<u8>>,
    pub seq: u32,
    rang_start: u32,
    rang_end: u32,
    pub prev: Option<Rc<RefCell<StreamSeg>>>,
    pub next: Option<Rc<RefCell<StreamSeg>>>,
}

fn tcp_new_stream_seg()->StreamSeg{
    StreamSeg{
        buf: Rc::new(Vec::new()),
        seq: 0,
        rang_start: 0,
        rang_end: 0,
        prev: None,
        next: None,
    }
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
    pub seg_list: Option<Rc<RefCell<StreamSeg>>>,
    pub seg_list_tail: Option<Rc<RefCell<StreamSeg>>>,
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

pub fn tcp_new_stream(tcp: &Tcp) -> Stream{
    Stream{
        seg_list: None,
        seg_list_tail: None,
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

pub fn tcp_new_session(tcp: &Tcp) -> TcpSession{
    let stream_from_server = tcp_new_stream(tcp);
    let stream_from_client = tcp_new_stream(tcp);

    TcpSession{
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
    }
}

/*{
let stream = tcp_new_stream(tcp);

flow.transport_info = TransportInfo::transport_tcp(steam);

return;

}*/



pub fn ssn_set_packet_state(flow: &mut Flow, ssn: &mut TcpSession, state: TCP_SSN_STATE){
    ssn.pstate = ssn.state;
    ssn.state = state;
    match ssn.state{
        TCP_SSN_ESTABLISHED|TCP_SSN_FIN_WAIT1|TCP_SSN_FIN_WAIT2|TCP_SSN_CLOSING|TCP_SSN_CLOSE_WAIT => {
            flow.state = FLOW_STATE_ESTABLISHED;
        },
        TCP_SSN_LAST_ACK|TCP_SSN_TIME_WAIT|TCP_SSN_CLOSED => {
            flow.state = FLOW_STATE_CLOSED;
        },
        _ => {},
    }
}

fn stream_seg_befor_offset(stream_seg: &StreamSeg, stream: &Stream, offset: u32) -> bool{
    if stream_get_seg_offset(stream, stream_seg) + stream_seg.buf.len() as u32 <= offset{
        return true;
    }else{
        return false;
    }
}

fn stream_get_seg_offset(stream: &Stream, stream_seg: &StreamSeg) -> STREAM_OFFSET_TYPE{
    return stream_seg.seq - stream.base_seq - stream.base_offset;
}

fn stream_get_applayer_progress_offset(stream: &Stream) -> STREAM_OFFSET_TYPE{
    return stream.base_offset + stream.app_progress_real;
}

fn stream_get_applayer_data(stream: &Stream, app_progress: STREAM_OFFSET_TYPE) -> Rc<Vec<u8>>{

    Rc::new(Vec::new())
}

enum STREAM_TO_APPLAYER{
    None, // no new data, mabe a gap
    Gap(STREAM_OFFSET_TYPE), // gap happened, value means gap len
    Seg(Rc<RefCell<StreamSeg>>), // data
}

fn stream_get_one_seg_from_offset(stream: &Stream, offset: STREAM_OFFSET_TYPE) ->STREAM_TO_APPLAYER{
    if offset < stream.base_offset{
        // suricata return. ignore anything.
        // this mabe some probrem. we need return gap, and reset offset to base_offset
        return STREAM_TO_APPLAYER::Gap(stream.base_offset-offset);
    }else{
        match stream.seg_list{
            None => {
              return STREAM_TO_APPLAYER::None;
            },
            Some(ref sg) => {
                let diff = stream_get_seg_offset(stream, &(*sg.borrow())) - offset;
                if diff > 0{
                    return STREAM_TO_APPLAYER::Gap(diff);
                }else{
                    if offset <= (stream_get_seg_offset(stream, &(*sg.borrow())) + sg.borrow().buf.len() as u32) &&
                        offset > stream_get_seg_offset(stream, &(*sg.borrow())){

                    }

                    return STREAM_TO_APPLAYER::Seg(Rc::clone(&sg));
                }
            },
        }
    }
}


// this_dir: which dir to update.
fn stream_reassemble_applayer(packet: &Packet, flow:&mut Flow, ssn: &TcpSession, stream: &mut Stream, this_dir: bool) -> bool{

    if check_flag!(ssn.stream_flags, STREAM_FLAGS_APPLAYER_DISABLED) ||
        check_flag!(stream.stream_flags, STREAM_FLAGS_NO_REASSEMBLY){
        return true;
    }

    let seg_tail = stream.seg_list_tail.clone();

    if let None = seg_tail {
        if (ssn.state >= TCP_SSN_CLOSED) || (check_flag!(packet.flags, PACKET_FLAGS_PSEUDO_STREAM_END)) {
            let tmp_flags = get_applayer_flag_from_stream(packet, ssn, stream, this_dir);
            stream_applayer_hand_tcp_data(flow, ssn, stream, tmp_flags, APPLAYER_DATA::APPLAYER_DATA_NONE);
            return true;
        }
    }else if let Some(ref seg_tail) = seg_tail{
        if stream_seg_befor_offset(&mut (*seg_tail.borrow_mut()), stream, stream_get_applayer_progress_offset(stream)) {
            if (ssn.state >= TCP_SSN_CLOSED) || (check_flag!(packet.flags, PACKET_FLAGS_PSEUDO_STREAM_END)) {
                let tmp_flags = get_applayer_flag_from_stream(packet, ssn, stream, this_dir);
                stream_applayer_hand_tcp_data(flow, ssn, stream, tmp_flags, APPLAYER_DATA::APPLAYER_DATA_NONE);
                return true;
            }
        }
    }

    let mut to_applayer_seg: StreamSeg = tcp_new_stream_seg();
    let mut app_progress = stream_get_applayer_progress_offset(stream);
    let mut data_len = 0;

    loop {

        let (stream_seg, seg_gap_len) = stream_get_seg_by_offset(stream, app_progress);
        if let Some(seg) = stream_seg {

            data_len = seg.rang_end - seg.rang_start;
            to_applayer_seg = seg;
            break;
        } else if let Some(gap_len) = seg_gap_len {
            let tmp_flags = get_applayer_flag_from_stream(packet, ssn, stream, this_dir)|APPLAYER_FLAGS_STREAM_GAP;
            stream_applayer_hand_tcp_data(flow, ssn, stream, tmp_flags, APPLAYER_DATA::APPLAYER_DATA_GAP(gap_len));

            stream.app_progress_real += gap_len;
            app_progress += data_len;
        }else{
            return true;
        }
    }

    let data = &to_applayer_seg.buf[to_applayer_seg.rang_start as usize..to_applayer_seg.rang_end as usize];

    if !check_flag!(packet.flags, PACKET_FLAGS_PSEUDO_STREAM_END){
        let mut last_ack_abs = app_progress;
        if stream_lastack_great_than_baseseq(stream){
            let delta = stream.last_ack - stream.base_seq;
            if delta > 10000000 && delta > stream.window as u32{
                error!("suricata exit here, some error must happened.");
                return false;
            }
            last_ack_abs += delta;
        }

        if app_progress + data_len > last_ack_abs{
            let check = data_len;
            data_len = last_ack_abs - app_progress;
            if data_len > check{
                error!("suricata exit here, some error must happened.");
                return false;
            }
        }
    }

    let tmp_flags = get_applayer_flag_from_stream(packet, ssn, stream, this_dir);
    if stream_applayer_hand_tcp_data(flow, ssn, stream, tmp_flags, APPLAYER_DATA::APPLAYER_DATA_SLICE(data)){
        if (data_len > 0) && check_flag!(stream.stream_flags, STREAM_FLAGS_APPPROTO_DETECTION_COMPLETED){
            stream.app_progress_real += data_len;
            debug!("app progress now {}", stream.app_progress_real);
        }else{
            debug!("NOT UPDATED app progress still {}", app_progress);
        }
    }

    return true;
}

fn stream_get_seg_by_offset(stream: &Stream, offset: STREAM_OFFSET_TYPE) -> (Option<StreamSeg>, Option<STREAM_OFFSET_TYPE>){
    if offset < stream.base_offset{
        return (None, Some(stream.base_offset-offset));
    }else{
        let mut node = stream.seg_list.clone();
        while let Some(n) = node{

            let seg_offset = stream_get_seg_offset(stream, &(*n.borrow()));

            if (offset >= seg_offset) && (offset < seg_offset+n.borrow().buf.len() as u32){
                let mut r_seg: StreamSeg = StreamSeg{
                    seq: n.borrow().seq,
                    next: None,
                    prev: None,
                    buf: Rc::clone(&n.borrow().buf),
                    rang_start: 0,
                    rang_end: n.borrow().buf.len() as u32,
                };

                // send to applayer stream seg may be part of this real seg
                r_seg.rang_start = offset - seg_offset;

                return (Some(r_seg), None);
            }else if seg_offset > offset{
                return (None, Some(seg_offset - offset));
            }

            node = n.borrow().next.clone();
        }
    }

    return (None, None);
}

fn stream_depth_check(stream_seg: &mut StreamSeg, stream: &mut Stream){

}

fn stream_handle_segment_insert(packet: &mut Packet, tcp: &mut Tcp, stream: &mut Stream, mut stream_seg: StreamSeg) -> bool{



    // suricata os policy


    // reassemble depth check
    stream_depth_check(&mut stream_seg, stream);

    let rc_ref_stream_seg = Rc::new(RefCell::new(stream_seg));

    if let Some(_) = stream.seg_list_tail{
        let mut node = stream.seg_list_tail.clone();

        while let Some(seg) = node{
            if rc_ref_stream_seg.borrow().seq >= seg.borrow().seq{
                if (rc_ref_stream_seg.borrow().seq + rc_ref_stream_seg.borrow().buf.len() as u32) >
                    (seg.borrow().seq + seg.borrow().buf.len() as u32){

                    // cannot cover the next
                    if let Some(ref s) = seg.borrow().next{
                        if rc_ref_stream_seg.borrow().seq + rc_ref_stream_seg.borrow().buf.len() as u32 > s.borrow().seq{
                            return false;
                        }
                    }
                    if rc_ref_stream_seg.borrow().seq < seg.borrow().seq + seg.borrow().buf.len() as u32{
                        let cut_len = seg.borrow().seq + seg.borrow().buf.len() as u32 - rc_ref_stream_seg.borrow().seq;
                        if cut_len >= rc_ref_stream_seg.borrow().buf.len() as u32{
                            return false;
                        }

                        let mut tmp_buf = &rc_ref_stream_seg.borrow_mut().buf;
                        let mut tmp_slice = &tmp_buf[cut_len as usize..];
                        let mut tmp_vec = tmp_slice.to_vec();
                        let mut tmp_rc = Rc::new(tmp_vec);
                        rc_ref_stream_seg.borrow_mut().buf = tmp_rc;
                    }

                    rc_ref_stream_seg.borrow_mut().prev = Some(Rc::clone(& seg));
                    if let None = seg.borrow().next{
                        stream.seg_list_tail = Some(Rc::clone(&rc_ref_stream_seg));
                    }
                    seg.borrow_mut().next = Some(Rc::clone(&rc_ref_stream_seg));

                    return true;
                }
                return false;
            }

            // insert into the prev
            node = seg.borrow().prev.clone();
        }
        // just insert into the first.
        let tmp_seg = Rc::clone(&rc_ref_stream_seg);

        tmp_seg.borrow_mut().next = stream.seg_list.clone();
        stream.seg_list = Some(Rc::clone(&tmp_seg));

        return true;
    }else{
        stream.seg_list_tail = Some(Rc::clone(&rc_ref_stream_seg));
        stream.seg_list = Some(Rc::clone(&rc_ref_stream_seg));
        return true;
    }
}

fn stream_handle_segment_update_by_ack(packet: &Packet, flow:&mut Flow, ssn: &mut TcpSession, stream: &mut Stream) -> bool{
    return stream_reassemble_applayer(packet, flow, ssn, stream, false);
}

fn new_stream_seg_from_tcp(tcp: &Tcp) -> StreamSeg{
    StreamSeg{
        buf: Rc::clone(&tcp.buf),
        seq: tcp.seq,
        rang_start: 0,
        rang_end: tcp.buf.len() as u32,
        prev: None,
        next: None,
    }
}
/*
1. insert new seg with data into streamseg
2. triggered by ACK, update streamseg to applayer
*/
pub fn session_handle_stream_segment(packet: &mut Packet, flow:&mut Flow, tcp: &mut Tcp, ssn: &mut TcpSession, stream: &Stream){

    debug!("{} {} {}", ssn, stream, packet);

    let mut stream_push_to_applayer = false;

    let operation_stream = if (packet.flags & PACKET_FLAGS_TOSERVER)!=0{
        Rc::clone(&ssn.server_stream)
    }else{
        Rc::clone(&ssn.client_stream)
    };

    if check_flag!(packet.flags, PACKET_FLAGS_PSEUDO_STREAM_END){
        stream_push_to_applayer = true;
    }else if check_flag!(tcp.flags, TCP_FLAGS_RST){
        stream_push_to_applayer = true;
    }else if ((tcp.flags & TCP_FLAGS_FIN) != 0) && (ssn.state > TCP_SSN_TIME_WAIT){
        stream_push_to_applayer = true;
    }

    let stream_seg = new_stream_seg_from_tcp(tcp);

    if !stream_push_to_applayer{
        if let false = stream_handle_segment_update_by_ack(packet, flow, ssn, &mut (operation_stream.borrow_mut())){
            println!("session_handle_segment_update_by_ack fail.");
            return;
        }
    }

    if tcp.buf.len() > 0 && check_flag!(stream.stream_flags, STREAM_FLAGS_NOREASSEMBLY) {
        if let false = stream_handle_segment_insert(packet, tcp, &mut (operation_stream.borrow_mut()), stream_seg) {
            error!("session_handle_segment_insert fail.");
            return;
        }
    }else{
        warn!("{} {} {} not calling stream_handle_segment_insert.", ssn, stream, packet)
    }

    if stream_push_to_applayer{
        if let false = stream_reassemble_applayer(packet, flow, ssn, &mut (operation_stream.borrow_mut()), true){
            println!("stream_reassemble_applayer fail.");
            return;
        }
    }

    return;
}

// for a new stream or closed stream.
fn session_handle_state_none(packet: &mut Packet, tcp: &mut Tcp, flow: &mut Flow, ssn: &mut TcpSession, stream: &mut Stream) -> bool{

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
        add_flag!(ssn.stream_flags, STREAM_FLAGS_MIDSTREAM);
        add_flag!(ssn.stream_flags, STREAM_FLAGS_MIDSTREAM_SYNACK);
        if tcp_assem_config.async_oneside{
            add_flag!(ssn.stream_flags, STREAM_FLAGS_ASYNC);
        }

        ssn.server_stream.borrow_mut().isn = tcp.seq;
        ssn.server_stream.borrow_mut().base_seq = tcp.seq + 1;
        ssn.server_stream.borrow_mut().next_seq = tcp.seq + 1;
        ssn.server_stream.borrow_mut().window = tcp.win;


        ssn.client_stream.borrow_mut().isn = tcp.ack - 1;
        ssn.client_stream.borrow_mut().base_seq = tcp.ack;
        ssn.client_stream.borrow_mut().next_seq = tcp.ack;

        ssn.client_stream.borrow_mut().last_ack = tcp.ack;
        ssn.server_stream.borrow_mut().last_ack = tcp.seq;

        ssn.server_stream.borrow_mut().next_win = ssn.server_stream.borrow().last_ack + ssn.server_stream.borrow().window as u32;

        if TCP_HAS_WSCALE!(tcp){
            ssn.client_stream.borrow_mut().wscale = TCP_GET_WSCALE!(tcp);
            ssn.server_stream.borrow_mut().wscale = TCP_WSCALE_MAX;
            debug!("{} wscale enabled, client {} server {}", ssn,
                ssn.client_stream.borrow().wscale, ssn.server_stream.borrow().wscale)
        }

        debug!("{} client isn {} next_seq {}", ssn, ssn.client_stream.borrow().isn,
                ssn.client_stream.borrow().next_seq);
        debug!("{} server isn {} next_seq {}", ssn, ssn.server_stream.borrow().isn,
               ssn.server_stream.borrow().next_seq);

        if TCP_HAS_TS!(tcp){
            ssn.server_stream.borrow_mut().last_ts = TCP_GET_TS!(tcp);
            ssn.client_stream.borrow_mut().last_ts = TCP_GET_TSECR!(tcp);
            debug!("{} server last_ts {} client last_ts {}", ssn,
                ssn.server_stream.borrow().last_ts, ssn.client_stream.borrow().last_ts);
            add_flag!(ssn.stream_flags, STREAM_FLAGS_TIMESTAMP);

            ssn.server_stream.borrow_mut().last_pkt_ts = packet.ts;
            if ssn.server_stream.borrow().last_ts == 0{
                add_flag!(ssn.server_stream.borrow_mut().stream_flags, STREAM_FLAGS_ZERO_TIMESTAMP);
            }
            if ssn.client_stream.borrow().last_ts == 0{
                add_flag!(ssn.client_stream.borrow_mut().stream_flags, STREAM_FLAGS_ZERO_TIMESTAMP);
            }
        }else{
            ssn.server_stream.borrow_mut().last_ts = 0;
            ssn.client_stream.borrow_mut().last_ts = 0;
        }

        if TCP_HAS_SACKOK!(tcp){
            add_flag!(ssn.stream_flags, STREAM_FLAGS_SACKOK);
        }

        packet_switch_dir(packet);

    }else if (tcp.flags & TCP_FLAGS_SYN) != 0{

        ssn_set_packet_state( flow, ssn, TCP_SSN_SYN_SENT);

        if tcp_assem_config.async_oneside{
            debug!("{} ASYNC", ssn);
            add_flag!(ssn.stream_flags, STREAM_FLAGS_ASYNC);
        }

        ssn.client_stream.borrow_mut().isn = tcp.seq;
        ssn.client_stream.borrow_mut().base_seq = tcp.seq + 1;
        ssn.client_stream.borrow_mut().next_seq = tcp.seq + 1;

        if TCP_HAS_TS!(tcp){
            ssn.client_stream.borrow_mut().last_ts = TCP_GET_TS!(tcp);
            if ssn.client_stream.borrow().last_ts == 0{
                add_flag!(ssn.client_stream.borrow_mut().stream_flags, STREAM_FLAGS_ZERO_TIMESTAMP);
            }

            ssn.client_stream.borrow_mut().last_pkt_ts = packet.ts;
            add_flag!(ssn.client_stream.borrow_mut().stream_flags, STREAM_FLAGS_TIMESTAMP);
        }

        ssn.server_stream.borrow_mut().window = tcp.win;

        if TCP_HAS_WSCALE!(tcp){
            add_flag!(ssn.stream_flags, STREAM_FLAGS_SERVER_WSCALE);
            ssn.server_stream.borrow_mut().wscale = TCP_GET_WSCALE!(tcp);
        }

        if TCP_HAS_SACKOK!(tcp){
            add_flag!(ssn.stream_flags, STREAM_FLAGS_CLIENT_SACKOK);
        }

        debug!("{} client isn {} next_seq {} last_ack {}", ssn,
            ssn.client_stream.borrow().isn, ssn.client_stream.borrow().next_seq,
               ssn.client_stream.borrow().last_ack);

    }else if (tcp.flags & TCP_FLAGS_ACK) != 0{

        if !tcp_assem_config.mid_stream{
            return false;
        }

        ssn_set_packet_state( flow, ssn, TCP_SSN_ESTABLISHED);

        add_flag!(ssn.stream_flags, STREAM_FLAGS_MIDSTREAM);
        add_flag!(ssn.stream_flags, STREAM_FLAGS_MIDSTREAM_ESTABLISHED);

        if tcp_assem_config.async_oneside{
            add_flag!(ssn.stream_flags, STREAM_FLAGS_ASYNC);
        }

        ssn.client_stream.borrow_mut().wscale = TCP_WSCALE_MAX;
        ssn.server_stream.borrow_mut().wscale = TCP_WSCALE_MAX;

        ssn.client_stream.borrow_mut().isn = tcp.seq - 1;
        ssn.client_stream.borrow_mut().base_seq = tcp.seq;
        ssn.client_stream.borrow_mut().next_seq = tcp.seq + tcp.buf.len() as u32;
        ssn.client_stream.borrow_mut().window = tcp.win << ssn.client_stream.borrow().wscale;
        ssn.client_stream.borrow_mut().last_ack = tcp.seq;
        ssn.client_stream.borrow_mut().next_win = ssn.client_stream.borrow().last_ack + ssn.client_stream.borrow().window as u32;
        debug!("{} client isn {} next_seq {}", ssn, ssn.client_stream.borrow().isn, ssn.client_stream.borrow().next_seq);

        ssn.server_stream.borrow_mut().isn = tcp.ack - 1;
        ssn.server_stream.borrow_mut().base_seq = tcp.ack;
        ssn.server_stream.borrow_mut().next_seq = tcp.ack;
        ssn.server_stream.borrow_mut().last_ack = tcp.ack;
        ssn.server_stream.borrow_mut().next_win = ssn.server_stream.borrow().last_ack;
        debug!("{} client next_win {} server next_win {}", ssn,
            ssn.client_stream.borrow().next_win, ssn.server_stream.borrow().next_win);

        debug!("{} client last_ack {} server last_ack {}", ssn,
            ssn.client_stream.borrow().last_ack, ssn.server_stream.borrow().last_ack);

        if TCP_HAS_TS!(tcp){
            ssn.client_stream.borrow_mut().last_ts = TCP_GET_TS!(tcp);
            ssn.server_stream.borrow_mut().last_ts = TCP_GET_TSECR!(tcp);
            debug!("{} server last_ts {} client last_ts {}", ssn,
                ssn.server_stream.borrow().last_ts, ssn.client_stream.borrow().last_ts);

            add_flag!(ssn.stream_flags, STREAM_FLAGS_TIMESTAMP);

            ssn.client_stream.borrow_mut().last_pkt_ts = packet.ts;
            if ssn.server_stream.borrow().last_ts == 0{
                add_flag!(ssn.server_stream.borrow_mut().stream_flags, STREAM_FLAGS_ZERO_TIMESTAMP);
            }
            if ssn.client_stream.borrow().last_ts == 0{
                add_flag!(ssn.client_stream.borrow_mut().stream_flags, STREAM_FLAGS_ZERO_TIMESTAMP);
            }
        }else{
            ssn.server_stream.borrow_mut().last_ts = 0;
            ssn.client_stream.borrow_mut().last_ts = 0;
        }

        session_handle_stream_segment(packet, flow, tcp, ssn, stream);

        add_flag!(ssn.stream_flags, STREAM_FLAGS_SACKOK);
    }else{
        debug!("default case");
    }

    return true;
}

fn stream_packet_is_keepalive_ack(packet: &Packet, tcp: &Tcp, ssn: &TcpSession) -> bool{
    return true;
}
fn stream_packet_is_keepalive(packet: &Packet, tcp: &Tcp, ssn: &TcpSession, stream: &mut Stream) -> bool{
    if tcp.buf.len() > 0{
        return false;
    }

    if (tcp.flags & (TCP_FLAGS_SYN|TCP_FLAGS_FIN|TCP_FLAGS_RST)) != 0{
        return false;
    }

    let seq = tcp.seq;
    let ack = tcp.ack;

    if check_flag!(packet.flags, PACKET_FLAGS_TOSERVER){
        if (ack == ssn.server_stream.borrow().last_ack) &&
            (seq == (ssn.client_stream.borrow().next_seq - 1)){
            add_flag!(stream.stream_flags, STREAM_FLAGS_KEEPALIVE);
            return true;
        }
    }

    return false;
}

pub fn tcp_session_hand(packet: &mut Packet, tcp: Rc<RefCell<Tcp>>, flow: Rc<RefCell<Flow>>){

    let ssn = match flow.borrow().transport_info{
        TransportNone => {
            let mut s = tcp_new_session(&(*tcp.borrow()));
            let tmp_ssn = Rc::new(RefCell::new(s));
            Rc::clone(&tmp_ssn)
        },
        TransportTcp(ref tmp_ssn) => {
            Rc::clone(tmp_ssn)
        },
        _ =>{
            println!("when tcp_session_handle, flow->transport_info is not tcp or none, errors.");
            return;
        },
    };

    let server_stream = Rc::clone(&ssn.borrow().server_stream);
    let client_stream = Rc::clone(&ssn.borrow().client_stream);

    ssn.borrow_mut().tcp_flags |= tcp.borrow().flags;
    if check_flag!(packet.flags, PACKET_FLAGS_TOSERVER){
        server_stream.borrow_mut().tcp_flags |= tcp.borrow().flags;
    }else{
        client_stream.borrow_mut().tcp_flags |= tcp.borrow().flags;
    }

    if check_flag!(ssn.borrow().stream_flags, STREAM_FLAGS_ASYNC) &&
        client_stream.borrow().tcp_flags != 0 &&
        server_stream.borrow().tcp_flags != 0{

        debug!("{} removing ASYNC flag as we have packets on both sides.", ssn.borrow());
        del_flag!(ssn.borrow_mut().stream_flags, STREAM_FLAGS_ASYNC);
    }

    if check_flag!(tcp.borrow().flags, TCP_FLAGS_SYN|TCP_FLAGS_ACK){
        ssn.borrow_mut().ssn_static.SynAckCnt += 1;
    }else if check_flag!(tcp.borrow().flags, TCP_FLAGS_SYN){
        ssn.borrow_mut().ssn_static.SynCnt += 1;
    }

    if check_flag!(tcp.borrow().flags, TCP_FLAGS_RST){
        ssn.borrow_mut().ssn_static.RstCnt += 1;
    }

    if !check_flag!(tcp.borrow().flags, TCP_FLAGS_ACK) &&
        tcp.borrow().ack != 0{
        ; // StreamTcpSetEvent(tcp,STREAM_PKT_BROKEN_ACK)  follow suricata
    }

    // check ips mode follow suricata

    if ssn.borrow().first_ssn_dir == FIRST_DIR::FIRST_NONE{
        if check_flag!(packet.flags, PACKET_FLAGS_TOSERVER){
            ssn.borrow_mut().first_ssn_dir = FIRST_DIR::FIRST_TOSERVER;
        }else if check_flag!(packet.flags, PACKET_FLAGS_TOCLIENT){
            ssn.borrow_mut().first_ssn_dir = FIRST_DIR::FIRST_TOCLIENT;
        }else{
            error!("tcp_session_hand: packet dir is not set, error.");
            return;
        }
    }

    if ssn.borrow().state == TCP_SSN_NONE{

        let stream = if (packet.flags & PACKET_FLAGS_TOSERVER) != 0{
            Rc::clone(&ssn.borrow().server_stream)
        }else if (packet.flags & PACKET_FLAGS_TOCLIENT) != 0{
            Rc::clone(&ssn.borrow().client_stream)
        }else{
            println!("tcp_session_hand: packet dir is not set, error.");
            return;
        };

        if!(session_handle_state_none(packet,&mut (*tcp.borrow_mut()), &mut (* flow.borrow_mut()), &mut (*ssn.borrow_mut()), &mut (*stream.borrow_mut()))){
            return;
        }
    }else{
        let stream = if (packet.flags & PACKET_FLAGS_TOSERVER) != 0{
            Rc::clone(&ssn.borrow().server_stream)
        }else if (packet.flags & PACKET_FLAGS_TOCLIENT) != 0{
            Rc::clone(&ssn.borrow().client_stream)
        }else{
            println!("tcp_session_hand: packet dir is not set, error.");
            return;
        };

        ssn.borrow_mut().tcp_flags |= tcp.borrow().flags;
        stream.borrow_mut().tcp_flags |= tcp.borrow().flags;


        if check_flag!(ssn.borrow().stream_flags, STREAM_FLAGS_ASYNC) &&
            server_stream.borrow().tcp_flags != 0 &&
            client_stream.borrow().tcp_flags != 0 {

            del_flag!(ssn.borrow_mut().stream_flags, STREAM_FLAGS_ASYNC);
        }

        if check_flag!(ssn.borrow().stream_flags, STREAM_FLAGS_MIDSTREAM_SYNACK){
            packet_switch_dir(packet);
        }

        if stream_packet_is_keepalive(packet, &mut (*tcp.borrow_mut()), &(*ssn.borrow()), &mut (*stream.borrow_mut())){
            stream_packet_check_post_rst(&mut (*tcp.borrow_mut()), &(*ssn.borrow()), &mut (*stream.borrow_mut()));
            return;
        }

        if(stream_packet_is_keepalive_ack(packet, &mut (*tcp.borrow_mut()), &(*ssn.borrow()))){
            del_flag!(stream.borrow_mut().stream_flags, STREAM_FLAGS_KEEPALIVE);
            stream_packet_check_post_rst(&mut (*tcp.borrow_mut()), &(*ssn.borrow()), &mut (*stream.borrow_mut()));
            return;
        }

        if stream_packet_is_fin_shutdown_ack(packet,&(*tcp.borrow()), &(*ssn.borrow()) ){
            if stream_packet_is_window_update(packet, &(*tcp.borrow()), &(*ssn.borrow()) ) {
                if stream_packet_is_bad_window_update(packet, &(*tcp.borrow()), &(*ssn.borrow()) ) {
                    stream_packet_check_post_rst(&mut (*tcp.borrow_mut()), &(*ssn.borrow()), &mut (*stream.borrow_mut()));
                    return;
                }
            }
        }
        if check_flag!(stream.borrow().stream_flags, STREAM_FLAGS_KEEPALIVE){
            del_flag!(stream.borrow_mut().stream_flags, STREAM_FLAGS_KEEPALIVE);
        }

        if !(stream_state_dispatch(packet, &mut (*tcp.borrow_mut()), &mut (*flow.borrow_mut()),&mut (*ssn.borrow_mut()), &mut (*stream.borrow_mut()))) {
            return;
        }

        stream_packet_check_post_rst(&mut (*tcp.borrow_mut()), &(*ssn.borrow()), &mut (*stream.borrow_mut()));
    }

    return;
}

fn stream_packet_is_window_update(packet: &Packet, tcp: &Tcp, ssn: &TcpSession) -> bool{
    if ssn.state < TCP_SSN_ESTABLISHED{
        return false;
    }

    if tcp.buf.len() > 0{
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
        (Rc::clone(&ssn.server_stream), Rc::clone(&ssn.client_stream))
    }else{
        (Rc::clone(&ssn.client_stream), Rc::clone(&ssn.server_stream))
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

fn stream_packet_is_bad_window_update(packet: &Packet, tcp: &Tcp, ssn: &TcpSession) -> bool{
    if (ssn.state < TCP_SSN_ESTABLISHED) || (ssn.state == TCP_SSN_CLOSED){
        return false;
    }

    if check_flag!(tcp.flags, (TCP_FLAGS_SYN|TCP_FLAGS_FIN|TCP_FLAGS_RST)){
        return false;
    }

    let seq = tcp.seq;
    let ack = tcp.ack;

    let (stream, ostream) = if check_flag!(packet.flags, PACKET_FLAGS_TOSERVER){
        (Rc::clone(&ssn.server_stream), Rc::clone(&ssn.client_stream))
    }else{
        (Rc::clone(&ssn.client_stream), Rc::clone(&ssn.server_stream))
    };

    let pkt_win = tcp.win << ostream.borrow().wscale;

    if pkt_win < ostream.borrow().window{
        let diff = ostream.borrow().window - pkt_win;
        if (diff > tcp.buf.len() as u16 ) &&
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

fn stream_packet_is_fin_shutdown_ack(packet: &Packet, tcp: &Tcp, ssn: &TcpSession) -> bool{

    if!(ssn.state == TCP_SSN_TIME_WAIT || ssn.state == TCP_SSN_CLOSE_WAIT || ssn.state == TCP_SSN_LAST_ACK){
        return false;
    }

    if (tcp.flags != TCP_FLAGS_ACK){
        return false;
    }

    if(tcp.buf.len() > 0){
        return false;
    }

    let seq = tcp.seq;
    let ack = tcp.ack;

    let (stream, ostream) = if check_flag!(packet.flags, PACKET_FLAGS_TOSERVER){
        (Rc::clone(&ssn.server_stream), Rc::clone(&ssn.client_stream))
    }else{
        (Rc::clone(&ssn.client_stream), Rc::clone(&ssn.server_stream))
    };


    if((stream.borrow().next_seq + 1)==seq) &&
        (ack == (ostream.borrow().next_seq + 1)){
        return true;
    }

    return false;
}

fn stream_packet_check_post_rst(tcp: &Tcp, ssn: &TcpSession, stream: &mut Stream){
    if check_flag!(tcp.flags, TCP_FLAGS_RST){
        return;
    }

    if check_flag!(stream.stream_flags, STREAM_FLAGS_RST_RECV) {
        del_flag!(stream.stream_flags, STREAM_FLAGS_RST_RECV);
        return;
    }

    return;
}

fn stream_release_all_segment(stream: &mut Stream){
    let mut node = stream.seg_list.clone();
    stream.seg_list = None;
    stream.seg_list_tail = None;

    while let Some(n) = node{

        node = n.borrow().next.clone();
        n.borrow_mut().next = None;
        n.borrow_mut().prev = None;
    }
}

// check app progress and raw progress and progresses if needed. gets rid of segments
pub fn tcp_stream_release_segment(packet: &Packet){

    let ssn = if let Some(ref flow) = packet.flow{
        if let TransportTcp(ref s) = flow.borrow().transport_info{
            Rc::clone(s)
        }else{
            return;
        }
    }else{
        return;
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
        stream_release_all_segment(&mut (*stream.borrow_mut()));
        return;
    }else if (((stream.borrow().stream_flags & STREAM_FLAGS_GAP) != 0) ||
        (ssn.borrow().stream_flags & STREAM_FLAGS_APPLAYER_DISABLED)!=0) &&
        (stream.borrow().stream_flags & STREAM_FLAGS_DISABLE_RAW) != 0{

        add_flag!(stream.borrow_mut().stream_flags, STREAM_FLAGS_NO_REASSEMBLY);
        stream_release_all_segment(&mut (*stream.borrow_mut()));
        return;
    }

    let move_len = get_stream_move_len(&(*ssn.borrow_mut()), &(*stream.borrow_mut()));
    if (move_len > 0) {
        stream.borrow_mut().base_seq += move_len;

        if move_len <= stream.borrow().app_progress_real {
            stream.borrow_mut().app_progress_real -= move_len;
        } else {
            stream.borrow_mut().app_progress_real = 0;
        }
    }

    let mut node = stream.borrow().seg_list.clone();
    while let Some(n) = node{
        if stream_seg_check(&(*stream.borrow()), &(*n.borrow())){
            break;
        }

        if let Some(ref prev) = n.borrow().prev{
            prev.borrow_mut().next = n.borrow().next.clone();
        }else{
            stream.borrow_mut().seg_list = n.borrow().next.clone();
        }

        if let Some(ref next) = n.borrow().next{
            next.borrow_mut().prev = n.borrow().prev.clone();
        }else{
            stream.borrow_mut().seg_list_tail = n.borrow().prev.clone();
        }

        n.borrow_mut().prev = None;
        n.borrow_mut().next = None;

        node = n.borrow().next.clone();
    }

    return;
}

fn get_stream_move_len(ssn: &TcpSession, stream: &Stream)-> u32{
    return 1;
}

// ret true, cannot del seg
fn stream_seg_check(stream: &Stream, stream_seg: &StreamSeg) -> bool{
    if stream_seg_in_use(stream){
        return true;
    }

    if stream_seg.seq + stream_seg.buf.len() as u32 <= stream.base_seq{
        return false;
    }

    return true;
}

fn stream_seg_in_use(stream: &Stream)->bool{
    if !check_flag!(stream.stream_flags, (STREAM_FLAGS_GAP|STREAM_FLAGS_NOREASSEMBLY)){
        if !check_flag!(stream.stream_flags, STREAM_FLAGS_APPPROTO_DETECTION_COMPLETED){
            return true;
        }
    }

    return false;
}

fn stream_state_dispatch(packet: &mut Packet, tcp: &mut Tcp, flow:&mut Flow, ssn: &mut TcpSession, stream: &mut Stream) -> bool{

    match ssn.state{
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


fn stream_lastack_great_than_baseseq(stream: &Stream) -> bool{
    if stream.last_ack == 0{
        return false;
    }

    if stream.last_ack > stream.base_seq{
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

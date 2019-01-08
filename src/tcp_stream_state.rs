extern crate libc;

use std::cmp::PartialEq;

use libc::timeval;

use std::rc::Rc;
use std::cell::RefCell;
use std::sync::{Arc, RwLock};


use ::tcp_stream::{TcpSession, Stream, ssn_set_packet_state};
use ::tcp::{Tcp};
use ::tcp::{TCP_FLAGS_RST, TCP_FLAGS_FIN, TCP_FLAGS_SYN, TCP_FLAGS_ACK};
use ::tcp_stream::{STREAM_FLAGS_ASYNC, STREAM_FLAGS_RST_RECV, STREAM_FLAGS_SERVER_WSCALE, STREAM_FLAGS_SACKOK, STREAM_FLAGS_CLIENT_SACKOK};
use ::packet::{Packet, PACKET_FLAGS_TOSERVER, PACKET_FLAGS_TOCLIENT};
use ::flow::{Flow};

use ::tcp_stream::{STREAM_FLAGS_DETECTION_EVASION_ATTEMPT, STREAM_FLAGS_4WHS, STREAM_FLAGS_TIMESTAMP, STREAM_FLAGS_ZERO_TIMESTAMP};
use ::tcp_stream::{TCP_SSN_ESTABLISHED, TCP_SSN_CLOSED, TCP_SSN_SYN_RECV, session_handle_stream_segment};

/*
TCP_SSN_SYN_SENT => { return stream_state_syn_sent(); },
TCP_SSN_RECV => { return stream_state_syn_recv(); },
TCP_SSN_ESTABLISHED => { return stream_state_established(); },
TCP_SSN_FIN_WAIT1 => { return stream_state_fin_wait1(); },
TCP_SSN_FIN_WAIT2 => { return stream_state_fin_wait2(); },
TCP_SSN_CLOSING => { return stream_state_closing(); },
TCP_SSN_CLOSE_WAIT => { return stream_state_close_wait(); },
TCP_SSN_LAST_ACK => { return stream_state_last_ack(); },
TCP_SSN_TIME_WAIT => { return stream_state_time_wait(); },
TCP_SSN_CLOSED => { return stream_state_closed(); },
*/

const STREAM_QUEUE_FLAG_TS: u8 = 1;
const STREAM_QUEUE_FLAG_WS: u8 = 2;
const STREAM_QUEUE_FLAG_SACK: u8 = 4;

const TCP_WSCALE_MAX: u8 = 14;

#[derive(Clone)]
pub enum os_policy_type
{
    OS_POLICY_NONE,
    OS_POLICY_BSD,
    OS_POLICY_BSD_RIGHT,
    OS_POLICY_OLD_LINUX,
    OS_POLICY_LINUX,
    OS_POLICY_OLD_SOLARIS,
    OS_POLICY_SOLARIS,
    OS_POLICY_HPUX10,
    OS_POLICY_HPUX11,
    OS_POLICY_IRIX,
    OS_POLICY_MACOS,
    OS_POLICY_WINDOWS,
    OS_POLICY_VISTA,
    OS_POLICY_WINDOWS2K3,
    OS_POLICY_FIRST,
    OS_POLICY_LAST
}


use self::os_policy_type::{    OS_POLICY_NONE,
                               OS_POLICY_BSD,
                               OS_POLICY_BSD_RIGHT,
                               OS_POLICY_OLD_LINUX,
                               OS_POLICY_LINUX,
                               OS_POLICY_OLD_SOLARIS,
                               OS_POLICY_SOLARIS,
                               OS_POLICY_HPUX10,
                               OS_POLICY_HPUX11,
                               OS_POLICY_IRIX,
                               OS_POLICY_MACOS,
                               OS_POLICY_WINDOWS,
                               OS_POLICY_VISTA,
                               OS_POLICY_WINDOWS2K3,
                               OS_POLICY_FIRST,
                               OS_POLICY_LAST};

const OS_POLICY_DEFAULT:os_policy_type = OS_POLICY_BSD;

fn stream_set_os_policy(stream: &Rc<RefCell<Stream>>){
    // read from conf file to set stream os policy
    // all set to be default os policy
    stream.borrow_mut().os_policy = OS_POLICY_DEFAULT;
}

fn stream_validate_ack(tcp:&Tcp, ssn: &Rc<RefCell<TcpSession>>, stream: &Rc<RefCell<Stream>>) -> bool{

    return true;
}

fn stream_validate_rst(packet: &Packet, ssn: &Rc<RefCell<TcpSession>>, tcp: &Rc<Tcp>, stream: &Rc<RefCell<Stream>>) -> bool{

    if check_flag!(ssn.borrow().stream_flags, STREAM_FLAGS_TIMESTAMP){
        if !(stream_validate_timestamp(packet, tcp, ssn)){
            return false;
        }
    }

    if stream.borrow().os_policy == OS_POLICY_NONE{
        stream_set_os_policy(stream);
    }

    let os_policy = stream.borrow().os_policy.clone();

    if (tcp.flags & TCP_FLAGS_ACK) != 0 &&
        tcp.ack > 0 &&
        !stream_validate_ack(tcp, ssn, stream){
        return false;
    }

    if (ssn.borrow().stream_flags & STREAM_FLAGS_ASYNC) != 0{
        if tcp.seq >= stream.borrow().next_seq{
            return true;
        }
        return false;
    }

    match os_policy {
        // temply handle os_policy default
        OS_POLICY_BSD => {
            if tcp.seq == stream.borrow().next_seq{
                return true;
            }else{
                return false;
            }
        },
        _ => {},
    };

    return false;
}

pub fn stream_state_syn_recv(packet: &Packet, tcp: &Rc<Tcp>, flow: &Arc<RwLock<Flow>>, ssn: &Rc<RefCell<TcpSession>>, stream: &Rc<RefCell<Stream>>) -> bool{

    if check_flag!(tcp.flags, TCP_FLAGS_RST){
        if !stream_validate_rst(packet, ssn, tcp, stream){
            return false;
        }

        let mut reset = true;
        if check_flag!(ssn.borrow().stream_flags, STREAM_FLAGS_DETECTION_EVASION_ATTEMPT){
            if check_flag!(packet.flags, PACKET_FLAGS_TOSERVER){
                if check_eq_b_b!(ssn, server_stream, os_policy, OS_POLICY_LINUX) ||
                    check_eq_b_b!(ssn, server_stream, os_policy, OS_POLICY_OLD_LINUX) ||
                    check_eq_b_b!(ssn, server_stream, os_policy, OS_POLICY_SOLARIS){

                    reset = false;
                }
            }else{
                if check_eq_b_b!(ssn, client_stream, os_policy, OS_POLICY_LINUX) ||
                    check_eq_b_b!(ssn, client_stream, os_policy, OS_POLICY_OLD_LINUX) ||
                    check_eq_b_b!(ssn, client_stream, os_policy, OS_POLICY_SOLARIS){

                    reset = false;
                }
            }
        }

        if reset{
            ssn_set_packet_state( flow, ssn, TCP_SSN_CLOSED);
            if check_flag!(ssn.borrow().stream_flags, STREAM_FLAGS_TIMESTAMP){
                stream_validate_timestamp(packet, tcp,ssn);
            }
        }
    }else if check_flag!(tcp.flags, TCP_FLAGS_FIN){

    }

    return true;
}



pub fn stream_state_syn_sent(packet:&mut Packet, tcp: & Rc<Tcp>, flow: & Arc<RwLock<Flow>>, ssn: & Rc<RefCell<TcpSession>>, stream: & Rc<RefCell<Stream>>) -> bool{

    // RST
    if (tcp.flags & TCP_FLAGS_RST) != 0{
        if!stream_validate_rst(packet, ssn, tcp, stream){
            return false;
        }

        if check_flag!(packet.flags, PACKET_FLAGS_TOSERVER){
            if  check_eq_b_b!(ssn, client_stream, isn, tcp.seq) &&
                (tcp.win == 0) &&
                (tcp.ack == get_ref_b_b!(ssn,client_stream, isn) + 1){

                add_contain_b_bw!(ssn, server_stream, stream_flags, STREAM_FLAGS_RST_RECV);
                ssn_set_packet_state( flow, ssn, TCP_SSN_CLOSED);
            }
        }else{

            add_contain_b_bw!(ssn, client_stream, stream_flags, STREAM_FLAGS_RST_RECV);
            ssn_set_packet_state( flow, ssn, TCP_SSN_CLOSED);
        }
    // FIN
    }else if (tcp.flags & TCP_FLAGS_FIN) != 0{
        /*nothing to do*/
        ;
    // SYN/ACK
    }else if (tcp.flags & (TCP_FLAGS_SYN|TCP_FLAGS_ACK)) == (TCP_FLAGS_SYN|TCP_FLAGS_ACK){
        if((ssn.borrow().stream_flags & STREAM_FLAGS_4WHS)!=0 && (packet.flags & PACKET_FLAGS_TOSERVER)!=0){
            if(!(tcp.ack == get_ref_b_b!(ssn, server_stream, isn) + 1)){
                return false;
            }
            if(!(tcp.seq == get_ref_b_b!(ssn, client_stream, isn))){
                return false;
            }

            ssn_set_packet_state(flow, ssn,TCP_SSN_SYN_RECV);
            add_eq_b_bw!(ssn, client_stream, isn, tcp.seq);
            add_eq_b_bw!(ssn, client_stream, base_seq, tcp.seq + 1);
            add_eq_b_bw!(ssn, client_stream, next_seq, tcp.seq + 1);

            add_eq_b_bw!(ssn, server_stream, window, tcp.win);

            add_eq_b_bw!(ssn, server_stream, last_ack, tcp.ack);
            add_eq_b_bw!(ssn, client_stream, last_ack, get_ref_b_b!(ssn,client_stream, isn) + 1);

            if check_flag!(ssn.borrow().stream_flags, STREAM_FLAGS_SERVER_WSCALE) &&
                (TCP_HAS_WSCALE!(tcp)) {

                add_eq_b_bw!(ssn, server_stream, wscale, TCP_GET_WSCALE!(tcp));
            } else{

                add_eq_b_bw!(ssn, server_stream, wscale, 0);
            }

            if check_flag!(ssn.borrow().stream_flags, STREAM_FLAGS_CLIENT_SACKOK) &&
                TCP_GET_SACKOK!(tcp){

                ssn.borrow_mut().stream_flags |= STREAM_FLAGS_SACKOK;
            }

            add_eq_b_bw!(ssn, client_stream, next_win, get_ref_b_b!(ssn, client_stream, last_ack) + get_ref_b_b!(ssn, client_stream, window) as u32);
            add_eq_b_bw!(ssn, server_stream, next_win, get_ref_b_b!(ssn, server_stream, last_ack) + get_ref_b_b!(ssn, server_stream, window) as u32);

            return true;
        }

        if (packet.flags & PACKET_FLAGS_TOSERVER) != 0{
            return false;
        }

        if tcp.ack != (get_ref_b_b!(ssn, client_stream, isn) + 1){
            return false;
        }

        stream_3whs_syn_ack_update(packet, tcp, flow, ssn, None);
    }else if (tcp.flags & TCP_FLAGS_SYN) != 0{

        if check_flag!(packet.flags, PACKET_FLAGS_TOCLIENT){

            add_flag!(ssn.borrow_mut().stream_flags, STREAM_FLAGS_4WHS);
            add_eq_b_bw!(ssn, server_stream, isn, tcp.seq);
            add_eq_b_bw!(ssn, server_stream, base_seq, tcp.seq + 1);
            add_eq_b_bw!(ssn, server_stream, next_seq, tcp.seq + 1);

            if let Some(ref option) = tcp.tcp_option{
                if let Some(ref ts) = option.ts{

                    add_eq_b_bw!(ssn, server_stream, last_ts, ts[0] as usize);

                    if check_eq_b_b!(ssn, server_stream, last_ts, 0){
                        add_contain_b_bw!(ssn, server_stream, stream_flags, STREAM_FLAGS_ZERO_TIMESTAMP);
                    }
                    add_eq_b_bw!(ssn, server_stream, last_pkt_ts, packet.ts);
                    add_contain_b_bw!(ssn, server_stream, stream_flags, STREAM_FLAGS_TIMESTAMP);
                }

                if let Some(ws) = option.ws{

                    ssn.borrow_mut().stream_flags |= STREAM_FLAGS_SERVER_WSCALE;
                    add_eq_b_bw!(ssn, server_stream, wscale, ws);
                }else{


                    ssn.borrow_mut().stream_flags &= !STREAM_FLAGS_SERVER_WSCALE;
                    add_eq_b_bw!(ssn, server_stream, wscale, 0);
                }

                if option.sackok{
                    add_flag!(ssn.borrow_mut().stream_flags, STREAM_FLAGS_CLIENT_SACKOK);
                }else{
                    del_flag!(ssn.borrow_mut().stream_flags, STREAM_FLAGS_CLIENT_SACKOK);
                }

            }
            add_eq_b_bw!(ssn, server_stream, window, tcp.win);
        }
    }else if tcp.flags & TCP_FLAGS_ACK != 0{
        if !check_eq_b_b!(ssn, client_stream, next_seq, tcp.seq){
            return false;
        }

        ssn.borrow_mut().stream_flags |= STREAM_FLAGS_ASYNC;
        ssn_set_packet_state( flow, ssn, TCP_SSN_ESTABLISHED);

        add_eq_b_bw!(ssn, client_stream, window, tcp.win);
        add_eq_b_bw!(ssn, client_stream, last_ack, tcp.seq);
        add_eq_b_bw!(ssn, client_stream, next_seq, get_ref_b_b!(ssn, client_stream, last_ack) + get_ref_b_b!(ssn, client_stream, window) as u32);

        add_eq_b_bw!(ssn, server_stream, isn, tcp.ack - 1);
        add_eq_b_bw!(ssn, server_stream, base_seq, get_ref_b_b!(ssn, server_stream, isn) + 1);

        add_eq_b_bw!(ssn, server_stream, next_seq, get_ref_b_b!(ssn, server_stream, isn) + 1);
        add_eq_b_bw!(ssn, server_stream, last_ack, get_ref_b_b!(ssn, server_stream, next_seq));
        add_eq_b_bw!(ssn, server_stream, next_win, get_ref_b_b!(ssn, server_stream, last_ack));

        if check_flag!(ssn.borrow().stream_flags, STREAM_FLAGS_SERVER_WSCALE){
            add_eq_b_bw!(ssn, client_stream, wscale, TCP_WSCALE_MAX);
        }

        if let Some(ref option) = tcp.tcp_option{
            if let Some(ref ts) = option.ts {
                if check_contain_b_b!(ssn, client_stream, stream_flags, STREAM_FLAGS_TIMESTAMP) {

                    add_flag!(ssn.borrow_mut().stream_flags, STREAM_FLAGS_TIMESTAMP);
                    del_contain_b_bw!(ssn,client_stream, stream_flags, STREAM_FLAGS_TIMESTAMP);
                    add_eq_b_bw!(ssn, client_stream, last_pkt_ts, ts[0] as usize);
                }else{

                    add_eq_b_bw!(ssn, client_stream, last_ts, 0);
                    del_contain_b_bw!(ssn, client_stream, stream_flags, STREAM_FLAGS_ZERO_TIMESTAMP);
                }
            }
            else{
                add_eq_b_bw!(ssn, client_stream, last_ts, 0);
                del_contain_b_bw!(ssn, client_stream, stream_flags, STREAM_FLAGS_ZERO_TIMESTAMP);
            }
        }else{
            add_eq_b_bw!(ssn, client_stream, last_ts, 0);
            del_contain_b_bw!(ssn, client_stream, stream_flags, STREAM_FLAGS_ZERO_TIMESTAMP);
        }

        if check_flag!(ssn.borrow().stream_flags, STREAM_FLAGS_CLIENT_SACKOK) {
            add_flag!(ssn.borrow_mut().stream_flags, STREAM_FLAGS_SACKOK);
        }

        session_handle_stream_segment(packet, tcp, flow, ssn);
    }else{
        ;
    }

    return true;
}

// store all received syn/ack
struct TcpStateQueue{
    flags: u8,
    wscale: u8,
    win: u16,
    seq: u32,
    ack: u32,
    ts: usize,
    pkt_ts: usize,
    next: Option<Rc<Box<TcpStateQueue>>>,
}
fn new_tcp_state_queue() -> TcpStateQueue{
    return TcpStateQueue{
      flags: 0,
        wscale: 0,
        win: 0,
        seq: 0,
        ack: 0,
        ts: 0,
        pkt_ts: 0,
        next: None,
    };
}

fn stream_3whs_syn_ack_to_state_queue(packet: &Packet, tcp: &Tcp, q: &mut TcpStateQueue){
    q.flags = 0;
    q.wscale = 0;
    q.ts = 0;
    q.win = tcp.win;
    q.seq = tcp.seq;
    q.ack = tcp.ack;
    q.pkt_ts = packet.ts;

    if let Some(ref option) = tcp.tcp_option{
        if option.sackok{
            q.flags |= STREAM_QUEUE_FLAG_SACK;
        }
        if let Some(ws) = option.ws{
            q.flags | STREAM_QUEUE_FLAG_WS;
            q.wscale = ws;
        }
        if let Some(ref ts) = option.ts{
            q.flags |= STREAM_QUEUE_FLAG_TS;
            q.ts = ts[0] as usize;
        }
    }
}

fn stream_3whs_syn_ack_update(packet: &Packet, tcp: &Tcp, flow: & Arc<RwLock<Flow>>, ssn: & Rc<RefCell<TcpSession>>, option_queue: Option<Rc<Box<TcpStateQueue>>>){

    let q = if let Some(ref q) = option_queue{
        Rc::clone(q)
    }else{
        let mut tmp_queue = new_tcp_state_queue();
        stream_3whs_syn_ack_to_state_queue(packet, tcp, &mut tmp_queue);
        Rc::new(Box::new(tmp_queue))
    };

    if ssn.borrow().state != TCP_SSN_SYN_RECV{
        ssn_set_packet_state( flow, ssn, TCP_SSN_SYN_RECV);
    }

    add_eq_b_bw!(ssn, server_stream, isn, q.seq);
    add_eq_b_bw!(ssn, server_stream, base_seq, q.seq + 1);
    add_eq_b_bw!(ssn, server_stream, next_seq, q.seq + 1);

    add_eq_b_bw!(ssn, client_stream, window, q.win);

    if (q.flags & STREAM_QUEUE_FLAG_TS) != 0 &&
        check_contain_b_b!(ssn, client_stream, stream_flags, STREAM_FLAGS_TIMESTAMP) {

        add_eq_b_bw!(ssn, server_stream, last_ts, q.ts);
        ssn.borrow_mut().stream_flags |= STREAM_FLAGS_TIMESTAMP;
        add_eq_b_bw!(ssn, server_stream, last_pkt_ts, q.pkt_ts);

        if check_eq_b_b!(ssn, server_stream, last_ts, 0){
            add_contain_b_bw!(ssn, server_stream, stream_flags, STREAM_FLAGS_ZERO_TIMESTAMP);
        }
    }else{
        add_eq_b_bw!(ssn, client_stream, last_ts, 0);
        add_eq_b_bw!(ssn, server_stream, last_ts, 0);
        del_contain_b_bw!(ssn, client_stream, stream_flags, STREAM_FLAGS_ZERO_TIMESTAMP);
    }

    add_eq_b_bw!(ssn, client_stream, last_ack, q.ack);
    add_eq_b_bw!(ssn, server_stream, last_ack, get_ref_b_b!(ssn,server_stream,isn) + 1);

    if (ssn.borrow().stream_flags & STREAM_FLAGS_SERVER_WSCALE) != 0 &&
        (q.flags & STREAM_QUEUE_FLAG_WS) != 0{
        add_eq_b_bw!(ssn, client_stream, wscale, q.wscale);
    }else{
        add_eq_b_bw!(ssn, client_stream, wscale, 0);
    }

    if (ssn.borrow().stream_flags & STREAM_FLAGS_CLIENT_SACKOK) != 0 &&
        (q.flags & STREAM_QUEUE_FLAG_SACK) != 0{
        ssn.borrow_mut().stream_flags |= STREAM_FLAGS_SACKOK;
    }else{
        del_flag!(ssn.borrow_mut().stream_flags, STREAM_FLAGS_SACKOK);
    }

    add_eq_b_bw!(ssn, server_stream, next_win, get_ref_b_b!(ssn, server_stream, last_ack) + get_ref_b_b!(ssn, server_stream, window) as u32);
    add_eq_b_bw!(ssn, client_stream, next_win, get_ref_b_b!(ssn, client_stream, last_ack) + get_ref_b_b!(ssn, client_stream, window) as u32);

    del_flag!(ssn.borrow_mut().stream_flags, STREAM_FLAGS_4WHS);
}

fn stream_validate_timestamp(packet: &Packet, tcp: &Rc<Tcp>, ssn: &Rc<RefCell<TcpSession>>) -> bool{
    let sender_stream =  if check_flag!(packet.flags,PACKET_FLAGS_TOSERVER){
        Rc::clone(&ssn.borrow().client_stream)
    }else{
        Rc::clone(&ssn.borrow().server_stream)
    };

    let receiver_stream = if check_flag!(packet.flags,PACKET_FLAGS_TOSERVER){
        Rc::clone(&ssn.borrow().server_stream)
    }else{
        Rc::clone(&ssn.borrow().client_stream)
    };

    if receiver_stream.borrow().os_policy == OS_POLICY_NONE{
        stream_set_os_policy(&receiver_stream);
    }

    if let Some(ref option) = tcp.tcp_option{
        if let Some(ref ts) = option.ts{
            if check_flag!(sender_stream.borrow().stream_flags,STREAM_FLAGS_ZERO_TIMESTAMP){

            }
        }
    }

    return true;
}

pub fn stream_state_established() -> bool{
    return true;
}

pub fn stream_state_fin_wait1() -> bool{
    return true;
}

pub fn stream_state_fin_wait2() -> bool{
    return true;
}

pub fn stream_state_closing() -> bool{
    return true;
}

pub fn stream_state_close_wait() -> bool{
    return true;
}

pub fn stream_state_last_ack() -> bool {
    return true;
}

pub fn stream_state_time_wait() -> bool {
    return true;
}
pub fn stream_state_closed() -> bool {
    return true;
}



/**************************************************************************************************/


impl PartialEq for os_policy_type{
    fn eq(&self, other: &os_policy_type) -> bool{
        match self{
            OS_POLICY_NONE => {if let OS_POLICY_NONE = other{true}else{false}},
            OS_POLICY_BSD => {if let OS_POLICY_BSD = other{true}else{false}},
            OS_POLICY_LINUX => {if let OS_POLICY_LINUX = other{true}else{false}},
            OS_POLICY_OLD_LINUX => {if let OS_POLICY_OLD_LINUX = other{true}else{false}},
            OS_POLICY_SOLARIS => {if let OS_POLICY_SOLARIS = other{true}else{false}},
            OS_POLICY_BSD_RIGHT => {if let OS_POLICY_BSD_RIGHT = other{true}else{false}},
            OS_POLICY_OLD_SOLARIS => {if let OS_POLICY_OLD_SOLARIS = other{true}else{false}},
            OS_POLICY_HPUX10 => {if let OS_POLICY_HPUX10 = other{true}else{false}},
            OS_POLICY_HPUX11 => {if let OS_POLICY_HPUX11 = other{true}else{false}},
            OS_POLICY_IRIX => {if let OS_POLICY_IRIX = other{true}else{false}},
            OS_POLICY_MACOS => {if let OS_POLICY_MACOS = other{true}else{false}},
            OS_POLICY_WINDOWS => {if let OS_POLICY_WINDOWS = other{true}else{false}},
            OS_POLICY_VISTA => {if let OS_POLICY_VISTA = other{true}else{false}},
            OS_POLICY_WINDOWS2K3 => {if let OS_POLICY_WINDOWS2K3 = other{true}else{false}},
            OS_POLICY_FIRST => {if let OS_POLICY_FIRST = other{true}else{false}},
            OS_POLICY_LAST => {if let OS_POLICY_LAST = other{true}else{false}},
        }
    }
}

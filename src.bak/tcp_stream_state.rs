extern crate libc;

use std::cmp::PartialEq;

use libc::timeval;

use std::rc::Rc;
use std::cell::RefCell;

use ::tcp_stream::{TcpSession, Stream, ssn_set_packet_state};
use ::tcp::{Tcp};
use ::tcp::{TCP_FLAGS_RST, TCP_FLAGS_FIN, TCP_FLAGS_SYN, TCP_FLAGS_ACK};
use ::tcp_stream::{STREAM_FLAGS_ASYNC, STREAM_FLAGS_RST_RECV, STREAM_FLAGS_SERVER_WSCALE, STREAM_FLAGS_SACKOK, STREAM_FLAGS_CLIENT_SACKOK};
use ::flow::{Packet, PACKET_FLAGS_TOSERVER, PACKET_FLAGS_TOCLIENT};
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

fn stream_set_os_policy(stream: &mut Stream){
    // read from conf file to set stream os policy
    // all set to be default os policy
    stream.os_policy = OS_POLICY_DEFAULT;
}

fn stream_validate_ack(tcp:&Tcp, ssn: &TcpSession, stream: &Stream) -> bool{

    return true;
}

fn stream_validate_rst(packet: &Packet, ssn: &TcpSession, tcp: &Tcp, stream: &mut Stream) -> bool{

    if check_flag!(ssn.stream_flags, STREAM_FLAGS_TIMESTAMP){
        if !(stream_validate_timestamp(packet, ssn, tcp)){
            return false;
        }
    }

    if stream.os_policy == OS_POLICY_NONE{
        stream_set_os_policy(stream);
    }

    let os_policy = stream.os_policy.clone();

    if (tcp.flags & TCP_FLAGS_ACK) != 0 &&
        tcp.ack > 0 &&
        !stream_validate_ack(tcp, ssn, stream){
        return false;
    }

    if (ssn.stream_flags & STREAM_FLAGS_ASYNC) != 0{
        if tcp.seq >= stream.next_seq{
            return true;
        }
        return false;
    }

    match os_policy {
        // temply handle os_policy default
        OS_POLICY_BSD => {
            if tcp.seq == stream.next_seq{
                return true;
            }else{
                return false;
            }
        },
        _ => {},
    };

    return false;
}

pub fn stream_state_syn_recv(packet: &Packet, tcp: &Tcp, flow: &mut Flow, ssn: &mut TcpSession, stream: &mut Stream) -> bool{
    if check_flag!(tcp.flags, TCP_FLAGS_RST){
        if !stream_validate_rst(packet, ssn, tcp, stream){
            return false;
        }

        let mut reset = true;
        if check_flag!(ssn.stream_flags, STREAM_FLAGS_DETECTION_EVASION_ATTEMPT){
            if check_flag!(packet.flags, PACKET_FLAGS_TOSERVER){
                if ssn.server_stream.borrow().os_policy == OS_POLICY_LINUX ||
                    ssn.server_stream.borrow().os_policy == OS_POLICY_OLD_LINUX ||
                    ssn.server_stream.borrow().os_policy == OS_POLICY_SOLARIS{
                    reset = false;
                }
            }else{
                if ssn.client_stream.borrow().os_policy == OS_POLICY_LINUX ||
                    ssn.client_stream.borrow().os_policy == OS_POLICY_OLD_LINUX ||
                    ssn.client_stream.borrow().os_policy == OS_POLICY_SOLARIS{
                    reset = false;
                }
            }
        }

        if reset{
            ssn_set_packet_state( flow, ssn, TCP_SSN_CLOSED);
            if check_flag!(ssn.stream_flags, STREAM_FLAGS_TIMESTAMP){
                stream_validate_timestamp(packet, ssn,tcp);
            }
        }
    }else if check_flag!(tcp.flags, TCP_FLAGS_FIN){

    }

    return true;
}



pub fn stream_state_syn_sent(packet:&mut Packet, tcp: &mut Tcp, flow: &mut Flow, ssn: &mut TcpSession, stream: &mut Stream) -> bool{

    // RST
    if (tcp.flags & TCP_FLAGS_RST) != 0{
        if!stream_validate_rst(packet,ssn, tcp, stream){
            return false;
        }

        if check_flag!(packet.flags, PACKET_FLAGS_TOSERVER){
            if (tcp.seq == ssn.client_stream.borrow().isn) &&
                (tcp.win == 0) &&
                (tcp.ack == ssn.client_stream.borrow().isn + 1){
                ssn.server_stream.borrow_mut().stream_flags |= STREAM_FLAGS_RST_RECV;
                ssn_set_packet_state( flow, ssn, TCP_SSN_CLOSED);
            }
        }else{
            ssn.client_stream.borrow_mut().stream_flags |= STREAM_FLAGS_RST_RECV;
            ssn_set_packet_state( flow, ssn, TCP_SSN_CLOSED);
        }
    // FIN
    }else if (tcp.flags & TCP_FLAGS_FIN) != 0{
        /*nothing to do*/
        ;
    // SYN/ACK
    }else if (tcp.flags & (TCP_FLAGS_SYN|TCP_FLAGS_ACK)) == (TCP_FLAGS_SYN|TCP_FLAGS_ACK){
        if((ssn.stream_flags & STREAM_FLAGS_4WHS)!=0 && (packet.flags & PACKET_FLAGS_TOSERVER)!=0){
            if(!(tcp.ack == ssn.server_stream.borrow().isn + 1)){
                return false;
            }
            if(!(tcp.seq == ssn.client_stream.borrow().isn)){
                return false;
            }

            ssn_set_packet_state(flow, ssn,TCP_SSN_SYN_RECV);
            ssn.client_stream.borrow_mut().isn = tcp.seq;
            ssn.client_stream.borrow_mut().base_seq = tcp.seq + 1;
            ssn.client_stream.borrow_mut().next_seq = tcp.seq + 1;

            ssn.server_stream.borrow_mut().window = tcp.win;

            ssn.server_stream.borrow_mut().last_ack = tcp.ack;
            ssn.client_stream.borrow_mut().last_ack = ssn.client_stream.borrow().isn + 1;

            if check_flag!(ssn.stream_flags, STREAM_FLAGS_SERVER_WSCALE) &&
                (TCP_HAS_WSCALE!(tcp)) {
                ssn.server_stream.borrow_mut().wscale = TCP_GET_WSCALE!(tcp);
            } else{
                ssn.server_stream.borrow_mut().wscale = 0;
            }

            if check_flag!(ssn.stream_flags, STREAM_FLAGS_CLIENT_SACKOK) &&
                TCP_GET_SACKOK!(tcp){
                ssn.stream_flags |= STREAM_FLAGS_SACKOK;
            }

            ssn.client_stream.borrow_mut().next_win = ssn.client_stream.borrow().last_ack + ssn.client_stream.borrow().window as u32;
            ssn.server_stream.borrow_mut().next_win = ssn.server_stream.borrow().last_ack + ssn.server_stream.borrow().window as u32;

            return true;
        }

        if (packet.flags & PACKET_FLAGS_TOSERVER) != 0{
            return false;
        }

        if tcp.ack != (ssn.client_stream.borrow().isn + 1){
            return false;
        }

        stream_3whs_syn_ack_update(packet, tcp, flow, ssn, None);
    }else if (tcp.flags & TCP_FLAGS_SYN) != 0{

        if check_flag!(packet.flags, PACKET_FLAGS_TOCLIENT){

            add_flag!(ssn.stream_flags, STREAM_FLAGS_4WHS);
            ssn.server_stream.borrow_mut().isn = tcp.seq;
            ssn.server_stream.borrow_mut().base_seq = tcp.seq + 1;
            ssn.server_stream.borrow_mut().next_seq = tcp.seq + 1;

            if let Some(ref option) = tcp.tcp_option{
                if let Some(ref ts) = option.ts{
                    ssn.server_stream.borrow_mut().last_ts = ts[0] as usize;
                    if ssn.server_stream.borrow().last_ts == 0{
                        add_flag!(ssn.server_stream.borrow_mut().stream_flags, STREAM_FLAGS_ZERO_TIMESTAMP);
                    }
                    ssn.server_stream.borrow_mut().last_pkt_ts = packet.ts;
                    add_flag!(ssn.server_stream.borrow_mut().stream_flags, STREAM_FLAGS_TIMESTAMP);
                }

                if let Some(ws) = option.ws{
                    ssn.stream_flags |= STREAM_FLAGS_SERVER_WSCALE;
                    ssn.server_stream.borrow_mut().wscale = ws;
                }else{
                    ssn.stream_flags &= !STREAM_FLAGS_SERVER_WSCALE;
                    ssn.server_stream.borrow_mut().wscale = 0;
                }

                if option.sackok{
                    ssn.stream_flags |= STREAM_FLAGS_CLIENT_SACKOK;
                }else{
                    ssn.stream_flags &= !STREAM_FLAGS_CLIENT_SACKOK;
                }

            }
            ssn.server_stream.borrow_mut().window = tcp.win;
        }
    }else if tcp.flags & TCP_FLAGS_ACK != 0{
        if tcp.seq != ssn.client_stream.borrow().next_seq{
            return false;
        }

        ssn.stream_flags |= STREAM_FLAGS_ASYNC;
        ssn_set_packet_state( flow, ssn, TCP_SSN_ESTABLISHED);
        ssn.client_stream.borrow_mut().window = tcp.win;
        ssn.client_stream.borrow_mut().last_ack = tcp.seq;
        ssn.client_stream.borrow_mut().next_seq = ssn.client_stream.borrow().last_ack + ssn.client_stream.borrow().window as u32;

        ssn.server_stream.borrow_mut().isn = tcp.ack - 1;
        ssn.server_stream.borrow_mut().base_seq = ssn.server_stream.borrow().isn + 1;
        ssn.server_stream.borrow_mut().next_seq = ssn.server_stream.borrow().isn + 1;
        ssn.server_stream.borrow_mut().last_ack = ssn.server_stream.borrow().next_seq;
        ssn.server_stream.borrow_mut().next_win = ssn.server_stream.borrow().last_ack;

        if (ssn.stream_flags & STREAM_FLAGS_SERVER_WSCALE) != 0{
            ssn.client_stream.borrow_mut().wscale = TCP_WSCALE_MAX;
        }

        if let Some(ref option) = tcp.tcp_option{
            if let Some(ref ts) = option.ts {
                if check_flag!(ssn.client_stream.borrow().stream_flags, STREAM_FLAGS_TIMESTAMP) {
                    add_flag!(ssn.stream_flags, STREAM_FLAGS_TIMESTAMP);
                    del_flag!(ssn.client_stream.borrow_mut().stream_flags, STREAM_FLAGS_TIMESTAMP);
                    ssn.client_stream.borrow_mut().last_pkt_ts = ts[0] as usize;
                }else{
                    ssn.client_stream.borrow_mut().last_ts = 0;
                    del_flag!(ssn.client_stream.borrow_mut().stream_flags, STREAM_FLAGS_ZERO_TIMESTAMP);
                }
            }
            else{
                ssn.client_stream.borrow_mut().last_ts = 0;
                del_flag!(ssn.client_stream.borrow_mut().stream_flags, STREAM_FLAGS_ZERO_TIMESTAMP);
            }
        }else{
            ssn.client_stream.borrow_mut().last_ts = 0;
            del_flag!(ssn.client_stream.borrow_mut().stream_flags, STREAM_FLAGS_ZERO_TIMESTAMP);
        }

        if check_flag!(ssn.stream_flags, STREAM_FLAGS_CLIENT_SACKOK) {
            add_flag!(ssn.stream_flags, STREAM_FLAGS_SACKOK);
        }

        session_handle_stream_segment(packet, flow, tcp, ssn, stream);
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
    next: Option<Rc<RefCell<TcpStateQueue>>>,
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

fn stream_3whs_syn_ack_update(packet: &Packet, tcp: &Tcp, flow: &mut Flow, ssn: &mut TcpSession, option_queue: Option<Rc<RefCell<TcpStateQueue>>>){

    let q = if let Some(ref q) = option_queue{
        Rc::clone(q)
    }else{
        let mut tmp_queue = new_tcp_state_queue();
        stream_3whs_syn_ack_to_state_queue(packet, tcp, &mut tmp_queue);
        Rc::new(RefCell::new(tmp_queue))
    };

    if ssn.state != TCP_SSN_SYN_RECV{
        ssn_set_packet_state( flow, ssn, TCP_SSN_SYN_RECV);
    }

    ssn.server_stream.borrow_mut().isn = q.borrow().seq;
    ssn.server_stream.borrow_mut().base_seq = q.borrow().seq + 1;
    ssn.server_stream.borrow_mut().next_seq = q.borrow().seq + 1;

    ssn.client_stream.borrow_mut().window = q.borrow().win;
    if (q.borrow().flags & STREAM_QUEUE_FLAG_TS) != 0 &&
        (ssn.client_stream.borrow().stream_flags & STREAM_FLAGS_TIMESTAMP) != 0{
        ssn.server_stream.borrow_mut().last_ts = q.borrow().ts;
        ssn.stream_flags |= STREAM_FLAGS_TIMESTAMP;
        ssn.server_stream.borrow_mut().last_pkt_ts = q.borrow().pkt_ts;
        if ssn.server_stream.borrow().last_ts  == 0{
            ssn.server_stream.borrow_mut().stream_flags |= STREAM_FLAGS_ZERO_TIMESTAMP;
        }
    }else{
        ssn.client_stream.borrow_mut().last_ts = 0;
        ssn.server_stream.borrow_mut().last_ts = 0;
        del_flag!(ssn.client_stream.borrow_mut().stream_flags, STREAM_FLAGS_ZERO_TIMESTAMP);
    }

    ssn.client_stream.borrow_mut().last_ack = q.borrow().ack;
    ssn.server_stream.borrow_mut().last_ack = ssn.server_stream.borrow().isn + 1;

    if (ssn.stream_flags & STREAM_FLAGS_SERVER_WSCALE) != 0 &&
        (q.borrow().flags & STREAM_QUEUE_FLAG_WS) != 0{
        ssn.client_stream.borrow_mut().wscale = q.borrow().wscale;
    }else{
        ssn.client_stream.borrow_mut().wscale = 0;
    }

    if (ssn.stream_flags & STREAM_FLAGS_CLIENT_SACKOK) != 0 &&
        (q.borrow().flags & STREAM_QUEUE_FLAG_SACK) != 0{
        ssn.stream_flags |= STREAM_FLAGS_SACKOK;
    }else{
        del_flag!(ssn.stream_flags, STREAM_FLAGS_SACKOK);
    }

    ssn.server_stream.borrow_mut().next_win = ssn.server_stream.borrow().last_ack + ssn.server_stream.borrow().window as u32;
    ssn.client_stream.borrow_mut().next_win = ssn.client_stream.borrow().last_ack + ssn.client_stream.borrow().window as u32;

    del_flag!(ssn.stream_flags, STREAM_FLAGS_4WHS);
}

fn stream_validate_timestamp(packet: &Packet, ssn: &TcpSession, tcp: &Tcp) -> bool{
    let sender_stream =  if check_flag!(packet.flags,PACKET_FLAGS_TOSERVER){
        Rc::clone(&ssn.client_stream)
    }else{
        Rc::clone(&ssn.server_stream)
    };

    let receiver_stream = if check_flag!(packet.flags,PACKET_FLAGS_TOSERVER){
      Rc::clone(&ssn.server_stream)
    }else{
        Rc::clone(&ssn.client_stream)
    };

    if receiver_stream.borrow().os_policy == OS_POLICY_NONE{
        stream_set_os_policy(&mut (receiver_stream.borrow_mut()));
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

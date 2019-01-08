
use std::collections::HashMap;
use std::cmp::{PartialEq, Eq};
use std::hash::{Hash, Hasher};
use std::rc::{Rc};


use tcp::{Tcp, TCP_FLAG_SYN, TCP_FLAG_FIN, TCP_FLAG_ACK, TCP_FLAG_PSH, TCP_FLAG_RST, TCP_FLAG_URG};
use flow::{Flow};
use thread::{ThreadVar};
use tcp_stream::Stream;

#[derive(Eq)]
pub struct StreamHash{
    src_ip: u32,
    dst_ip :u32,
    src_port: u16,
    dst_port: u16
}







pub fn stream_event(info: &str){

}


pub fn insert_stream(streamhash: StreamHash, stream: Stream, hashmap: &mut HashMap<StreamHash, Stream>){

}



fn tcp_new_stream(tcp: &Tcp) -> (Stream, StreamHash){
    (Stream{
        src_ip: tcp.iph.src_ip,
        dst_ip: tcp.iph.dst_ip,
        src_port: tcp.sport,
        dst_port: tcp.dport,
        seg_list: None,
        seg_list_tail: None,
        isn: tcp.seq,
        seq_next: tcp.seq + 1,
        base_seq: tcp.seq + 1,
        last_ack: tcp.seq,
        pstate: TCP_SSN_NONE,
        state: TCP_SSN_NONE,
    },StreamHash{
        src_ip: tcp.iph.src_ip,
        dst_ip: tcp.iph.dst_ip,
        src_port: tcp.sport,
        dst_port: tcp.dport,
    })
}

fn new_stream_seg(buf: &Rc<Vec<u8>>, seq: u32) -> StreamSeg{
    StreamSeg{
        buf: Rc::clone(buf),
        seq: seq,
        prev: None,
        next: None,
    }
}

fn stream_set_state(stream: &mut Stream, state: u8){
    stream.pstate = stream.state;
    stream.state = state;
}

fn stream_send_eof(){

}



fn insert_seg(mut seg: StreamSeg, stream: &mut Stream) {
    let rc_ref_seg = Rc::new(RefCell::new(seg));

    if (rc_ref_seg.borrow().seq + rc_ref_seg.borrow().buf.len() as u32) < stream.base_seq {
        //follow suricata
        return;
    }

    match stream.seg_list {
        None => {
            stream.seg_list = Some(Rc::clone(&rc_ref_seg));
            stream.seg_list_tail = Some(Rc::clone(&rc_ref_seg));
            return;
        },
        _ => {},
    }

    if let Some(tmp_seg) = &stream.seg_list_tail {
        if rc_ref_seg.borrow().seq >= (tmp_seg.borrow().seq + tmp_seg.borrow().buf.len() as u32) {
            rc_ref_seg.borrow_mut().prev = Some(Rc::clone(&tmp_seg));
            tmp_seg.borrow_mut().next = Some(Rc::clone(&rc_ref_seg));

            stream.seg_list_tail = Some(Rc::clone(&rc_ref_seg));
            return;
        }
    }

    let mut node = stream.seg_list.clone();

    while let Some(n) = node{
        if rc_ref_seg.borrow().seq < n.borrow().seq{
            let activate_len = n.borrow().seq - rc_ref_seg.borrow().seq;

            if activate_len < rc_ref_seg.borrow().buf.len() as u32 {
                let tmp_buf = Rc::clone(&rc_ref_seg.borrow().buf);
                let buf = &tmp_buf[0..activate_len as usize];
                ;
                let buf_vec = buf.to_vec();
                let buf_vec_rc = Rc::new(buf_vec);
                seg.buf = buf_vec_rc;
            }

            seg.next = Some(Rc::clone(&n));

            if let None = n.borrow().prev{
                stream.seg_list = Some(Rc::clone(&rc_ref_seg));
            }
            n.borrow_mut().prev = Some(Rc::clone(&rc_ref_seg));

            return;
        }

        node = n.borrow().next.clone();
    }

    // follow suricata, just append the seg
    let mut node = stream.seg_list_tail.clone();
    if let Some(n) = node {
        seg.prev = Some(Rc::clone(&n));
        n.borrow_mut().next = Some(Rc::clone(&rc_ref_seg));
        stream.seg_list_tail = Some(Rc::clone(&rc_ref_seg));

    }

    return;
}

fn stream_update_ack(stream: & mut Stream, tcp: &Tcp){
    if stream.state >= TCP_SSN_CLOSING{
        // send eof msg to app parser
        stream_send_eof();
        return;
    }

    let stram_seg = new_stream_seg(&tcp.buf, tcp.seq);

    insert_seg(stram_seg,  stream);
}

fn tcp_reassemble_handle_seg(tcp: &Tcp, stream: &mut Stream){

    if (tcp.flags & TCP_FLAG_RST) != 0 ||
        ((tcp.flags & TCP_FLAG_FIN)!=0 && (stream.state > TCP_SSN_TIME_WAIT)){

    }else{
        stream_update_ack(stream, tcp);

    }



}


pub fn get_stream_hash(tcp: &Tcp) -> StreamHash{
    let mut tmp_stream_hash = StreamHash{
        src_ip: tcp.iph.src_ip,
        dst_ip: tcp.iph.dst_ip,
        src_port: tcp.sport,
        dst_port: tcp.dport,
    };

    return tmp_stream_hash;
}

fn tcp_reassemble_seg_syn(tcp: Tcp, threadvar: &mut ThreadVar){
    let stream_hash = get_stream_hash(&tcp);

    match threadvar.streamhash.get_mut(&stream_hash) {
        None => {
            let (mut stream, stream_hash) = tcp_new_stream(&tcp);
            stream_set_state(&mut stream, TCP_SSN_SYN_SENT);
            insert_stream(stream_hash, stream, &mut threadvar.streamhash);

        },
        Some(mut stream) => {
            stream_set_state(&mut stream, TCP_SSN_SYN_SENT);
            stream.isn = tcp.seq;
            stream.base_seq = tcp.seq + 1;
            stream.seq_next = tcp.seq + 1;
        },
    }

    return;
}

fn tcp_reassemble_seg_ack(tcp: Tcp, threadvar: &mut ThreadVar){
    let stream_hash = get_stream_hash(&tcp);

    match tmp_stream{
        None =>{

        },
        Some(mut stream) => {
            stream_set_state(&mut stream, TCP_SSN_ESTABLISHED);
            stream.isn = tcp.seq - 1;
            stream.base_seq = tcp.seq -1;
            stream.seq_next = tcp.seq + tcp.buf.len() as u32;
            stream.last_ack = tcp.seq;
            tcp_reassemble_handle_seg(&tcp, &mut stream);
        },
    }
}
pub fn tcp_reassemble_seg(tcp: Tcp, threadvar: &mut ThreadVar) {

    if (tcp.flags & TCP_FLAG_SYN) != 0{
        tcp_reassemble_seg_syn(tcp, threadvar);
        return;
    }else if (tcp.flags & TCP_FLAG_ACK) != 0{
        tcp_reassemble_seg_ack(tcp, threadvar);
        return;
    }


    /*match get_stream(tcp, threadvar){
        None => {

            let mut tmpstream = Stream{
                src_ip: tcp.iph.src_ip,
                dst_ip: tcp.iph.dst_ip,
                src_port: tcp.sport,
                dst_port: tcp.dport,
                sorted_seg_list: Rc::new(Nil),
                unsort_seg_list: Rc::new(Nil),
                seq_next: 0,

            };
        },
        Some(t) => {

        },
    }*/


}


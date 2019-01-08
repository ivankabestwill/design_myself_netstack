
use std::clone::Clone;
use std::fmt::{Display, Result, Formatter};

use ::flow::{Flow, Packet, flow_change_protocol, PACKET_FLAGS_TOSERVER, PACKET_FLAGS_PSEUDO_STREAM_END};
use ::tcp_stream::{TcpSession, Stream, TCP_SSN_CLOSED, STREAM_FLAGS_APPPROTO_DETECTION_COMPLETED,
                   STREAM_FLAGS_DEPTH_REACHED, STREAM_FLAGS_APPLAYER_DISABLED};

// follow suricata, not only so much.
#[derive(Clone)]
pub enum ApplayerProto{
    APPLAYER_UNKNOWN,
    APPLAYER_HTTP,
    APPLAYER_FTP,
    APPLAYER_SMTP,
    APPLAYER_TLS,
    APPLAYER_SSH,
    APPLAYER_IMAP,
    APPLAYER_MSN,
}

use self::ApplayerProto::{APPLAYER_UNKNOWN, APPLAYER_HTTP, APPLAYER_FTP, APPLAYER_SMTP,
                          APPLAYER_TLS, APPLAYER_SSH, APPLAYER_IMAP, APPLAYER_MSN};

impl PartialEq for ApplayerProto{
    fn eq(&self, other: &ApplayerProto) -> bool{
        match self{
            APPLAYER_UNKNOWN => {if let APPLAYER_UNKNOWN = other{true}else{false}},
            APPLAYER_HTTP => {if let APPLAYER_HTTP = other{true}else{false}},
            APPLAYER_FTP => {if let APPLAYER_FTP = other{true}else{false}},
            APPLAYER_SMTP => {if let APPLAYER_SMTP = other{true}else{false}},
            APPLAYER_TLS => {if let APPLAYER_TLS = other{true}else{false}},
            APPLAYER_SSH => {if let APPLAYER_SSH = other{true}else{false}},
            APPLAYER_IMAP => {if let APPLAYER_IMAP = other{true}else{false}},
            APPLAYER_MSN => {if let APPLAYER_MSN = other{true}else{false}},
        }
    }
}

pub enum APPLAYER_DATA<'a>{
    APPLAYER_DATA_GAP(u32),
    APPLAYER_DATA_NONE,
    APPLAYER_DATA_SLICE(&'a [u8]),
}

pub fn new_applayer_proto() -> ApplayerProto{
    return ApplayerProto::APPLAYER_UNKNOWN;
}

impl Display for ApplayerProto{
    fn fmt(&self, f: &mut Formatter) -> Result{
        write!(f, "{}",
        match self{
            ApplayerProto::APPLAYER_UNKNOWN => {"unknown"},
            ApplayerProto::APPLAYER_HTTP => {"http"},
            ApplayerProto::APPLAYER_FTP => {"ftp"},
            ApplayerProto::APPLAYER_SMTP => {"smtp"},
            ApplayerProto::APPLAYER_TLS => {"tls"},
            ApplayerProto::APPLAYER_SSH => {"ssh"},
            ApplayerProto::APPLAYER_IMAP => {"imap"},
            ApplayerProto::APPLAYER_MSN => {"msn"},
        })
    }
}

pub type APPLAYER_FLAGS_TYPE = u64;

pub const APPLAYER_FLAGS_NONE: APPLAYER_FLAGS_TYPE = 0;
pub const APPLAYER_FLAGS_STREAM_START: APPLAYER_FLAGS_TYPE = 1<<0;
pub const APPLAYER_FLAGS_STREAM_EOF: APPLAYER_FLAGS_TYPE = 1<<1;
pub const APPLAYER_FLAGS_STREAM_TOCLIENT: APPLAYER_FLAGS_TYPE = 1<<2;
pub const APPLAYER_FLAGS_STREAM_TOSERVER: APPLAYER_FLAGS_TYPE = 1<<3;
pub const APPLAYER_FLAGS_STREAM_DEPTH: APPLAYER_FLAGS_TYPE = 1<<4;
pub const APPLAYER_FLAGS_STREAM_GAP: APPLAYER_FLAGS_TYPE = 1<<5;


pub fn get_applayer_flag_from_stream(packet: &Packet, ssn: &TcpSession, stream: &Stream, this_dir: bool) -> APPLAYER_FLAGS_TYPE{
    let mut flag:APPLAYER_FLAGS_TYPE = APPLAYER_FLAGS_NONE;

    if !check_flag!(stream.stream_flags, STREAM_FLAGS_APPPROTO_DETECTION_COMPLETED){
        add_flag!(flag, APPLAYER_FLAGS_STREAM_START);
    }

    if ssn.state == TCP_SSN_CLOSED{
        add_flag!(flag, APPLAYER_FLAGS_STREAM_EOF);
    }

    if check_flag!(packet.flags, PACKET_FLAGS_PSEUDO_STREAM_END){
        add_flag!(flag, APPLAYER_FLAGS_STREAM_EOF);
    }

    if this_dir{
        if check_flag!(packet.flags, PACKET_FLAGS_TOSERVER){
            add_flag!(flag, APPLAYER_FLAGS_STREAM_TOSERVER);
        }else{
            add_flag!(flag, APPLAYER_FLAGS_STREAM_TOCLIENT);
        }
    }else{// opposing dir
        if check_flag!(packet.flags, PACKET_FLAGS_TOSERVER){
            add_flag!(flag, APPLAYER_FLAGS_STREAM_TOCLIENT);
        }else{
            add_flag!(flag, APPLAYER_FLAGS_STREAM_TOSERVER);
        }
    }

    if check_flag!(stream.stream_flags, STREAM_FLAGS_DEPTH_REACHED){
        add_flag!(flag, APPLAYER_FLAGS_STREAM_DEPTH);
    }

    return flag;
}

pub fn stream_applayer_hand_tcp_data(flow: &mut Flow, ssn: &TcpSession, stream: &mut Stream, flags: APPLAYER_FLAGS_TYPE, data: APPLAYER_DATA) -> bool{

    if check_flag!(ssn.stream_flags, STREAM_FLAGS_APPLAYER_DISABLED){
        debug!("{} with STREAM_FLAGS_APPLAYER_DISABLED is set, return it.", ssn);
        return true;
    }

    let alproto = if check_flag!(flags, APPLAYER_FLAGS_STREAM_TOSERVER){
        flow.alproto_ts.clone()
    }else if check_flag!(flags, APPLAYER_FLAGS_STREAM_TOCLIENT){
        flow.alproto_tc.clone()
    }else{
        error!("stream_applayer_hand_tcp_data, but the flags not with dir info.");
        return false;
    };

    if check_flag!(flags, APPLAYER_FLAGS_STREAM_GAP){
        if alproto == ApplayerProto::APPLAYER_UNKNOWN{
            add_flag!(stream.stream_flags, STREAM_FLAGS_APPPROTO_DETECTION_COMPLETED);
            debug!("APPLAYER_UNKNOWN {} du to GAP in stream start.", flow);
        }else{
            do_call_applayer_parser_to_parse(flags, data, flow.alproto.clone());
        }
        return true;
    }

    if alproto == ApplayerProto::APPLAYER_UNKNOWN &&
        check_flag!(flags, APPLAYER_FLAGS_STREAM_START){
        tcp_proto_detect();
        return false;
    }else if (alproto != ApplayerProto::APPLAYER_UNKNOWN) &&
        (flow_change_protocol(flow)){
        flow.alproto_orig = flow.alproto.clone();
        debug!("protocol change, old {} ", flow.alproto_orig);
        applayer_proto_detect_reset(flow);
        tcp_proto_detect();

        // follow suricata, some event handle, ignore it .
    }else{
        if flow.alproto != ApplayerProto::APPLAYER_UNKNOWN{
            do_call_applayer_parser_to_parse(flags, data, flow.alproto.clone());
        }
    }

    return true;
}

fn do_call_applayer_parser_to_parse(flags: APPLAYER_FLAGS_TYPE, data: APPLAYER_DATA, alproto: ApplayerProto){
    // follow suricata, call AppLayerParserParse
}

fn tcp_proto_detect(){
    // follow suricata, call TCPProtoDetect
}

fn applayer_proto_detect_reset(flow: &Flow){
    // follow suricata, call applayer_proto_detect_reset
}
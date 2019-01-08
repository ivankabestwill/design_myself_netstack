
use std::rc::Rc;
use std::cell::RefCell;
use capture::pkthdr;
use flow::{Packet, PacketData, new_packet};
use tools::read_u16_from_networkendian_slice;
use thread::ThreadVar;


use ::eth::{Eth};
use ::flow::{PACKET_FLAGS_NONE,FlowHash};

pub struct Data{
    pub hdr: pkthdr,
    pub buf: Rc<Vec<u8>>,
}

impl Data{
    //pub fn save(&self) {}; // save in pcap file

    pub fn decode_to_eth(self, threadvar: Rc<RefCell<ThreadVar>>) -> Result<Packet, String>{

        let mut after_mac: u16 = 0;
        read_u16_from_networkendian_slice(&self.buf[12..14], &mut after_mac);

        if after_mac == 0x0800 {
            let buf = Rc::clone(&self.buf);
            let buf = &buf[14..];
            let buf = buf.to_vec();
            let buf = Rc::new(buf);

            let buf1 = Rc::clone(&self.buf);
            let buf1 = &buf1[0..6];
            let buf1 = buf1.to_vec();
            let buf1 = buf1.clone();

            let buf2 = Rc::clone(&self.buf);
            let buf2 = &buf2[6..12];
            let buf2 = buf2.to_vec();
            let buf2 = buf2.clone();

            let pkt_len = self.hdr.caplen as usize;

            let eth = Eth {
                data: Rc::new(RefCell::new(self)),
                buf: Rc::clone(&buf),
                dst_mac: buf1,
                src_mac: buf2,
            };

            let flow_hash = FlowHash{
                src_ip: 0,
                dst_ip: 0,
                src_port: 0,
                dst_port: 0,
                protocol: 0,
            };

            let packet = Packet{
                flags: PACKET_FLAGS_NONE,
                data: Some(PacketData::PacketEth(Rc::new(RefCell::new(eth)))),
                flow: None,
                flow_hash: flow_hash,
                ts: 0,
                threadvar: threadvar,
                pkt_len: pkt_len,
            };

            return Ok(packet);
        }else {
            // println!("not ipv4");
            return Err("ipv4 only".to_string());
        }
    }
}


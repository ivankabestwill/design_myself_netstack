
use std::rc::Rc;
use std::cell::RefCell;
use capture::pkthdr;
use packet::{Packet, PacketData, new_packet};
use tools::read_u16_from_networkendian_slice;
use thread::ThreadVar;


use ::eth::{Eth};
use ::flow::{FlowHash, new_flow_hash};
use ::packet::{LayerDataLink, new_packetdata_data};


pub struct Data{
    pub hdr: pkthdr,
    pub buf: Vec<u8>,
}


impl Data{
    //pub fn save(&self) {}; // save in pcap file

    pub fn decode_to_eth(self, threadvar: Rc<ThreadVar>) -> Option<Packet>{

        let mut after_mac: u16 = 0;
        read_u16_from_networkendian_slice(&self.buf[12..14], &mut after_mac);

        if after_mac == 0x0800{
            let dst_mac = Vec::from(&self.buf[0..6]);;
            let src_mac = Vec::from(&self.buf[6..12]);

            let pkt_len = self.hdr.caplen as usize;

            let eth = Eth {
                data_offset: 14,
                dst_mac: dst_mac,
                src_mac: src_mac,
            };

            let flow_hash = new_flow_hash();

            let mut packet = new_packet(threadvar);

            packet.pkt_len = pkt_len;
            packet.flow_hash = Some(Rc::new(RefCell::new(flow_hash)));

            let mut data = new_packetdata_data(self);
            data.layer_data_link = Some(LayerDataLink::data_eth(Rc::new(eth)));
            packet.data = data;

            return Some(packet);
        }else {
            warn!("decode_to_eth only accept ipv4.");
            return None;
        }
    }
}


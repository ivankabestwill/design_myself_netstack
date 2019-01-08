
extern crate libc;
extern crate byteorder;
extern crate core;

#[macro_use]
extern crate log;
extern crate log4rs;

use std::path::{Path};
use std::rc::Rc;
use std::cell::RefCell;
use std::collections::HashMap;

mod config;
#[macro_use]
mod tools;

mod capture;
mod data;
#[macro_use]
mod tcp;
mod eth;
mod ipv4;

mod flow;
mod tcp_stream_state;
mod thread;
mod tcp_stream;

mod applayer;

use capture::{Capture};
use data::Data;
use tools::{print_addr};
use thread::{ThreadVar, new_thread_var};
use flow::{flow_hand, Packet};
use flow::{PACKET_FLAGS_NONE, PACKET_FLAGS_TOSERVER_FIRST, PACKET_FLAGS_TOCLIENT_FIRST, PacketData};
use self::PacketData::{PacketNone, PacketIpv4, PacketEth, PacketTcp};

fn main() {
   match log4rs::init_file(Path::new("./log4rs.yml"), Default::default()){
        Ok(_) => {},
        Err(why) => {println!("log4rs init err."); return;},
    }

    let threadvars = new_thread_var();

    let mut mycapture = Capture::new("enp1s0f0".to_string());
    match mycapture.open(){
        Ok(_) => {},
        Err(why) => {println!("capture open err: {}", why); return;},
    }

    let rc_refcell_threadvars = Rc::new(RefCell::new(threadvars));

   loop {
       let data = match mycapture.next() {
           Some(t) => { t },
           None => {
               println!("capture next none.");
               continue;
           },
       };

       let mut packet = match data.decode_to_eth(Rc::clone(&rc_refcell_threadvars)) {
           Ok(t) => { t },
           Err(_e) => { continue; },
       };

       let rc_ref_eth = match packet.data{
           Some(ref packet_data) => {
                match packet_data{
                    PacketData::PacketEth(ref eth) => {Rc::clone(eth)},
                    _ => {continue;},
                }
           },
           None => {continue;},
       };

       if !packet.decode_to_ipv4(rc_ref_eth) {
           continue;
       }

       let rc_ref_ipv4 = match packet.data{
           Some(ref packet_data) => {
                match packet_data {
                    PacketData::PacketIpv4(ref ipv4) => {Rc::clone(ipv4)},
                    _ => {continue;},
                }
           },
           None => {continue;},
       };
       /*println!("eth: smac {:X}:{:X}:{:X}:{:X}:{:X}:{:X} dmac {:X}:{:X}:{:X}:{:X}:{:X}:{:X}",
                eth.src_mac[0], eth.src_mac[1], eth.src_mac[2], eth.src_mac[3], eth.src_mac[4], eth.src_mac[5],
                eth.dst_mac[0], eth.dst_mac[1], eth.dst_mac[2], eth.dst_mac[3], eth.dst_mac[4], eth.dst_mac[5]);*/

       //println!("ipv4: sip {} dip {} protocol {}", print_addr(ipv4.src_ip), print_addr(ipv4.dst_ip), ipv4.protocol);

        match packet.flow_hash.protocol {
           _IPPROTO_TCP => {
               if !packet.decode_to_tcp(rc_ref_ipv4) {
                   continue;
               }
           },
           _ => { continue; },
        }

        flow_hand(&mut packet);
   }
}


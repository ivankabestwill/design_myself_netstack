#![feature(linked_list_extras)]

extern crate libc;
extern crate byteorder;
extern crate core;
#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate log;
extern crate log4rs;

use std::path::{Path};
use std::rc::Rc;
use std::collections::HashMap;

mod config;
#[macro_use]
mod tools;
#[macro_use]
mod packet;

mod capture;
mod data;
#[macro_use]
mod tcp;
mod eth;
mod ipv4;
#[macro_use]
mod flow;
mod tcp_stream_state;
mod thread;
mod tcp_stream;

mod applayer;

use capture::{Capture};
use data::Data;
use tools::{print_addr};
use thread::{ThreadVar, new_thread_var};
use flow::{flow_hand, statistic_flow};
use packet::{Packet, new_packet};
use packet::{PACKET_FLAGS_NONE, PACKET_FLAGS_TOSERVER_FIRST, PACKET_FLAGS_TOCLIENT_FIRST, PacketData};

fn main() {

   match log4rs::init_file(Path::new("./log4rs.yml"), Default::default()){
        Ok(_) => {},
        Err(why) => {println!("log4rs init err."); return;},
    }

    let mut threadvars = new_thread_var();
    let rc_threadvars = Rc::new(threadvars);

    let mut mycapture = Capture::new("enp1s0f0".to_string());
    match mycapture.open(){
        Ok(_) => {},
        Err(why) => {println!("capture open err: {}", why); return;},
    }

   loop {
       statistic_flow();

       let data = match mycapture.next() {
           Some(t) => { t },
           None => {
               println!("capture next none.");
               continue;
           },
       };

       if let Some(mut packet) = data.decode_to_eth(Rc::clone(&rc_threadvars)){
            if !packet.decode_to_ipv4(){
                continue;
            }

           let flowhash = if let Some(ref fh) = packet.flow_hash {
               Rc::clone(fh)
           }else{
               continue;
           };

           match flowhash.borrow().protocol {
               _IPPROTO_TCP => {
                   if !packet.decode_to_tcp() {
                       continue;
                   }
               },
               _ => { continue; },
           }

           flow_hand(&mut packet);

       }else{
           continue;
       }



       /*println!("eth: smac {:X}:{:X}:{:X}:{:X}:{:X}:{:X} dmac {:X}:{:X}:{:X}:{:X}:{:X}:{:X}",
                eth.src_mac[0], eth.src_mac[1], eth.src_mac[2], eth.src_mac[3], eth.src_mac[4], eth.src_mac[5],
                eth.dst_mac[0], eth.dst_mac[1], eth.dst_mac[2], eth.dst_mac[3], eth.dst_mac[4], eth.dst_mac[5]);*/

       //println!("ipv4: sip {} dip {} protocol {}", print_addr(ipv4.src_ip), print_addr(ipv4.dst_ip), ipv4.protocol);


   }
}



extern crate libc;

use std;
use std::rc::Rc;
use libc::{c_int, c_char, c_uint, timeval, c_uchar};
use data::{Data};



#[repr(C)]
#[derive(Copy, Clone)]
pub struct pkthdr {
    pub ts: timeval,
    pub caplen: c_uint,
    pub len: c_uint,
}

pub enum PcapT{}

#[cfg(not(windows))]
#[link(name="pcap")]


extern "C" {
    fn pcap_create(dev_name: *mut c_uchar, err: *mut c_char) -> *mut PcapT;
    fn pcap_close(arg1: *mut PcapT);
    fn pcap_set_snaplen(handle: *mut PcapT, len: c_int) -> c_int;
    fn pcap_set_promisc(handle: *mut PcapT, val: c_int) -> c_int;
    fn pcap_set_immediate_mode(handle: *mut PcapT, val: c_int) -> c_int;
    fn pcap_activate(handle: *mut PcapT) -> c_int;
    fn pcap_next_ex(handle: *mut PcapT, header: *mut *mut pkthdr, data: *mut *const c_uchar) -> c_int;
}

pub struct Capture{
    dev: String,
    handle: * mut PcapT,
}



impl Capture{
    pub fn new(dev: String) -> Capture{
        let tmphandle: *mut PcapT = std::ptr::null_mut();
        let tmpcapture = Capture {
            dev: dev,
            handle: tmphandle,
        };

        tmpcapture
    }

    pub fn open(&mut self) -> Result<(), String>{

        let mut tmpdev = String::new();
        let dev = "enp3s0";

        tmpdev.push_str(dev );
        tmpdev.push_str("\0");
        let tmperrinfo = [0u8; 257];

        let tmphandle = unsafe{pcap_create(tmpdev.as_ptr() as *mut u8, tmperrinfo.as_ptr() as _)};
        if tmphandle.is_null() {
            return Err("pcap_create err".to_string());
        }else {
            self.handle = tmphandle;
        }

        let ret = unsafe { pcap_set_immediate_mode(self.handle, 0 as c_int) };
        if ret < 0 {
            unsafe{pcap_close(self.handle)};
            return Err("pcap_set_immediate_mode err".to_string());
        }

        let ret = unsafe { pcap_set_snaplen(self.handle, 65535) };
        if ret < 0 {
            unsafe{pcap_close(self.handle)};
            return Err("pcap_set_snaplen err".to_string());
        }

        let ret = unsafe { pcap_set_promisc(self.handle, 1) };
        if ret < 0 {
            unsafe{pcap_close(self.handle)};
            return Err("pcap_set_promisc err".to_string());
        }

        let ret = unsafe { pcap_activate(self.handle) };
        if ret < 0 {
            unsafe{pcap_close(self.handle)};
            let err = std::io::Error::last_os_error();
            let errinfo = format!("{:?}", err);
            let errinfo = format!("pcap_activate err: {:?}", errinfo);
            return Err(errinfo);
        }

        return Ok(());
    }


    pub fn next(&self) -> Option<Data>{

        let mut header: *mut pkthdr = std::ptr::null_mut();
        let mut data: *const c_uchar = std::ptr::null_mut();

        let ret = unsafe { pcap_next_ex(self.handle, &mut header, &mut data) };
        if ret < 0 {
            return None;
        } else if ret == 0 {
            return None;
        }

        if header.is_null() || data.is_null() {
            return None;
        }

        let tmphdr = unsafe { *header };
        let tmpslice = unsafe {std::slice::from_raw_parts(data, tmphdr.caplen as _)};
        let tmpvec1: Vec<u8> = tmpslice.to_vec();
        let tmpvec = tmpvec1.clone();
        Some(Data{
            hdr: tmphdr,
            buf: tmpvec,
        })
    }

}
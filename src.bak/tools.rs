



use std;
use byteorder::{ByteOrder,BigEndian};

#[macro_export]
macro_rules! check_flag{
    ($value:expr,$flag:expr) => {
        if ($value & $flag) != 0{
            true
        }else{
            false
        }
    }
}
#[macro_export]
macro_rules! add_flag{
    ($value:expr,$flag:expr) => {
        $value |= $flag
    }
}
#[macro_export]
macro_rules! del_flag{
    ($value:expr,$flag:expr) => {
        $value &= !$flag
    }
}



pub fn write_u32_to_networkendian_slice(buf: &mut [u8], data: u32){
    BigEndian::write_u32(buf, data);
}

pub fn write_u16_to_networkendian_slice(buf: &mut [u8], data: u16){
    BigEndian::write_u16(buf, data);
}

pub fn write_u8_to_slice(buf: &mut [u8], data: u8){
    buf[0] = data;
}

pub fn get_u32_from_networkendian_slice(buf: &[u8]) -> u32{
    return BigEndian::read_u32(buf);
}

pub fn read_u32_from_networkendian_slice(buf: &[u8], data: &mut u32){
    *data = BigEndian::read_u32(buf);
}

pub fn read_u16_from_networkendian_slice(buf: &[u8], data: &mut u16){
    *data = BigEndian::read_u16(buf);
}

pub fn get_u16_from_networkendian_slice(buf: &[u8]) -> u16{
    return BigEndian::read_u16(buf);
}

pub fn read_u8_from_slice(buf: &[u8], data: &mut u8){
    *data = buf[0];
}

pub fn print_addr(ip: u32) -> String{

    let mut tmparray:[u8;4] = [0;4];
    let tmpslice = &mut tmparray[..];
    write_u32_to_networkendian_slice(tmpslice, ip);
    let tmp = format!("{}.{}.{}.{}", tmpslice[0], tmpslice[1], tmpslice[2], tmpslice[3]);

    tmp
}
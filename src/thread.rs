
use std::thread::ThreadId;
use std::thread;
use std::collections::HashMap;
use std::rc::Rc;


use config::{Config};
use flow::{FlowHash, Flow};

pub struct ThreadVar{
    pub id: ThreadId,
}

thread_local! {
   pub static threadvar: ThreadVar = new_thread_var();
}

pub fn new_thread_var() -> ThreadVar{
    let thread = ThreadVar{
        id: std::thread::current().id(),
    };


    return thread;
}


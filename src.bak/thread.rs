
use std::thread::ThreadId;
use std::thread;
use std::collections::HashMap;
use std::rc::Rc;
use std::cell::RefCell;

use config::{Config};
use flow::{FlowHash, Flow};

pub struct ThreadVar{
    pub flowhash: HashMap<FlowHash, Rc<RefCell<Flow>>>,
    pub id: ThreadId,
}

pub fn new_thread_var() -> ThreadVar{
    ThreadVar{
        flowhash: HashMap::new(),
        id: std::thread::current().id(),
    }
}

pub fn thread_init(){



}
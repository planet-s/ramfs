#![feature(try_reserve)]

use std::fs::File;
use std::io::prelude::*;
use std::env;

use syscall::{CloneFlags, Packet, SchemeMut};

mod filesystem;
mod scheme;

use self::scheme::Scheme;

fn main() {
    let scheme_name = env::args().nth(1).expect("Usage:\n\tramfs SCHEME_NAME");
    let mut socket = File::create(format!(":{}", scheme_name)).expect("ramfs: failed to create socket");

    if unsafe { syscall::clone(CloneFlags::empty()) }.expect("ramfs: failed to fork") != 0 {
        return;
    }

    let mut scheme = Scheme::new(scheme_name).expect("ramfs: failed to initialize scheme");

    loop {
        let mut packet = Packet::default();
        match socket.read(&mut packet) {
            Ok(0) => break,
            Ok(_) => (),
            Err(error) => panic!("ramfs: failed to read from socket: {:?}", error),
        }
        scheme.handle(&mut packet);

        match socket.write(&packet) {
            Ok(0) => break,
            Ok(_) => (),
            Err(error) => panic!("ramfs: failed to write to socket: {:?}", error),
        }
    }
}

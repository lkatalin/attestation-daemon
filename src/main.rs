extern crate dcap_ql;

use std::net::{TcpListener, TcpStream};
use std::io::{self, Read, Write};

fn main() {
    println!("Daemon listening on port 1034... ");

    // listen for attestation request from client
    for stream in TcpListener::bind("localhost:1034").unwrap().incoming() {
        match stream {
            Ok(stream) => {
                println!("New connection for daemon: {}", stream.peer_addr().unwrap());
                let qe_id = dcap_ql::target_info().unwrap();
                println!("QE ID is: {:?}", qe_id);

                // send QE identity to enclave (server)
                match TcpStream::connect("localhost:1032") {
                    Ok(mut stream) => {
                        match stream.write(&qe_id.as_ref()) {
                            Ok(_) => (),
                            Err(e) => panic!("Error sending QE ID to enclave: {}", e),
                        };
                    },
                    Err(_) => {
                        panic!("Daemon unable to connect to client.");
                    }
                };
            }
            Err(e) => {
                println!("Daemon error connecting to stream: {}", e);
            }
        }
    }
}

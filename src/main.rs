extern crate dcap_ql;

use std::net::{TcpListener, TcpStream};
use std::io::{self, Read, Write};
use sgx_isa::{Report, Targetinfo};

fn main() {
    println!("Daemon listening on port 1034... ");

    // listen for attestation request from client
    for stream in TcpListener::bind("localhost:1034").unwrap().incoming() {
        match stream {
            Ok(stream) => {
                println!("New connection for daemon: {}", stream.peer_addr().unwrap());
                let qe_id = dcap_ql::target_info().unwrap();

                // send QE identity to enclave (server)
                match TcpStream::connect("localhost:1032") {
                    Ok(mut stream) => {
                        match stream.write(&qe_id.as_ref()) {
                            Ok(_) => (),
                            Err(e) => panic!("Error sending QE ID to enclave: {}", e),
                        };

                        // read report back from enclave
                        let mut encl_report = [0; sgx_isa::Report::UNPADDED_SIZE];
                        match stream.read_exact(&mut encl_report) {
                            Ok(_) => {
                                let encl_report = sgx_isa::Report::try_copy_from(&encl_report).unwrap();

                                let quote = dcap_ql::quote(&encl_report);

                                match quote {
                                    Ok(q) => {
                                        println!("Quote successfully generated.");
                                        println!("{:?}", q);
                                    },
                                    Err(e) => {
                                        panic!("Error generating quote.");
                                    },
                                };
                            },
                            Err(e) => {
                                panic!("Unable to read report back from enclave.");
                            },
                        };
                    }

                    Err(e) => {
                        panic!("Daemon unable to connect to client: {}", e);
                    }
                };
            }
            Err(e) => {
                println!("Client unable to connect to daemon: {}", e);
            }
        }
    }
}

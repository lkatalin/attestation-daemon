extern crate dcap_ql;

use std::net::{TcpListener, TcpStream};
use std::io::{self, Read, Write};
use sgx_isa::{Report, Targetinfo};
use dcap_ql::quote::*;

fn main() {
    println!("Daemon listening on port 1034... ");

    // listen for attestation request from client
    for stream_client in TcpListener::bind("localhost:1034").unwrap().incoming() {
        match stream_client {
            Ok(stream_client) => {
                println!("New connection for daemon: {}", stream_client.peer_addr().unwrap());
                let qe_id = dcap_ql::target_info().unwrap();

                // send QE identity to enclave (server)
                match TcpStream::connect("localhost:1032") {
                    Ok(mut stream_enclave) => {
                        match stream_enclave.write(&qe_id.as_ref()) {
                            Ok(_) => (),
                            Err(e) => panic!("Error sending QE ID to enclave: {}", e),
                        };

                        // read report back from enclave
                        let mut encl_report = [0; sgx_isa::Report::UNPADDED_SIZE];
                        match stream_enclave.read_exact(&mut encl_report) {
                            Ok(_) => {
                                let encl_report = sgx_isa::Report::try_copy_from(&encl_report).unwrap();

                                // get a quote from QE for the enclave's report
                                let quote = dcap_ql::quote(&encl_report);

                                match quote {
                                    Ok(q) => {
                                        println!("Quote successfully generated.");
                                        //println!("{:?}", q);

                                        // test attempt to parse quote
                                        let quote = dcap_ql::quote::Quote::parse(&q).unwrap();
                                        let sig = quote
                                            .signature::<dcap_ql::quote::Quote3SignatureEcdsaP256>()
                                            .unwrap();

                                        
                                        let encl_rep_sig = sig.signature();

                                        let att_pub_key = sig.attestation_public_key();

                                        let certdata = sig.certification_data::<Qe3CertDataPckCertificateChain>().unwrap();

                                        println!("Cert Data: {:?}", certdata);

                                        //let sig = quote.signature::<Quote3SignatureEcdsaP256>().unwrap();


                                        //println!("{:?}", sig);
                                        
                                        // send quote back to client
                                        //match stream_client.write(&q.as_ref()) {
                                        //    Ok(_) => (),
                                        //    Err(e) => panic!("Error sending quote back to client: {}", e),
                                        //};
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

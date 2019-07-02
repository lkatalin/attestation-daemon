extern crate dcap_ql;

use std::net::{TcpListener, TcpStream};
use std::io::{self, Read, Write};
use sgx_isa::{Report, Targetinfo};
use dcap_ql::quote::*;
use signatory_ring::ecdsa::p256::*;
use signatory::ecdsa::PublicKey;

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
                                        // println!("{:X?}", q);

                                        // get parsable quote
                                        let quote = dcap_ql::quote::Quote::parse(&q).unwrap();

                                        // extract quote signature data struct
                                        let sig = quote
                                            .signature::<Quote3SignatureEcdsaP256>()
                                            .unwrap();

                                        // extract quote header
                                        let quote_header = quote
                                            .header();

                                        // some parsing of quote sig data struct
                                        let encl_report_body = quote.report_body();
                                        let encl_report_sig = sig.signature();
                                        let qe_report = sig.qe3_report();
                                        let qe_report_sig = sig.qe3_signature();
                                        let att_key = sig.attestation_public_key();
                                        let certdata = sig.certification_data::<Qe3CertDataPckCertificateChain>().unwrap();

                                        // debugging print statements
                                        //println!("encl rep body: {:X?}\n", encl_report_body);
                                        //println!("encl rep sig: {:X?}\n", encl_report_sig);
                                        //println!("qe rep: {:X?}\n", qe_report);
                                        //println!("qe rep sig: {:X?}\n", qe_report_sig);
                                        //println!("att key: {:X?}\n", att_key);
                                        
                                    },
                                    Err(_e) => {
                                        panic!("Error generating quote.");
                                    },
                                };
                            },
                            Err(_e) => {
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

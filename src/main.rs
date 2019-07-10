extern crate dcap_ql;

use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write};
use sgx_isa::{Report};
use dcap_ql::quote::*;
//use openssl::x509::*;
//use openssl::x509::store::X509StoreBuilder;
//use openssl::stack::Stack;
//use openssl::ec::EcKey;
//use openssl::nid::Nid;
//use openssl::pkey::PKey;
//use openssl::sign::Verifier;
//use openssl::ec::EcPoint;
//use openssl::bn::BigNumContext;
//use std::ops::DerefMut;
//use openssl::ec::EcGroup;
//use openssl::hash::MessageDigest;


fn handle_client_init(stream_client: TcpStream) {
    println!("New connection for daemon: {}", stream_client.peer_addr().unwrap());
}


fn connect_to_enclave() -> Result<TcpStream> {
    let mut enclave_cnx = TcpStream::connect("localhost:1032")
        .expect("Could not connect to enclave on 1032");

    Ok(enclave_cnx)
}

fn send_qe_ti(mut cnx: &TcpStream) -> Result<()> {
    // retrieve QE target info
    let qe_ti = dcap_ql::target_info().unwrap();
 
    // send target info to enclave
    cnx.write(&qe_ti.as_ref())
        .expect("Could not send QE's target info to enclave on 1032");
    
    Ok(())
}

fn receive_report(mut cnx: TcpStream) -> Result<Report> {
    let mut encl_report = [0; sgx_isa::Report::UNPADDED_SIZE];

    cnx.read_exact(&mut encl_report)
        .expect("Could not read report from enclave on 1032");

    let report = sgx_isa::Report::try_copy_from(&encl_report)
        .expect("Could not create report from enclave data");

    Ok(report)
}

fn generate_quote(report: &sgx_isa::Report) -> std::vec::Vec<u8> {
    let quote = dcap_ql::quote(report).unwrap();

    println!("Quote successfully generated");
    quote
}

fn main() -> std::result::Result<(), std::io::Error> {
    println!("Daemon listening for client request on port 1034... ");

    // listen for attestation request from client
    for stream_client in TcpListener::bind("localhost:1034").unwrap().incoming() {
        match stream_client {
            Ok(stream_client) => {
                handle_client_init(stream_client);

                let mut enclave_cnx = connect_to_enclave().unwrap();
                send_qe_ti(&enclave_cnx);

                let report = receive_report(enclave_cnx).unwrap();

                // get a quote from QE for the enclave's report
                let quote = generate_quote(&report);


//                                        // get parsable quote
//                                        let quote = dcap_ql::quote::Quote::parse(&quote).unwrap();
//
//                                        // extract quote signature data struct
//                                        let sig = quote
//                                            .signature::<Quote3SignatureEcdsaP256>()
//                                            .unwrap();
//
//                                        // extract quote header
//                                        let quote_header = quote
//                                            .header();
//
//                                        // some parsing of quote sig data struct
//                                        let encl_report_body = quote.report_body();
//                                        let encl_report_sig = sig.signature();
//                                        let _qe_report = sig.qe3_report();
//                                        let qe_report_sig = sig.qe3_signature();
//                                        let _att_key = sig.attestation_public_key();
//                                        let _certdata = sig.certification_data::<Qe3CertDataPckCertificateChain>().unwrap();
// 
//                                        // to do: let user choose root cert
//                                        
//                                        // load hardcoded external pck_cert file
//                                        let pck_cert = include_bytes!("../pck_cert.pem");
//                                        let pck_cert = X509::from_pem(pck_cert).ok().expect("Failed to load PCK cert");
//
//                                        // load intermed cert
//                                        let intermed_cert = include_bytes!("../pck_intermed_cert.pem");
//                                        let intermed_cert = X509::from_pem(intermed_cert).ok().expect("Failed to load intermed cert");
//
//                                        // load root cert
//                                        let root_cert = include_bytes!("../pck_root_cert.pem");
//                                        let root_cert = X509::from_pem(root_cert).ok().expect("Failed to load root cert");
//
//                                        // check issued relationships
//                                        let intermed_issued_pck = intermed_cert.issued(&pck_cert);
//                                        let root_issued_intermed = root_cert.issued(&intermed_cert);
//                                        println!("Intermed cert issued PCK: {}", intermed_issued_pck);
//                                        println!("Root cert issued intermed: {}", root_issued_intermed);
//
//                                        // check signature on 
//                                        let _pck_pub_key = pck_cert.public_key();
//                                        
//                                        // create cert chain
//                                        let mut chain = Stack::new().unwrap();
//
//                                        // add root to trusted store
//                                        let mut store_bldr = X509StoreBuilder::new().unwrap();
//                                        store_bldr.add_cert(root_cert).unwrap();
//                                        let store = store_bldr.build();
//
//                                        // create context to verify cert
//                                        let mut context = X509StoreContext::new().unwrap();
//                                        assert!(context
//                                            .init(&store, &intermed_cert, &chain, |c| c.verify_cert())
//                                            .unwrap());
//                                        assert!(context
//                                            .init(&store, &intermed_cert, &chain, |c| c.verify_cert())
//                                            .unwrap());
//
//                                        // check that untrue verification fails
//                                        assert!(!context
//                                                .init(&store, &pck_cert, &chain, |c| c.verify_cert())
//                                                .unwrap());
//
//                                        // add intermed to context chain
//                                        let _ = chain.push(intermed_cert);
//
//
//                                        // check pck cert verification now
//                                        assert!(context
//                                                .init(&store, &pck_cert, &chain, |c| c.verify_cert())
//                                                .unwrap());
//                                    
//                                    
//                                        println!("PCK cert chain verified");
//
//                                        //let pck_pub = EcKey::from_curve_name(Nid::SECP256K1).unwrap();
//                                        
//                                        // parameters for AK
//                                        let ecgroup = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
//                                        let mut empty_context = BigNumContext::new().unwrap();
//                                        let empty_context = empty_context.deref_mut(); 
//
//                                        // AK transform EcPoint --> EcKey --> PKey --> Verifier
//                                        let att_key = EcPoint::from_bytes(&ecgroup, _att_key, empty_context).unwrap();
//                                        let att_key = EcKey::from_public_key(&ecgroup, &att_key).unwrap();
//                                        let att_key = PKey::from_ec_key(att_key).unwrap();
//                                        
//                                        let msgdgst = MessageDigest::from_nid(Nid::X9_62_PRIME256V1).unwrap();
//                                        let mut att_key_verifier = Verifier::new(msgdgst, &att_key).unwrap();
//
//                                        // test verifer
//                                        //att_key_verifier.update(&quote_header[..]).unwrap();
//                                        att_key_verifier.update(encl_report_body).unwrap();
//                                        assert!(att_key_verifier.verify(&encl_report_sig[..]).unwrap());
//

            },
            Err(e) => {
                println!("Client unable to connect to daemon: {}", e);
            },
        }
    };
    Ok (())
}

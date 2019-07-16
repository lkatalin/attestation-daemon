extern crate dcap_ql;

//use bytevec;
use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write};
use sgx_isa::{Report};
use dcap_ql::quote::*;
//use std::borrow::Cow;
//use std::env;
use std::fs;
use openssl::x509::*;
use openssl::x509::store::X509StoreBuilder;
use openssl::stack::Stack;
use openssl::ec::EcKey;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::sign::Verifier;
use openssl::ec::EcPoint;
use openssl::bn::BigNumContext;
use std::ops::DerefMut;
use openssl::ec::EcGroup;
use openssl::hash::MessageDigest;
//use byteorder::{ByteOrder, BigEndian, ReadBytesExt};
//use num_traits::cast::ToPrimitive;
//use read_byte_slice::{ByteSliceIter, FallibleStreamingIterator};
//use std::io::Cursor;
//use convert_base::Convert;


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

fn return_quote_sig<'a>(quote: &'a dcap_ql::quote::Quote<'a>) ->
        dcap_ql::quote::Quote3SignatureEcdsaP256<'a> {
    quote.signature::<Quote3SignatureEcdsaP256>().unwrap()
}

fn load_cert(file_path: &str) -> openssl::x509::X509 {
    let cert = fs::read_to_string(file_path)
        .expect("Failed to load file");
    
    openssl::x509::X509::from_pem(cert.as_bytes()).ok()
        .expect("Failed to load cert")
}

// TODO: process chain of arbitrary length
fn verify_chain_issuers(root_cert: &openssl::x509::X509, 
                        intermed_cert: &openssl::x509::X509, 
                        pck_cert: &openssl::x509::X509) {

    assert!(intermed_cert.issued(&pck_cert).as_raw() == 1, 
        "Intermed cert did not issue leaf cert in PCK chain");
    
    assert!(root_cert.issued(&intermed_cert).as_raw() == 1,
        "Root cert did not issue leaf cert in PCK chain");

    println!("Issuer relationships in PCK cert chain are valid.");
}

// TODO: process chain of arbitrary length
fn verify_chain_sigs(root_cert: openssl::x509::X509, 
                     intermed_cert: openssl::x509::X509, 
                     pck_cert: &openssl::x509::X509) {

    // create new cert chain object and context
    let mut chain = Stack::new().unwrap();
    let mut context = X509StoreContext::new().unwrap();
    
    // add root to trusted store
    let mut store_bldr = X509StoreBuilder::new().unwrap();
    store_bldr.add_cert(root_cert).unwrap();
    let store = store_bldr.build();
    
    // check that intermediate cert sig checks out in context with root cert
    assert!(context
        .init(&store, &intermed_cert, &chain, |c| c.verify_cert())
        .unwrap());

    // check that pck cert sig fails since intermed cert not yet added to context
    assert!(!context
        .init(&store, &pck_cert, &chain, |c| c.verify_cert())
        .unwrap());

    // add intermed to context chain
    let _ = chain.push(intermed_cert);
    
    // verify pck cert sig in context with intermed cert
    assert!(context
        .init(&store, &pck_cert, &chain, |c| c.verify_cert())
        .unwrap());

    //TODO: check root signature on itself
}

// TODO: set limit on number of intermediate certs
// fn check_chain_length {
//
// }

fn verify_AK_to_quote(ak: &[u8], quote_header: &dcap_ql::quote::QuoteHeader, 
                      report_body: &[u8], ak_sig: &[u8]) {

    // set curve and context
    let ecgroup = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let mut empty_context = BigNumContext::new().unwrap();
    let empty_context = empty_context.deref_mut(); 

    // import AK as EcPoint --> EcKey --> PKey
    let att_key = EcPoint::from_bytes(&ecgroup, ak, empty_context).unwrap();
    let att_key = EcKey::from_public_key(&ecgroup, &att_key).unwrap();
    let att_key = PKey::from_ec_key(att_key).unwrap();
                                        
    // AK as PKey --> Verifier
    let msgdgst = MessageDigest::from_nid(Nid::X9_62_PRIME256V1).unwrap();
    let mut att_key_verifier = Verifier::new(msgdgst, &att_key).unwrap();

    // verify signature of AK on quote_header + report_body
    //att_key_verifier.update(quote_header[..]).unwrap();
    //att_key_verifier.update(report_body).unwrap();
    //assert!(att_key_verifier.verify(&ak_sig).unwrap());
}

fn cast_u8_to_u16(num : u8 ) -> u16 { 
    num as u16
}

fn cast_u8vec_to_u16vec(vec : Vec<u8>) -> Vec<u16> {
    let mut u16vec = Vec::new();
    for num in vec {
        u16vec.push(cast_u8_to_u16(num));
    }
    u16vec
}

fn qheader_to_bytevec(header: dcap_ql::quote::QuoteHeader) -> Vec<u16> {
    let mut vec = Vec::new();
    match header {
        dcap_ql::quote::QuoteHeader::V3 {
            attestation_key_type,
            qe3_svn,
            pce_svn,
            qe3_vendor_id,
            user_data,
        } => {
            vec.push(3 as u16); // should be two bytes for "version"
            vec.push(attestation_key_type as u16);
            vec.push(qe3_svn.clone());
            vec.push(pce_svn.clone());
            println!("qe3vid: {:x?}", qe3_vendor_id);
            //let mut qe_vid = (**qe3_vendor_id).to_owned();
            //let qe_id_u16 = cast_u8vec_to_u16vec(qe_vid);
            //vec.extend(qe_id_u16);
            //let mut user_data = (**user_data).to_owned();
            //let user_data_u16 = cast_u8vec_to_u16vec(user_data);
            //vec.extend(user_data_u16);
        }
    }
    vec
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

                // get parseable quote
                let quote = dcap_ql::quote::Quote::parse(&quote).unwrap();

                // parse main quote
                let q_header = quote.header();
                let q_report_body = quote.report_body();
                let q_sig = return_quote_sig(&quote);

                // parse quote header
                // TODO
                let qvec = qheader_to_bytevec(**q_header.to_owned());
                println!("qvec is: {:x?}", qvec);

                // parse quote report body
                // TODO

                // parse quote sig
                let q_enclave_report_sig = q_sig.signature();
                let q_qe_report = q_sig.qe3_report();
                let q_qe_report_sig = q_sig.qe3_signature();
                let q_att_key_pub = q_sig.attestation_public_key();
                let q_cert_data = q_sig.certification_data::<Qe3CertDataPckCertificateChain>().unwrap();

                // TODO: let user choose root cert

                // load certs
                let pck_cert = load_cert("../pck_cert.pem");
                let intermed_cert = load_cert("../pck_intermed_cert.pem");
                let root_cert = load_cert("../pck_root_cert.pem");
                println!("PCK cert chain loaded.");
                
                // verify PCK certificate chain
                let _ = verify_chain_issuers(&root_cert, &intermed_cert, &pck_cert);
                let _ = verify_chain_sigs(root_cert, intermed_cert, &pck_cert);
                println!("PCK cert chain verified");

                // verify AK's signature on Quote
                verify_AK_to_quote(&q_att_key_pub, &q_header, &q_report_body, &q_enclave_report_sig);
                
                // verify PCK's signature on AKpub
                // verify_PCK_to_AK();
                //let _pck_pub_key = pck_cert.public_key();
                //let pck_pub = EcKey::from_curve_name(Nid::SECP256K1).unwrap();                           

            },
            Err(e) => {
                println!("Client unable to connect to daemon: {}", e);
            },
        }
    };
    Ok (())
}

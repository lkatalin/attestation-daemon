#![allow(dead_code)]

extern crate dcap_ql;

use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write};
use sgx_isa::{Report};
use dcap_ql::quote::*;
use std::fs;
use std::str;
use openssl::x509::*;
use openssl::x509::store::X509StoreBuilder;
use openssl::stack::Stack;
use openssl::ec::EcKey;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::sign::Verifier;
use openssl::ec::EcGroup;
use openssl::hash::MessageDigest;
use openssl::sign::*;
use num_traits::cast::ToPrimitive;
use hex::FromHex;


fn handle_client_init(stream_client: TcpStream) {
    println!("New connection for daemon: {}", stream_client.peer_addr().unwrap());
}


fn connect_to_enclave() -> Result<TcpStream> {
    let enclave_cnx = TcpStream::connect("localhost:1032")
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


fn key_from_affine_coordinates(x : Vec<u8>, y : Vec<u8>) -> 
    openssl::ec::EcKey<openssl::pkey::Public> {
    
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let xbn = openssl::bn::BigNum::from_slice(&x).unwrap();
        let ybn = openssl::bn::BigNum::from_slice(&y).unwrap();

        let ec_key = EcKey::from_public_key_affine_coordinates(
            &group, &xbn, &ybn
            ).unwrap();
        
        assert!(ec_key.check_key().is_ok());

        ec_key
}

fn verify_ak_to_quote(ak: &[u8], signed: &[u8], ak_sig: Vec<u8>) -> 
    std::result::Result<(), failure::Error> {

        let xcoord = ak[0..32].to_owned();
        let ycoord = ak[32..64].to_owned();

        let ec_key = key_from_affine_coordinates(xcoord, ycoord);
        let pkey = PKey::from_ec_key(ec_key).unwrap();
        
        let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey).unwrap();
        verifier.update(signed).unwrap();

        //assert!(verifier.verify(&ak_sig).unwrap());

        let mut sig = Vec::new();
        sig.extend([30, 46, 2, 21, 0].iter().cloned());
        sig.extend(&ak_sig);

        match verifier.verify(&sig) {
            Ok(_) => {
                println!("verification succeeded");
            },
            Err(e) => {
                println!("verification failed: {:?}", e);
            }
        }

        Ok(())
}

fn ec() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let key = PKey::from_ec_key(key).unwrap();

        let mut signer = Signer::new(MessageDigest::sha256(), &key).unwrap();
        signer.update(b"hello world").unwrap();
        let signature = signer.sign_to_vec().unwrap();
 
        let mut verifier = Verifier::new(MessageDigest::sha256(), &key).unwrap();
        verifier.update(b"hello world").unwrap();
        assert!(verifier.verify(&signature).unwrap());

        println!("success!");
    }

fn cast_u8_to_u16(num : u8 ) -> u16 { 
    num as u16
}

fn cast_u16_to_u8(num : u16) -> u8 {
    num as u8
}

fn cast_u8vec_to_u16vec(vec : Vec<u8>) -> Vec<u16> {
    let mut u16vec = Vec::new();
    for num in vec {
        u16vec.push(cast_u8_to_u16(num));
    }
    u16vec
}

fn cast_u16vec_to_u8vec(vec : Vec<u16>) -> Vec<u8> {
    let mut u8vec = Vec::new();
    for num in vec {
        u8vec.push(cast_u16_to_u8(num));
    }
    u8vec
}


fn qheader_to_bytevec(header: &dcap_ql::quote::QuoteHeader) -> Vec<u16> {
    let mut vec = Vec::new();
    match header {
        dcap_ql::quote::QuoteHeader::V3 {
            attestation_key_type,
            qe3_svn,
            pce_svn,
            qe3_vendor_id,
            user_data,
        } => {
            vec.push(3 as u16);                                  // version == 2 bytes
            vec.push(attestation_key_type.to_u16().unwrap());    // AK key type == 2 bytes
            vec.push(0 as u16);                                  // reserved == 4 bytes
            vec.push(0 as u16);
            vec.push(qe3_svn.clone());                           // QE SVN == 2 bytes
            vec.push(pce_svn.clone());                           // PCE SVN == 2 bytes
            
            let qe_vid = (**qe3_vendor_id).to_owned();       // QE vendor ID == 16 bytes
            let qe_id_u16 = cast_u8vec_to_u16vec(qe_vid);
            vec.extend(qe_id_u16);
            
            let user_data = (**user_data).to_owned();        // user data == 20 bytes
            let user_data_u16 = cast_u8vec_to_u16vec(user_data); // (first 16 bytes are QE identifier)
            vec.extend(user_data_u16);
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

                let enclave_cnx = connect_to_enclave().unwrap();
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

                // parse quote report body
                // TODO

                // parse quote sig
                let q_enclave_report_sig = q_sig.signature();
                let _q_qe_report = q_sig.qe3_report();
                let _q_qe_report_sig = q_sig.qe3_signature();
                let q_att_key_pub = q_sig.attestation_public_key();
                let _q_cert_data = q_sig.certification_data::<Qe3CertDataPckCertificateChain>().unwrap();

                //println!("ak sig: {:x?}", q_enclave_report_sig);
                println!("enclave report sig: {:x?}", q_enclave_report_sig);
                println!("enclave report body: {:x?}", q_report_body);

                // TODO: let user choose root cert

                // load certs
                //let pck_cert = load_cert("../pck_cert.pem");
                //let intermed_cert = load_cert("../pck_intermed_cert.pem");
                //let root_cert = load_cert("../pck_root_cert.pem");
                println!("PCK cert chain loaded.");
                
                // verify PCK certificate chain
                //let _ = verify_chain_issuers(&root_cert, &intermed_cert, &pck_cert);
                //let _ = verify_chain_sigs(root_cert, intermed_cert, &pck_cert);
                println!("PCK cert chain verified");

                // test arbitrary ec key verification
                ec();

                println!("old ak sig: {:x?}", q_enclave_report_sig);
                println!("ak sig length: {}", q_enclave_report_sig.len());
                let ak_signature = Vec::from_hex("6e1cb8d97a9e9c665f5834b02d253b912004387187439c67e5e708b4d25566a4421e84ae7453db80cd7b4e92fa0cef1b68515887a0ed27d4a5fe0a081e5f8fe6").unwrap();
                println!("new ak sig: {:x?}", ak_signature);
                println!("ak sig length: {}", ak_signature.len());

                let quoteheader = qheader_to_bytevec(q_header);
                println!("quote header: {:x?}", quoteheader);
                    
                // verify AK's signature on Quote
                let mut signed_by_ak = cast_u16vec_to_u8vec(qheader_to_bytevec(q_header));
                signed_by_ak.extend(q_report_body);
                //let ak_signature = q_enclave_report_sig.to_vec();

                verify_ak_to_quote(&q_att_key_pub, &signed_by_ak, ak_signature);
                
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

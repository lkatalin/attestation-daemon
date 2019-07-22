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

    // TODO: more verbose error message
    let cert = fs::read_to_string(file_path)
        .expect("Failed to read file");
    
    openssl::x509::X509::from_pem(cert.as_bytes()).ok()
        .expect("Failed to load cert from file: {}")
}

// TODO: process chain of arbitrary length
fn verify_chain_issuers(root_cert: &openssl::x509::X509, 
                        intermed_cert: &openssl::x509::X509, 
                        pck_cert: &openssl::x509::X509) {

    // TODO: probably want to print an error if it fails
    assert_eq!(intermed_cert.issued(&pck_cert), X509VerifyResult::OK);

    assert_eq!(root_cert.issued(&intermed_cert), X509VerifyResult::OK);
    
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
    
    println!("Signatures on certificate chain are valid.");
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


fn raw_ecdsa_to_asn1(ecdsa_sig: &Vec<u8>) -> Vec<u8> {
    let r = &ecdsa_sig[0..32];
    let s = &ecdsa_sig[32..64];

    // add check for top bit of first byte to be zero;
    // if not zero, add 0x00 padding

    let mut vec = Vec::new();
    vec.push(0x30); // beginning of ASN.1 encoding

    let rpad = 0; // change if padding 
    let spad = 0; // change if padding
    let asn1_marker_len = 4; // 2 bytes for r, 2 bytes for s
    let datalen = (32 * 2) + rpad + spad + asn1_marker_len;

    let rvec = r.to_vec();
    let svec = s.to_vec();

    vec.push(datalen);
    vec.push(0x02 as u8); // marks start of integer
    vec.push(rvec.len() as u8); // integer length
    vec.extend(rvec); // r value
    vec.push(0x02 as u8); // marks start of integer
    vec.push(svec.len() as u8); // integer length
    vec.extend(svec); // s value

    //println!("r: {:x?}, s: {:x?}", r, s);
    //println!("\n\nvec: {:x?}", vec);

    vec
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

        let asn1_ak_sig = raw_ecdsa_to_asn1(&ak_sig);

        match verifier.verify(&asn1_ak_sig) {
            Ok(s) => {
                println!("verification succeeded: {:?}", s);
            },
            Err(e) => {
                println!("verification failed: {:?}", e);
            }
        }

        //assert!(verifier.verify(&asn1_ak_sig).unwrap());

        Ok(())
}

fn verify_pck_to_ak(pck_cert: &openssl::x509::X509, qe_report_data_unhashed: &[u8], 
    qe_report_sig: &[u8]) {

        // verify signature
        let pkey = pck_cert.public_key().unwrap();

        let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey).unwrap();
        verifier.update(qe_report_data_unhashed).unwrap();
        
        let reportsig = raw_ecdsa_to_asn1(&qe_report_sig.to_vec());

        match verifier.verify(&reportsig) {
            Ok(s) => {
                println!("verification succeeded: {:?}", s); 
            },
            Err(e) => {
                println!("verification failed: {:?}", e); 
            }
        }

        // verify hash
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
                let q_sig = return_quote_sig(&quote); // is there a method for this?

                // parse quote sig
                let q_enclave_report_sig = q_sig.signature();
                let q_qe_report = q_sig.qe3_report();
                let q_qe_report_sig = q_sig.qe3_signature();
                let q_att_key_pub = q_sig.attestation_public_key();
                let q_auth_data = q_sig.authentication_data();
                //let _q_cert_data = q_sig.certification_data::<Qe3CertDataPckCertificateChain>().unwrap();


                // TODO: let user choose root cert

                // load certs
                let pck_cert = load_cert("pck_cert.pem");
                let intermed_cert = load_cert("pck_intermed_cert.pem");
                let root_cert = load_cert("pck_root_cert.pem");
                println!("PCK cert chain loaded.");
                
                // verify PCK certificate chain
                let _ = verify_chain_issuers(&root_cert, &intermed_cert, &pck_cert);
                let _ = verify_chain_sigs(root_cert, intermed_cert, &pck_cert);
                println!("PCK cert chain verified.");
                    
                // verify AK's signature on Quote
                let q_header_bytevec = qheader_to_bytevec(q_header);

                // concatenate AK's signed material
                let mut signed_by_ak = cast_u16vec_to_u8vec(q_header_bytevec);
                signed_by_ak.extend(q_report_body.to_vec());
                verify_ak_to_quote(&q_att_key_pub, &signed_by_ak, q_enclave_report_sig.to_vec());
                
                // verify PCK's signature on AKpub
                let mut qe_report_data = Vec::new();
                qe_report_data.extend(q_att_key_pub.to_vec());
                qe_report_data.extend(q_auth_data.to_vec());
                qe_report_data.extend(vec![0 as u8; 32]);
                //verify_pck_to_ak(&pck_cert, &qe_report_data, &q_qe_report_sig);

            },
            Err(e) => {
                println!("Client unable to connect to daemon: {}", e);
            },
        }
    };
    Ok (())
}

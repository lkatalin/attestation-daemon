extern crate dcap_ql;

use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write};
use sgx_isa::{Report};
use dcap_ql::quote::*;
use std::{fs, str};
use openssl::{ec::{EcKey, EcGroup}, 
              x509::*,
              nid::Nid,
              stack::Stack,
              pkey::PKey,
              sign::Verifier,
              hash::MessageDigest,
              sha};

fn handle_client_init(stream_client: TcpStream) {
    // TODO: add error handling
    println!("New connection for daemon on: {}", stream_client.peer_addr().unwrap());
}

fn connect_to_enclave() -> Result<TcpStream> {
    let enclave_cnx = TcpStream::connect("localhost:1032")
        .expect("Could not connect to enclave on 1032");

    Ok(enclave_cnx)
}

fn send_qe_targetinfo(mut cnx: &TcpStream) -> Result<()> {
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
    let mut store_bldr = store::X509StoreBuilder::new().unwrap();
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

// for ASN.1 DER, the top bit of the first byte of each encoding (r, s) must be zero
fn check_top_bit(val: [u8; 32]) -> Vec<u8> {
    let mut vec : Vec<u8> = Vec::new();

    // if the top bit is not zero, pad the slice with a 0x00 byte
    if 0b10000000 & &val[0] != 0 {
        vec.push(0x00 as u8);
        vec.extend(val.to_vec());
    } else {
        vec.extend(val.to_vec());
    }
    vec
}

// note: the ecdsa input could also be a Vec<u8>
fn raw_ecdsa_to_asn1(ecdsa_sig: &Vec<u8>) -> Vec<u8> {
    let mut r_init: [u8; 32] = Default::default();
    let mut s_init: [u8; 32] = Default::default();
    r_init.copy_from_slice(&ecdsa_sig[0..32]);
    s_init.copy_from_slice(&ecdsa_sig[32..64]);

    let r = check_top_bit(r_init);
    let s = check_top_bit(s_init);

    let r_len = r.len();
    let s_len = s.len();
    let asn1_marker_len = 4; // 2 bytes for r, 2 for s
    let datalen = r_len + s_len + asn1_marker_len; 

    let mut vec = Vec::new();
    vec.push(0x30);             // marks start of ASN.1 encoding
    vec.push(datalen as u8);    // remaining data length
    vec.push(0x02 as u8);       // marks start of integer
    vec.push(r_len as u8);      // integer length
    vec.extend(r);              // r value
    vec.push(0x02 as u8);       // marks start of integer
    vec.push(s_len as u8);      // integer length
    vec.extend(s);              // s value

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

        let asn1_ak_sig = raw_ecdsa_to_asn1(&ak_sig);

        match verifier.verify(&asn1_ak_sig) {
            Ok(s) => {
                println!("AK to Quote verification succeeded: {:?}", s);
            },
            Err(e) => {
                println!("AK to Quote verification failed: {:?}", e);
            }
        }

        assert!(verifier.verify(&asn1_ak_sig).unwrap());

        Ok(())
}

fn verify_pck_to_ak(pck_cert: &openssl::x509::X509, qe_report_body: &[u8], 
    qe_report_sig: &[u8], ak_pub: &[u8], qe_auth_data: &[u8]) {

        // verify signature
        let pkey = pck_cert.public_key().unwrap();

        let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey).unwrap();
        verifier.update(qe_report_body).unwrap();
        
        let reportsig = raw_ecdsa_to_asn1(&qe_report_sig.to_vec());

        match verifier.verify(&reportsig) {
            Ok(s) => {
                println!("PCK to AK verification succeeded: {:?}", s); 
            },
            Err(e) => {
                println!("PCK to AK verification failed: {:?}", e); 
            }
        }

        // verify hash
        let hashed_reportdata = &qe_report_body[320..352];
        let mut unhashed = Vec::new();
        unhashed.extend(ak_pub.to_vec());
        unhashed.extend(qe_auth_data.to_vec());

        let mut hasher = sha::Sha256::new();
        hasher.update(&unhashed);
        let hash = hasher.finish();

        assert_eq!(hash, hashed_reportdata);
        println!("QE Report's hash is valid (PCK signed AK).");
}
 
fn main() -> std::result::Result<(), std::io::Error> {
    println!("Daemon listening for client request on port 1034... ");

    // listen for attestation request from client
    for stream_client in TcpListener::bind("localhost:1034").unwrap().incoming() {
        match stream_client {
            Ok(stream_client) => {
                handle_client_init(stream_client);

                let enclave_cnx = connect_to_enclave().unwrap();
                let _ = send_qe_targetinfo(&enclave_cnx).expect("Could not send QE target info.");

                let report = receive_report(enclave_cnx).unwrap();

                // get a quote from QE for the enclave's report
                let quote = generate_quote(&report);

                // ISV enclave report signature's signed material == first 432 bytes of quote
                let ak_signed = &quote[0..432].to_vec();

                // make quote parseable and return quote signature
                let quote = dcap_ql::quote::Quote::parse(&quote).unwrap();
                let q_sig = return_quote_sig(&quote); // is there a method for this?

                // parse quote sig
                let q_enclave_report_sig = q_sig.signature();
                let q_qe_report = q_sig.qe3_report();
                let q_qe_report_sig = q_sig.qe3_signature();
                let q_att_key_pub = q_sig.attestation_public_key();
                let q_auth_data = q_sig.authentication_data();

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
                let _ = verify_ak_to_quote(&q_att_key_pub, &ak_signed, q_enclave_report_sig.to_vec())
                    .expect("Verification of AK signature on Quote failed");
                
                // verify PCK's signature on AKpub
                verify_pck_to_ak(&pck_cert, &q_qe_report, &q_qe_report_sig, &q_att_key_pub, &q_auth_data);

            },
            Err(e) => {
                println!("Client unable to connect to daemon: {}", e);
            },
        }
    };
    Ok (())
}

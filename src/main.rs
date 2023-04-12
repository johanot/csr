
use openssl::x509::{X509NameBuilder, X509Req, X509, X509Builder};
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::hash::MessageDigest;
use openssl::x509::extension::{AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage};
use chrono::{DateTime, Utc};
use std::error::Error;

const APP_NAME: &str = env!("CARGO_PKG_NAME");

fn main() {

    log::init(APP_NAME.to_string()).unwrap();

    let args = clap::App::new("wharfix")
    .arg(clap::Arg::with_name("path")
        .long("path")
        .help("Path to directory of static docker image specs")
        .takes_value(true)
        .required_unless_one(&["repo", "dbconnfile", "derivationoutput"]))
    .arg(clap::Arg::with_name("repo")
        .long("repo")
        .help("URL to git repository")
        .takes_value(true)
        .required_unless_one(&["path", "dbconnfile", "derivationoutput"]))
    .arg(clap::Arg::with_name("derivationoutput")
        .long("derivation-output")
        .help("Output which servable derivations need to produce to be valid")
        .takes_value(true)
        .required_unless_one(&["path", "repo", "dbconnfile"]))
    .arg(clap::Arg::with_name("target")
        .long("target")
        .help("Target path in which to checkout repos")
        .default_value("/tmp/wharfix")
        .required(false))
    .arg(clap::Arg::with_name("blobcachedir")
        .long("blob-cache-dir")
        .help("Directory in which to store persitent symlinks to docker layer blobs")
        .takes_value(true)
        .required(false))
    .arg(clap::Arg::with_name("substituters")
        .long("substituters")
        .help("Comma-separated list of nix substituters to pass directly to nix-build as 'substituters'")
        .takes_value(true)
        .required(false))
    .arg(clap::Arg::with_name("indexfilepath")
        .long("index-file-path")
        .help("Path to repository index file")
        .default_value("default.nix")
        .takes_value(true)
        .required(false))
    .arg(clap::Arg::with_name("indexfileisbuildable")
        .long("index-file-is-buildable")
        .help("Set if the provided index-file is a valid nix entrypoint by itself (i.e. don't use internal drv-wrapper)")
        .takes_value(false)
        .required(false))
    .arg(clap::Arg::with_name("sshprivatekey")
        .long("ssh-private-key")
        .help("Path to optional ssh private key file")
        .takes_value(true)
        .required(false))
    .arg(clap::Arg::with_name("addnixgcroots")
        .long("add-nix-gcroots")
        .help("Whether to add nix gcroots for blobs cached in blob cache dir")
        .takes_value(false)
        .required(false)
        .requires("blobcachedir"))
    .arg(clap::Arg::with_name("address")
        .long("address")
        .help("Listen address to open on <port>")
        .default_value("0.0.0.0")
        .required(false))
    .arg(clap::Arg::with_name("port")
        .long("port")
        .help("Listen port to open on <address>")
        .default_value("8088")
        .required(true));

}

pub fn issue_certificate_from_csr(
    name: &str,
    ca_private_key: &PKey<Private>,
    csr: &X509Req,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
) -> Result<X509, Box<dyn Error>> {
    // Build the X509 name of the issuer
    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_text("CN", name)?;
    let issuer_name = name_builder.build();

    // Create a new X509 certificate and set its issuer and subject
    let mut cert = X509::builder()?;
    cert.set_version(2)?;
    cert.set_not_before(Asn1Time::from_datetime(&not_before))?;
    cert.set_not_after(Asn1Time::from_datetime(&not_after))?;
    cert.set_issuer_name(&issuer_name)?;
    cert.set_subject_name(csr.subject_name())?;

    // Set the serial number of the certificate
    let serial_number = openssl::bn::BigNum::from_u32(1)?;
    cert.set_serial_number(&serial_number)?;

    // Set the public key of the certificate
    cert.set_pubkey(csr.public_key()?)?;

    // Add basic constraints
    let basic_constraints = BasicConstraints::new().ca().build()?;
    cert.append_extension(basic_constraints)?;

    // Add key usage
    let key_usage = KeyUsage::new().key_cert_sign().crl_sign().build()?;
    cert.append_extension(key_usage)?;

    // Add extended key usage
    let extended_key_usage =
        ExtendedKeyUsage::new().server_auth().client_auth().build()?;
    cert.append_extension(extended_key_usage)?;

    // Add authority key identifier
    let authority_key_identifier = AuthorityKeyIdentifier::new()
        .keyid(false)
        .issuer(false)
        .build(&cert.x509v3_context(None, None))?;
    cert.append_extension(authority_key_identifier)?;

    // Sign the certificate with the private key of the CA
    cert.sign(ca_private_key, MessageDigest::sha256())?;

    // Build and return the X509 certificate
    Ok(cert.build())
}

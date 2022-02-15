#[macro_use]
extern crate serde_derive;

use openssl::pkey;
use xml::{reader, writer};

pub mod c14n;
pub mod proto;

pub const DIGEST_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
pub const DIGEST_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
pub const DIGEST_SH224: &str = "http://www.w3.org/2001/04/xmldsig-more#sha224";
pub const DIGEST_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
pub const DIGEST_SHA512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";

pub const DIGEST_GOST256: &str = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256";
pub const DIGEST_GOST512: &str = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-512";

pub const TRANSFORM_ENVELOPED_SIGNATURE: &str =
    "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

pub const CANONICAL_1_0: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
pub const CANONICAL_1_0_COMMENTS: &str =
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
pub const CANONICAL_1_1: &str = "http://www.w3.org/2006/10/xml-c14n11";
pub const CANONICAL_1_1_COMMENTS: &str = "http://www.w3.org/2006/10/xml-c14n11#WithComments";
pub const CANONICAL_EXCLUSIVE_1_0: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
pub const CANONICAL_EXCLUSIVE_1_0_COMMENTS: &str =
    "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";

pub const SIGNATURE_RSA_MD5: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-md5";
pub const SIGNATURE_RSA_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
pub const SIGNATURE_RSA_SHA224: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224";
pub const SIGNATURE_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
pub const SIGNATURE_RSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
pub const SIGNATURE_RSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
pub const SIGNATURE_RSA_RIPEMD160: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160";
pub const SIGNATURE_ECDSA_SHA1: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1";
pub const SIGNATURE_ECDSA_SHA224: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224";
pub const SIGNATURE_ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
pub const SIGNATURE_ECDSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
pub const SIGNATURE_ECDSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";
pub const SIGNATURE_ECDSA_RIPEMD160: &str =
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-ripemd160";
pub const SIGNATURE_DSA_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#dsa-sha1";
pub const SIGNATURE_DSA_SHA256: &str = "http://www.w3.org/2009/xmldsig11#dsa-sha256";
pub const SIGNATURE_GOST_256: &str =
    "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256";
pub const SIGNATURE_GOST_512: &str =
    "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-512";

const SIGNATURE_ELEMENT_NAME: &str = "Signature";
const XMLDSIG_NAMESPACE: &str = "http://www.w3.org/2000/09/xmldsig#";

#[inline]
pub fn x509_name_to_string(name: &openssl::x509::X509NameRef) -> String {
    name.entries()
        .map(|e| {
            format!(
                "{}=\"{}\"",
                e.object().nid().short_name().unwrap_or_default(),
                match e.data().as_utf8() {
                    Ok(d) => d.to_string(),
                    Err(_) => String::new(),
                }
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

#[inline]
pub fn events_to_string(events: &[reader::XmlEvent]) -> String {
    let mut output = Vec::new();

    let emitter_config = writer::EmitterConfig {
        perform_indent: false,
        perform_escaping: false,
        write_document_declaration: true,
        autopad_comments: false,
        cdata_to_characters: true,
        line_separator: std::borrow::Cow::Borrowed("\n"),
        normalize_empty_elements: false,
        ..std::default::Default::default()
    };

    let mut output_writer = writer::EventWriter::new_with_config(&mut output, emitter_config);

    for event in events {
        if let Some(e) = event.as_writer_event() {
            output_writer.write(e).unwrap();
        }
    }

    String::from_utf8_lossy(&output).to_string()
}

fn decode_key(key_info: &proto::ds::KeyInfo) -> Result<pkey::PKey<pkey::Public>, String> {
    match key_info.keys_info.first() {
        Some(proto::ds::KeyInfoType::X509Data(x509data)) => {
            for x509_datum in &x509data.x509_data {
                if let proto::ds::X509Datum::Certificate(cert_data) = x509_datum {
                    let base64_data = cert_data.replace("\r", "").replace("\n", "");

                    let data = base64::decode_config(base64_data, base64::STANDARD_NO_PAD)
                        .map_err(|error| format!("error decoding X509 cert: {}", error))?;

                    let certificate = openssl::x509::X509::from_der(&data)
                        .map_err(|error| format!("error decoding X509 cert: {}", error))?;

                    return certificate
                        .public_key()
                        .map_err(|error| format!("error decoding X509 cert: {}", error));
                }
            }

            Err(format!("unsupported key: {:?}", x509data))
        }
        unsupported => Err(format!("unsupported key: {:?}", unsupported)),
    }
}

fn find_events_slice_by_id<'a>(
    events: &'a [reader::XmlEvent],
    id: &str,
) -> Option<&'a [reader::XmlEvent]> {
    let mut elm_i = events.len();
    let mut elm_end_i = elm_i;
    let mut elm_name = None;

    for (i, event) in events.iter().enumerate() {
        match event {
            reader::XmlEvent::StartElement {
                name, attributes, ..
            } => {
                let elm_id = attributes
                    .iter()
                    .filter_map(|a| {
                        if a.name.prefix.is_none()
                            && a.name.namespace.is_none()
                            && a.name.local_name.to_lowercase() == "id"
                        {
                            Some(&a.value)
                        } else {
                            None
                        }
                    })
                    .next();
                if let Some(elm_id) = elm_id {
                    if elm_name.is_none() && elm_id == id {
                        elm_i = i;
                        elm_name = Some(name.clone());
                    }
                }
            }
            reader::XmlEvent::EndElement { name, .. } => {
                if let Some(elm_name) = &elm_name {
                    if name == elm_name {
                        elm_end_i = i;
                        break;
                    }
                }
            }
            _ => {}
        }
    }

    if elm_i == events.len() {
        return None;
    }

    Some(&events[elm_i..elm_end_i + 1])
}

fn find_signed_info(events: &[reader::XmlEvent]) -> Option<&[reader::XmlEvent]> {
    let mut element_start = events.len();
    let mut element_end = element_start;
    let mut element_name = None;

    for (i, event) in events.iter().enumerate() {
        match event {
            reader::XmlEvent::StartElement { name, .. } => {
                if element_name.is_none()
                    && name.namespace.as_deref() == Some(XMLDSIG_NAMESPACE)
                    && &name.local_name == "SignedInfo"
                {
                    element_start = i;
                    element_name = Some(name.clone());
                }
            }
            reader::XmlEvent::EndElement { name, .. } => {
                if let Some(element_name) = &element_name {
                    if name == element_name {
                        element_end = i;
                        break;
                    }
                }
            }
            _ => {}
        }
    }

    if element_start == events.len() {
        return None;
    }

    Some(&events[element_start..element_end + 1])
}

#[derive(Debug)]
enum InnerAlgorithmData<'a> {
    NodeSet(&'a [reader::XmlEvent]),
    OctetStream(&'a str),
}

#[derive(Debug)]
enum AlgorithmData<'a> {
    NodeSet(&'a [reader::XmlEvent]),
    OctetStream(&'a str),
    OwnedNodeSet(Vec<reader::XmlEvent>),
    OwnedOctetStream(String),
}

impl<'a> AlgorithmData<'a> {
    fn into_inner_data(&'a self) -> InnerAlgorithmData<'a> {
        match self {
            AlgorithmData::NodeSet(n) => InnerAlgorithmData::NodeSet(n),
            AlgorithmData::OwnedNodeSet(n) => InnerAlgorithmData::NodeSet(n),
            AlgorithmData::OctetStream(o) => InnerAlgorithmData::OctetStream(o),
            AlgorithmData::OwnedOctetStream(o) => InnerAlgorithmData::OctetStream(o),
        }
    }
}

fn transform_canonical_xml_1_0(events: AlgorithmData) -> Result<AlgorithmData, String> {
    let events = match events.into_inner_data() {
        InnerAlgorithmData::NodeSet(e) => e,
        _ => return Err("unsupported input format for canonical XML 1.0".to_string()),
    };

    let canon_output = c14n::canonical_rfc3076(events, false, 0, false)?;

    Ok(AlgorithmData::OwnedOctetStream(canon_output))
}

fn transform_canonical_xml_1_0_with_comments(
    events: AlgorithmData,
) -> Result<AlgorithmData, String> {
    let events = match events.into_inner_data() {
        InnerAlgorithmData::NodeSet(e) => e,
        _ => {
            return Err(
                "unsupported input format for canonical XML 1.0 (with comments)".to_string(),
            )
        }
    };

    let canon_output = c14n::canonical_rfc3076(events, true, 0, false)?;

    Ok(AlgorithmData::OwnedOctetStream(canon_output))
}

fn transform_canonical_xml_1_1(events: AlgorithmData) -> Result<AlgorithmData, String> {
    let events = match events.into_inner_data() {
        InnerAlgorithmData::NodeSet(e) => e,
        _ => return Err("unsupported input format for canonical XML 1.1".to_string()),
    };

    let canon_output = c14n::canonical_rfc3076(events, false, 0, false)?;

    Ok(AlgorithmData::OwnedOctetStream(canon_output))
}

fn transform_canonical_xml_1_1_with_comments(
    events: AlgorithmData,
) -> Result<AlgorithmData, String> {
    let events = match events.into_inner_data() {
        InnerAlgorithmData::NodeSet(e) => e,
        _ => {
            return Err(
                "unsupported input format for canonical XML 1.1 (with comments)".to_string(),
            )
        }
    };

    let canon_output = c14n::canonical_rfc3076(events, true, 0, false)?;

    Ok(AlgorithmData::OwnedOctetStream(canon_output))
}

fn transform_exclusive_canonical_xml_1_0(events: AlgorithmData) -> Result<AlgorithmData, String> {
    let events = match events.into_inner_data() {
        InnerAlgorithmData::NodeSet(e) => e,
        _ => return Err("unsupported input format for exclusive canonical XML 1.0".to_string()),
    };

    let canon_output = c14n::canonical_rfc3076(events, false, 0, true)?;

    Ok(AlgorithmData::OwnedOctetStream(canon_output))
}

fn transform_exclusive_canonical_xml_1_0_with_comments(
    events: AlgorithmData,
) -> Result<AlgorithmData, String> {
    let events = match events.into_inner_data() {
        InnerAlgorithmData::NodeSet(e) => e,
        _ => {
            return Err(
                "unsupported input format for exclusive canonical XML 1.0 (with comments)"
                    .to_string(),
            )
        }
    };

    let canon_output = c14n::canonical_rfc3076(events, true, 0, true)?;

    Ok(AlgorithmData::OwnedOctetStream(canon_output))
}

fn transform_enveloped_signature(events: AlgorithmData) -> Result<AlgorithmData, String> {
    let events = match events.into_inner_data() {
        InnerAlgorithmData::NodeSet(e) => e,
        _ => return Err("unsupported input format for envelopd signature transform".to_string()),
    };

    let mut level = 0;
    let mut output = vec![];
    let mut should_output = true;

    for event in events {
        match event {
            reader::XmlEvent::StartElement {
                name,
                attributes,
                namespace,
            } => {
                level += 1;
                if level == 2
                    && name.namespace.as_deref() == Some(XMLDSIG_NAMESPACE)
                    && name.local_name == SIGNATURE_ELEMENT_NAME
                {
                    should_output = false
                }
                if should_output {
                    output.push(reader::XmlEvent::StartElement {
                        name: name.to_owned(),
                        attributes: attributes.to_vec(),
                        namespace: namespace.to_owned(),
                    });
                }
            }
            reader::XmlEvent::EndElement { name } => {
                if should_output {
                    output.push(reader::XmlEvent::EndElement {
                        name: name.to_owned(),
                    });
                }
                if level == 2
                    && name.namespace.as_deref() == Some(XMLDSIG_NAMESPACE)
                    && name.local_name == SIGNATURE_ELEMENT_NAME
                {
                    should_output = true;
                }
                level -= 1;
            }
            other => {
                if should_output {
                    output.push(other.to_owned());
                }
            }
        }
    }

    Ok(AlgorithmData::OwnedNodeSet(output))
}

fn apply_transforms(
    reference: &proto::ds::Reference,
    mut signed_data: AlgorithmData,
) -> Result<String, String> {
    if let Some(transforms) = &reference.transforms {
        for transform in &transforms.transforms {
            match transform.algorithm.as_str() {
                TRANSFORM_ENVELOPED_SIGNATURE => {
                    signed_data = transform_enveloped_signature(signed_data)?;
                }
                CANONICAL_1_0 => {
                    signed_data = transform_canonical_xml_1_0(signed_data)?;
                }
                CANONICAL_1_0_COMMENTS => {
                    signed_data = transform_canonical_xml_1_0_with_comments(signed_data)?;
                }
                CANONICAL_1_1 => {
                    signed_data = transform_canonical_xml_1_1(signed_data)?;
                }
                CANONICAL_1_1_COMMENTS => {
                    signed_data = transform_canonical_xml_1_1_with_comments(signed_data)?;
                }
                CANONICAL_EXCLUSIVE_1_0 => {
                    signed_data = transform_exclusive_canonical_xml_1_0(signed_data)?;
                }
                CANONICAL_EXCLUSIVE_1_0_COMMENTS => {
                    signed_data = transform_exclusive_canonical_xml_1_0_with_comments(signed_data)?;
                }
                unsupported => {
                    return Err(format!("unsupported transformation: {}", unsupported));
                }
            }
        }
    }

    match signed_data.into_inner_data() {
        InnerAlgorithmData::OctetStream(o) => Ok(o.to_string()),
        _ => Err("transforms did not output octet stream".to_string()),
    }
}

fn map_digest(method: &proto::ds::DigestMethod) -> Result<openssl::hash::MessageDigest, String> {
    match method.algorithm.as_str() {
        DIGEST_SHA1 => Ok(openssl::hash::MessageDigest::sha1()),
        DIGEST_SHA256 => Ok(openssl::hash::MessageDigest::sha256()),
        DIGEST_SH224 => Ok(openssl::hash::MessageDigest::sha224()),
        DIGEST_SHA384 => Ok(openssl::hash::MessageDigest::sha384()),
        DIGEST_SHA512 => Ok(openssl::hash::MessageDigest::sha512()),
        DIGEST_GOST256 => Ok(openssl::hash::MessageDigest::from_nid(
            openssl::nid::Nid::ID_GOSTR3411_2012_256,
        )
        .unwrap()),
        DIGEST_GOST512 => Ok(openssl::hash::MessageDigest::from_nid(
            openssl::nid::Nid::ID_GOSTR3411_2012_512,
        )
        .unwrap()),
        unsupported => {
            return Err(format!("unsupported digest: {}", unsupported));
        }
    }
}

fn verify_signature(
    sm: &proto::ds::SignatureMethod,
    pkey: &pkey::PKeyRef<pkey::Public>,
    signature: &[u8],
    data: &[u8],
) -> Result<bool, openssl::error::ErrorStack> {
    let md = match sm.algorithm.as_str() {
        SIGNATURE_RSA_MD5 => {
            pkey.rsa()?;
            openssl::hash::MessageDigest::md5()
        }
        SIGNATURE_RSA_SHA1 => {
            pkey.rsa()?;
            openssl::hash::MessageDigest::sha1()
        }
        SIGNATURE_RSA_SHA224 => {
            pkey.rsa()?;
            openssl::hash::MessageDigest::sha224()
        }
        SIGNATURE_RSA_SHA256 => {
            pkey.rsa()?;
            openssl::hash::MessageDigest::sha256()
        }
        SIGNATURE_RSA_SHA384 => {
            pkey.rsa()?;
            openssl::hash::MessageDigest::sha384()
        }
        SIGNATURE_RSA_SHA512 => {
            pkey.rsa()?;
            openssl::hash::MessageDigest::sha512()
        }
        SIGNATURE_RSA_RIPEMD160 => {
            pkey.rsa()?;
            openssl::hash::MessageDigest::ripemd160()
        }
        SIGNATURE_ECDSA_SHA1 => {
            pkey.ec_key()?;
            openssl::hash::MessageDigest::sha1()
        }
        SIGNATURE_ECDSA_SHA224 => {
            pkey.ec_key()?;
            openssl::hash::MessageDigest::sha224()
        }
        SIGNATURE_ECDSA_SHA256 => {
            pkey.ec_key()?;
            openssl::hash::MessageDigest::sha256()
        }
        SIGNATURE_ECDSA_SHA384 => {
            pkey.ec_key()?;
            openssl::hash::MessageDigest::sha384()
        }
        SIGNATURE_ECDSA_SHA512 => {
            pkey.ec_key()?;
            openssl::hash::MessageDigest::sha512()
        }
        SIGNATURE_ECDSA_RIPEMD160 => {
            pkey.ec_key()?;
            openssl::hash::MessageDigest::ripemd160()
        }
        SIGNATURE_DSA_SHA1 => {
            pkey.dsa()?;
            openssl::hash::MessageDigest::sha1()
        }
        SIGNATURE_DSA_SHA256 => {
            pkey.dsa()?;
            openssl::hash::MessageDigest::sha256()
        }
        SIGNATURE_GOST_256 => {
            if pkey.id() != pkey::Id::GOST3410_2012_256 {
                panic!(
                    "Unsupported key type {:?} for signature algorithm {}",
                    pkey.id(),
                    SIGNATURE_GOST_256
                );
            }
            openssl::hash::MessageDigest::from_nid(openssl::nid::Nid::ID_GOSTR3411_2012_256)
                .expect("Get GOSTR3411_2012_256 MessageDigest")
        }
        SIGNATURE_GOST_512 => {
            if pkey.id() != pkey::Id::GOST3410_2012_512 {
                panic!(
                    "Unsupported key type {:?} for signature algorithm {}",
                    pkey.id(),
                    SIGNATURE_GOST_512
                );
            }
            openssl::hash::MessageDigest::from_nid(openssl::nid::Nid::ID_GOSTR3411_2012_512)
                .expect("Get GOSTR3411_2012_512 MessageDigest")
        }
        unsupported => panic!("Unsupported signature algorithm: {}", unsupported),
    };

    let mut verifier = openssl::sign::Verifier::new(md, pkey)?;
    verifier.verify_oneshot(signature, data)
}

#[derive(Debug)]
pub enum Output {
    Verified {
        references: Vec<String>,
        // pkey: pkey::PKey<pkey::Public>,
    },
    Unsigned(String),
}

pub fn decode_and_verify_signed_document(source_xml: &str) -> Result<Output, String> {
    let parser_config = xml::ParserConfig::new()
        .ignore_comments(false)
        .trim_whitespace(false)
        .coalesce_characters(false)
        .ignore_root_level_whitespace(true);

    let reader = reader::EventReader::new_with_config(source_xml.as_bytes(), parser_config)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("unable to decode XML: {}", error))?;

    let mut level = 0;
    let mut seen_level = reader.len();
    let mut signature_start = reader.len();
    let mut signature_slices = Vec::new();

    for (i, event) in reader.iter().enumerate() {
        match event {
            reader::XmlEvent::StartElement { name, .. } => {
                level += 1;

                if level <= seen_level
                    && name.namespace.as_deref() == Some(XMLDSIG_NAMESPACE)
                    && &name.local_name == SIGNATURE_ELEMENT_NAME
                {
                    seen_level = level;
                    signature_start = i;
                }
            }
            reader::XmlEvent::EndElement { name, .. } => {
                if level == seen_level
                    && name.namespace.as_deref() == Some(XMLDSIG_NAMESPACE)
                    && &name.local_name == SIGNATURE_ELEMENT_NAME
                {
                    seen_level = level;
                    signature_slices.push(&reader[signature_start..i + 1]);
                }

                level -= 1;
            }
            _ => {}
        }
    }

    if signature_start == reader.len() {
        return Ok(Output::Unsigned(source_xml.to_string()));
    }

    let mut verified_outputs = vec![];

    println!(">> Signature count: {}", signature_slices.len());

    for (i, signature_slice) in signature_slices.iter().enumerate() {
        println!(">> Verifying Signature {}", i);

        let signature_elements = signature_slice
            .iter()
            .map(|event| reader::Result::Ok(event.to_owned()))
            .collect::<Vec<_>>();

        let outer_signature: proto::ds::OuterSignature =
            match xml_serde::from_events(signature_elements.as_slice()) {
                Ok(s) => s,
                Err(error) => return Err(format!("unable to decode XML signature: {}", error)),
            };

        let signature = &outer_signature.signature;

        // println!(">> {:?}", signature);

        // Verify references
        for reference in &signature.signed_info.reference {
            let uri = reference.uri.as_deref().unwrap_or_default();

            let data = if uri.is_empty() {
                reader.as_slice()
            } else if let Some(id) = uri.strip_prefix('#') {
                match find_events_slice_by_id(&reader, id) {
                    Some(events) => events,
                    None => return Err(format!("unable to find signed element: {}", uri)),
                }
            } else {
                return Err(format!("unsupported reference URI: {}", uri));
            };

            let signed_data = apply_transforms(reference, AlgorithmData::NodeSet(data))?;

            let provided_digest = match base64::decode(&reference.digest_value) {
                Ok(value) => value,
                Err(error) => return Err(format!("invalid disest base64: {}", error)),
            };

            let md = map_digest(&reference.digest_method)?;

            let digest = match openssl::hash::hash(md, signed_data.as_bytes()) {
                Ok(value) => value,
                Err(error) => return Err(format!("openssl error: {}", error)),
            };

            if digest.as_ref() != provided_digest {
                return Err("digest does not match".to_string());
            }

            verified_outputs.push(signed_data);
        }

        // Verify signature
        let signed_info_events = AlgorithmData::NodeSet(
            find_signed_info(signature_slice).expect("Find signed info elements"),
        );

        let canon_signed_info = match signature
            .signed_info
            .canonicalization_method
            .algorithm
            .as_str()
        {
            CANONICAL_1_0 => transform_canonical_xml_1_0(signed_info_events)?,
            CANONICAL_1_0_COMMENTS => {
                transform_canonical_xml_1_0_with_comments(signed_info_events)?
            }
            CANONICAL_1_1 => transform_canonical_xml_1_1(signed_info_events)?,
            CANONICAL_1_1_COMMENTS => {
                transform_canonical_xml_1_1_with_comments(signed_info_events)?
            }
            CANONICAL_EXCLUSIVE_1_0 => transform_exclusive_canonical_xml_1_0(signed_info_events)?,
            CANONICAL_EXCLUSIVE_1_0_COMMENTS => {
                transform_exclusive_canonical_xml_1_0_with_comments(signed_info_events)?
            }
            unsupported => {
                return Err(format!(
                    "unsupported canonicalization method: {}",
                    unsupported
                ))
            }
        };

        let signed_info_data = match canon_signed_info.into_inner_data() {
            InnerAlgorithmData::OctetStream(o) => o.to_string(),
            _ => unreachable!(),
        };

        let public_key = if let Some(key_info) = &signature.key_info {
            decode_key(key_info)?
        } else {
            return Err("key info not specified".to_string());
        };

        let signature_text = &signature
            .signature_value
            .value
            .replace("\r", "")
            .replace("\n", "");

        let signature_data = base64::decode(signature_text)
            .map_err(|error| format!("error decoding signature: {}", error))?;

        let valid = verify_signature(
            &signature.signed_info.signature_method,
            &public_key,
            &signature_data,
            signed_info_data.as_bytes(),
        )
        .map_err(|error| format!("error verifying signature: {}", error))?;

        if !valid {
            return Err(format!("Signature {} is invalid", i));
        }
    }

    Ok(Output::Verified {
        references: verified_outputs,
        // pkey,
    })
}

pub fn sign_document(
    events: &[reader::XmlEvent],
    certificate: &openssl::x509::X509Ref,
    private_key: &pkey::PKeyRef<pkey::Private>,
) -> Result<String, String> {
    let public_key = match certificate.public_key() {
        Ok(d) => d,
        Err(e) => {
            return Err(format!("openssl error: {}", e));
        }
    };

    if !private_key.public_eq(&public_key) {
        return Err("public and private key don't match".to_string());
    }

    let canonicalizied_events =
        match transform_exclusive_canonical_xml_1_0(AlgorithmData::NodeSet(events))?
            .into_inner_data()
        {
            InnerAlgorithmData::OctetStream(s) => s.to_string(),
            _ => unreachable!(),
        };

    let digest = match openssl::hash::hash(
        openssl::hash::MessageDigest::sha256(),
        canonicalizied_events.as_bytes(),
    ) {
        Ok(d) => d,
        Err(e) => {
            return Err(format!("openssl error: {}", e));
        }
    };

    let digest_method = proto::ds::DigestMethod {
        algorithm: DIGEST_SHA256.to_string(),
    };

    let reference = proto::ds::Reference {
        transforms: Some(proto::ds::Transforms {
            transforms: vec![
                proto::ds::Transform {
                    algorithm: TRANSFORM_ENVELOPED_SIGNATURE.to_string(),
                },
                proto::ds::Transform {
                    algorithm: CANONICAL_EXCLUSIVE_1_0.to_string(),
                },
            ],
        }),
        digest_method,
        digest_value: base64::encode(digest),
        id: None,
        uri: Some("".to_string()),
        ref_type: None,
    };

    let (signature_method, digest_method) = match private_key.id() {
        pkey::Id::RSA => (SIGNATURE_RSA_SHA256, openssl::hash::MessageDigest::sha256()),
        pkey::Id::DSA => (SIGNATURE_DSA_SHA256, openssl::hash::MessageDigest::sha256()),
        pkey::Id::EC => (
            SIGNATURE_ECDSA_SHA512,
            openssl::hash::MessageDigest::sha512(),
        ),
        unsupported => return Err(format!("unsupported key format {:?}", unsupported)),
    };

    let signed_info = proto::ds::SignedInfo {
        id: None,
        canonicalization_method: proto::ds::CanonicalizationMethod {
            algorithm: CANONICAL_EXCLUSIVE_1_0.to_string(),
        },
        signature_method: proto::ds::SignatureMethod {
            algorithm: signature_method.to_string(),
        },
        reference: vec![reference],
    };

    let signed_info_events = xml_serde::to_events(&signed_info).unwrap();
    let canonicalizied_signed_info_events =
        match transform_exclusive_canonical_xml_1_0(AlgorithmData::NodeSet(&signed_info_events))?
            .into_inner_data()
        {
            InnerAlgorithmData::OctetStream(s) => s.to_string(),
            _ => unreachable!(),
        };

    let mut signer = match openssl::sign::Signer::new(digest_method, private_key) {
        Ok(d) => d,
        Err(e) => {
            return Err(format!("openssl error: {}", e));
        }
    };

    if let Err(e) = signer.update(canonicalizied_signed_info_events.as_bytes()) {
        return Err(format!("openssl error: {}", e));
    }

    let signature = match signer.sign_to_vec() {
        Ok(d) => d,
        Err(e) => {
            return Err(format!("openssl error: {}", e));
        }
    };

    let x509_data = proto::ds::X509Data {
        x509_data: vec![
            proto::ds::X509Datum::SubjectName(x509_name_to_string(certificate.subject_name())),
            proto::ds::X509Datum::Certificate(base64::encode(certificate.to_der().unwrap())),
        ],
    };

    let key_info = proto::ds::KeyInfo {
        keys_info: vec![proto::ds::KeyInfoType::X509Data(x509_data)],
    };

    let signature_value = proto::ds::SignatureValue {
        value: base64::encode(&signature),
        id: None,
    };

    let signature = proto::ds::Signature {
        id: None,
        signed_info,
        signature_value,
        key_info: Some(key_info),
    };

    let outer_signature = proto::ds::OuterSignature { signature };

    let signature_events = xml_serde::to_events(&outer_signature).unwrap();

    let start_i = match events.iter().enumerate().find_map(|(i, e)| {
        if matches!(e, reader::XmlEvent::StartElement { .. }) {
            Some(i)
        } else {
            None
        }
    }) {
        Some(i) => i + 1,
        None => return Ok("".to_string()),
    };

    let mut final_events = vec![];
    final_events.extend_from_slice(&events[..start_i]);
    final_events.extend(signature_events.into_iter());
    final_events.extend_from_slice(&events[start_i..]);

    Ok(events_to_string(&final_events))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_verify_files() {
        let _engine = openssl_gost_engine::Engine::new().expect("Init GOST Engine");

        let test_data = [
            ("testdata/base_signed.xml", 1, true),
            ("testdata/signed.xml", 1, true),
            ("testdata/signed_xades.xml", 2, true),
            ("testdata/signed2.xml", 4, true),
        ];

        for (file, expected_references, _valid) in test_data {
            let source_xml = fs::read_to_string(file).expect("Read signed XML file");

            let output =
                decode_and_verify_signed_document(&source_xml).expect("Verify signed XML file");
            println!("{:#?}", output);

            if let Output::Verified {
                references,
                // pkey: _,
            } = output
            {
                assert_eq!(references.len(), expected_references);
            }
        }
    }
}

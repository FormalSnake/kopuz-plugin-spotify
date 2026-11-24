//! The access point: Spotify's own protocol over TCP. A Diffie-Hellman
//! handshake keys a Shannon cipher in each direction, a login follows, and
//! the session then hands out the key each audio file is encrypted with.

use std::io::{self, Read, Write};

use hmac::{Hmac, Mac as _};
use librespot_protocol::authentication::{
    APWelcome, AuthenticationType, ClientResponseEncrypted, CpuFamily, Os,
};
use librespot_protocol::keyexchange::{
    APLoginFailed, APResponseMessage, ClientHello, ClientResponsePlaintext, Cryptosuite, ErrorCode,
    Platform, Product, ProductFlags,
};
use num_bigint::BigUint;
use protobuf::Message as _;
use sha1::{Digest as _, Sha1};
use shannon::Shannon;

use crate::api::{CLIENT_VERSION_NUMBER, Credentials};

/// The RSA modulus the access point signs its key exchange with.
const SERVER_KEY: [u8; 256] = [
    0xac, 0xe0, 0x46, 0x0b, 0xff, 0xc2, 0x30, 0xaf, 0xf4, 0x6b, 0xfe, 0xc3, 0xbf, 0xbf, 0x86, 0x3d,
    0xa1, 0x91, 0xc6, 0xcc, 0x33, 0x6c, 0x93, 0xa1, 0x4f, 0xb3, 0xb0, 0x16, 0x12, 0xac, 0xac, 0x6a,
    0xf1, 0x80, 0xe7, 0xf6, 0x14, 0xd9, 0x42, 0x9d, 0xbe, 0x2e, 0x34, 0x66, 0x43, 0xe3, 0x62, 0xd2,
    0x32, 0x7a, 0x1a, 0x0d, 0x92, 0x3b, 0xae, 0xdd, 0x14, 0x02, 0xb1, 0x81, 0x55, 0x05, 0x61, 0x04,
    0xd5, 0x2c, 0x96, 0xa4, 0x4c, 0x1e, 0xcc, 0x02, 0x4a, 0xd4, 0xb2, 0x0c, 0x00, 0x1f, 0x17, 0xed,
    0xc2, 0x2f, 0xc4, 0x35, 0x21, 0xc8, 0xf0, 0xcb, 0xae, 0xd2, 0xad, 0xd7, 0x2b, 0x0f, 0x9d, 0xb3,
    0xc5, 0x32, 0x1a, 0x2a, 0xfe, 0x59, 0xf3, 0x5a, 0x0d, 0xac, 0x68, 0xf1, 0xfa, 0x62, 0x1e, 0xfb,
    0x2c, 0x8d, 0x0c, 0xb7, 0x39, 0x2d, 0x92, 0x47, 0xe3, 0xd7, 0x35, 0x1a, 0x6d, 0xbd, 0x24, 0xc2,
    0xae, 0x25, 0x5b, 0x88, 0xff, 0xab, 0x73, 0x29, 0x8a, 0x0b, 0xcc, 0xcd, 0x0c, 0x58, 0x67, 0x31,
    0x89, 0xe8, 0xbd, 0x34, 0x80, 0x78, 0x4a, 0x5f, 0xc9, 0x6b, 0x89, 0x9d, 0x95, 0x6b, 0xfc, 0x86,
    0xd7, 0x4f, 0x33, 0xa6, 0x78, 0x17, 0x96, 0xc9, 0xc3, 0x2d, 0x0d, 0x32, 0xa5, 0xab, 0xcd, 0x05,
    0x27, 0xe2, 0xf7, 0x10, 0xa3, 0x96, 0x13, 0xc4, 0x2f, 0x99, 0xc0, 0x27, 0xbf, 0xed, 0x04, 0x9c,
    0x3c, 0x27, 0x58, 0x04, 0xb6, 0xb2, 0x19, 0xf9, 0xc1, 0x2f, 0x02, 0xe9, 0x48, 0x63, 0xec, 0xa1,
    0xb6, 0x42, 0xa0, 0x9d, 0x48, 0x25, 0xf8, 0xb3, 0x9d, 0xd0, 0xe8, 0x6a, 0xf9, 0x48, 0x4d, 0xa1,
    0xc2, 0xba, 0x86, 0x30, 0x42, 0xea, 0x9d, 0xb3, 0x08, 0x6c, 0x19, 0x0e, 0x48, 0xb3, 0x9d, 0x66,
    0xeb, 0x00, 0x06, 0xa2, 0x5a, 0xee, 0xa1, 0x1b, 0x13, 0x87, 0x3c, 0xd7, 0x19, 0xe6, 0x55, 0xbd,
];

const DH_PRIME: [u8; 96] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9, 0x0f, 0xda, 0xa2, 0x21, 0x68, 0xc2, 0x34,
    0xc4, 0xc6, 0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1, 0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67, 0xcc, 0x74,
    0x02, 0x0b, 0xbe, 0xa6, 0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x08, 0x79, 0x8e, 0x34, 0x04, 0xdd,
    0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b, 0x30, 0x2b, 0x0a, 0x6d, 0xf2, 0x5f, 0x14, 0x37,
    0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51, 0xc2, 0x45, 0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6,
    0xf4, 0x4c, 0x42, 0xe9, 0xa6, 0x3a, 0x36, 0x20, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

const LOGIN: u8 = 0xab;
const AP_WELCOME: u8 = 0xac;
const AUTH_FAILURE: u8 = 0xad;
const PING: u8 = 0x04;
const PONG: u8 = 0x49;
const REQUEST_KEY: u8 = 0x0c;
const AES_KEY: u8 = 0x0d;
const AES_KEY_ERROR: u8 = 0x0e;
const COUNTRY_CODE: u8 = 0x1b;
const PRODUCT_INFO: u8 = 0x50;

const MAC_SIZE: usize = 4;

/// Packets read while waiting for one answer before giving up on it.
const MAX_UNRELATED: usize = 64;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

struct DhKeys {
    private: BigUint,
    public: BigUint,
}

impl DhKeys {
    fn random() -> Self {
        let mut bytes = [0u8; 95];
        rand::Rng::fill(&mut rand::rng(), &mut bytes[..]);
        Self::from_private(&bytes)
    }

    fn from_private(bytes: &[u8]) -> Self {
        let private = BigUint::from_bytes_le(bytes);
        let public = BigUint::from(2u8).modpow(&private, &BigUint::from_bytes_be(&DH_PRIME));
        Self { private, public }
    }

    fn shared_secret(&self, remote: &[u8]) -> Vec<u8> {
        BigUint::from_bytes_be(remote)
            .modpow(&self.private, &BigUint::from_bytes_be(&DH_PRIME))
            .to_bytes_be()
    }
}

/// Whether `signature` is the access point's RSA signature (PKCS#1 v1.5
/// over SHA-1) of its half of the key exchange. Without the check anyone on
/// the path could sit in the middle of the session.
fn signed_by_spotify(remote_key: &[u8], signature: &[u8]) -> bool {
    const SHA1_DIGEST_INFO: [u8; 15] = [
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
    ];
    if signature.len() != SERVER_KEY.len() {
        return false;
    }
    let opened = BigUint::from_bytes_be(signature)
        .modpow(
            &BigUint::from(65537u32),
            &BigUint::from_bytes_be(&SERVER_KEY),
        )
        .to_bytes_be();
    let digest = Sha1::digest(remote_key);
    let padding = SERVER_KEY.len() - 3 - SHA1_DIGEST_INFO.len() - digest.len();
    // The leading zero byte of the encoded message is lost in the integer.
    let mut expected = vec![0x01];
    expected.extend(std::iter::repeat_n(0xff, padding));
    expected.push(0x00);
    expected.extend_from_slice(&SHA1_DIGEST_INFO);
    expected.extend_from_slice(&digest);
    opened == expected
}

struct Keys {
    challenge: Vec<u8>,
    send: Vec<u8>,
    recv: Vec<u8>,
}

/// Both cipher keys and the proof sent back, all derived from the shared
/// secret and every byte the two sides exchanged in the clear.
fn compute_keys(shared_secret: &[u8], packets: &[u8]) -> io::Result<Keys> {
    type HmacSha1 = Hmac<Sha1>;
    let keyed =
        |key: &[u8]| HmacSha1::new_from_slice(key).map_err(|_| invalid("invalid key length"));
    let mut data = Vec::with_capacity(100);
    for round in 1..6u8 {
        let mut mac = keyed(shared_secret)?;
        mac.update(packets);
        mac.update(&[round]);
        data.extend_from_slice(&mac.finalize().into_bytes());
    }
    let mut mac = keyed(&data[..0x14])?;
    mac.update(packets);
    Ok(Keys {
        challenge: mac.finalize().into_bytes().to_vec(),
        send: data[0x14..0x34].to_vec(),
        recv: data[0x34..0x54].to_vec(),
    })
}

fn client_hello(public_key: Vec<u8>) -> io::Result<Vec<u8>> {
    let mut hello = ClientHello::new();
    let build = hello.build_info.mut_or_insert_default();
    build.set_product(Product::PRODUCT_CLIENT);
    build
        .product_flags
        .push(ProductFlags::PRODUCT_FLAG_NONE.into());
    build.set_platform(Platform::PLATFORM_LINUX_X86_64);
    build.set_version(CLIENT_VERSION_NUMBER);
    hello
        .cryptosuites_supported
        .push(Cryptosuite::CRYPTO_SUITE_SHANNON.into());
    let exchange = hello
        .login_crypto_hello
        .mut_or_insert_default()
        .diffie_hellman
        .mut_or_insert_default();
    exchange.set_gc(public_key);
    exchange.set_server_keys_known(1);
    hello.set_client_nonce(rand::random::<[u8; 16]>().to_vec());
    hello.set_padding(vec![0x1e]);

    // Only the first packet carries the two protocol bytes before its length.
    let mut packet = vec![0, 4];
    let size = 2 + 4 + hello.compute_size();
    packet.extend_from_slice(&(size as u32).to_be_bytes());
    hello.write_to_vec(&mut packet)?;
    Ok(packet)
}

fn client_response(challenge: Vec<u8>) -> io::Result<Vec<u8>> {
    let mut response = ClientResponsePlaintext::new();
    response
        .login_crypto_response
        .mut_or_insert_default()
        .diffie_hellman
        .mut_or_insert_default()
        .set_hmac(challenge);
    response.pow_response.mut_or_insert_default();
    response.crypto_response.mut_or_insert_default();
    let mut packet = Vec::new();
    let size = 4 + response.compute_size();
    packet.extend_from_slice(&(size as u32).to_be_bytes());
    response.write_to_vec(&mut packet)?;
    Ok(packet)
}

/// An encrypted connection to an access point, before or after its login.
pub struct Connection<S> {
    stream: S,
    send: Shannon,
    send_nonce: u32,
    recv: Shannon,
    recv_nonce: u32,
}

impl<S: Read + Write> Connection<S> {
    pub fn handshake(stream: S) -> io::Result<Self> {
        Self::handshake_with(stream, DhKeys::random(), signed_by_spotify)
    }

    fn handshake_with(
        mut stream: S,
        keys: DhKeys,
        signed: fn(&[u8], &[u8]) -> bool,
    ) -> io::Result<Self> {
        let mut exchanged = client_hello(keys.public.to_bytes_be())?;
        stream.write_all(&exchanged)?;

        let mut header = [0; 4];
        stream.read_exact(&mut header)?;
        let size = (u32::from_be_bytes(header) as usize)
            .checked_sub(4)
            .filter(|size| *size <= 16 * 1024)
            .ok_or_else(|| invalid("the access point's answer has no valid length"))?;
        let mut body = vec![0; size];
        stream.read_exact(&mut body)?;
        exchanged.extend_from_slice(&header);
        exchanged.extend_from_slice(&body);

        let answer = APResponseMessage::parse_from_bytes(&body)?;
        let exchange = answer
            .challenge
            .get_or_default()
            .login_crypto_challenge
            .get_or_default()
            .diffie_hellman
            .get_or_default();
        if !signed(exchange.gs(), exchange.gs_signature()) {
            return Err(invalid("the access point's key is not signed by Spotify"));
        }
        let derived = compute_keys(&keys.shared_secret(exchange.gs()), &exchanged)?;
        stream.write_all(&client_response(derived.challenge)?)?;
        Ok(Self::with_keys(stream, &derived.send, &derived.recv))
    }

    fn with_keys(stream: S, send: &[u8], recv: &[u8]) -> Self {
        Self {
            stream,
            send: Shannon::new(send),
            send_nonce: 0,
            recv: Shannon::new(recv),
            recv_nonce: 0,
        }
    }

    pub fn send(&mut self, command: u8, payload: &[u8]) -> io::Result<()> {
        let length =
            u16::try_from(payload.len()).map_err(|_| invalid("the packet is too large"))?;
        let mut packet = Vec::with_capacity(3 + payload.len() + MAC_SIZE);
        packet.push(command);
        packet.extend_from_slice(&length.to_be_bytes());
        packet.extend_from_slice(payload);
        self.send.nonce_u32(self.send_nonce);
        self.send_nonce = self.send_nonce.wrapping_add(1);
        self.send.encrypt(&mut packet);
        let mut mac = [0; MAC_SIZE];
        self.send.finish(&mut mac);
        packet.extend_from_slice(&mac);
        self.stream.write_all(&packet)
    }

    pub fn recv(&mut self) -> io::Result<(u8, Vec<u8>)> {
        let mut header = [0; 3];
        self.stream.read_exact(&mut header)?;
        self.recv.nonce_u32(self.recv_nonce);
        self.recv_nonce = self.recv_nonce.wrapping_add(1);
        self.recv.decrypt(&mut header);
        let size = u16::from_be_bytes([header[1], header[2]]) as usize;
        let mut payload = vec![0; size + MAC_SIZE];
        self.stream.read_exact(&mut payload)?;
        let mac = payload.split_off(size);
        self.recv.decrypt(&mut payload);
        self.recv.check_mac(&mac)?;
        Ok((header[0], payload))
    }

    /// Log in, with the token a browser sign-in ended in or with the login a
    /// previous one stored. Either way the answer is a login to store.
    pub fn login(mut self, login: Login<'_>, device_id: &str) -> Result<Session<S>, LoginError> {
        let mut packet = ClientResponseEncrypted::new();
        let credentials = packet.login_credentials.mut_or_insert_default();
        match login {
            Login::Token(token) => {
                credentials.set_typ(AuthenticationType::AUTHENTICATION_SPOTIFY_TOKEN);
                credentials.set_auth_data(token.as_bytes().to_vec());
            }
            Login::Stored(stored) => {
                credentials.set_username(stored.username.clone());
                credentials.set_typ(AuthenticationType::AUTHENTICATION_STORED_SPOTIFY_CREDENTIALS);
                credentials.set_auth_data(stored.auth_data.clone());
            }
        }
        let system = packet.system_info.mut_or_insert_default();
        system.set_cpu_family(CpuFamily::CPU_UNKNOWN);
        system.set_os(Os::OS_LINUX);
        system.set_system_information_string(concat!("kopuz-", env!("CARGO_PKG_VERSION")).into());
        system.set_device_id(device_id.to_string());
        packet.set_version_string(concat!("kopuz ", env!("CARGO_PKG_VERSION")).into());
        self.send(LOGIN, &packet.write_to_bytes().map_err(io::Error::from)?)?;

        let (command, payload) = self.recv()?;
        match command {
            AP_WELCOME => {
                let welcome = APWelcome::parse_from_bytes(&payload).map_err(io::Error::from)?;
                Ok(Session {
                    credentials: Credentials {
                        username: welcome.canonical_username().to_string(),
                        auth_data: welcome.reusable_auth_credentials().to_vec(),
                    },
                    connection: self,
                    sequence: 0,
                    product: None,
                    country: None,
                })
            }
            AUTH_FAILURE => {
                let failed = APLoginFailed::parse_from_bytes(&payload).map_err(io::Error::from)?;
                Err(LoginError::Refused(failed.error_code()))
            }
            _ => Err(LoginError::Io(invalid(
                "the access point did not answer the login",
            ))),
        }
    }
}

pub enum Login<'a> {
    Token(&'a str),
    Stored(&'a Credentials),
}

#[derive(Debug)]
pub enum LoginError {
    Io(io::Error),
    Refused(ErrorCode),
}

impl From<io::Error> for LoginError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl LoginError {
    /// Whether the stored login is no good, as opposed to this attempt.
    pub fn expires_credentials(&self) -> bool {
        matches!(
            self,
            Self::Refused(ErrorCode::BadCredentials | ErrorCode::CouldNotValidateCredentials)
        )
    }

    pub fn message(&self) -> String {
        match self {
            Self::Io(error) => format!("Spotify's access point did not answer: {error}"),
            Self::Refused(ErrorCode::TravelRestriction) => {
                "Spotify blocked sign-in because of an account country or travel restriction. \
                 Check your country or region at https://www.spotify.com/account/profile/ \
                 and any VPN or proxy, then sign in again."
                    .to_string()
            }
            Self::Refused(ErrorCode::PremiumAccountRequired) => {
                "Spotify needs a Premium account for this.".to_string()
            }
            Self::Refused(code) => format!("Spotify refused the login: {code:?}"),
        }
    }
}

#[derive(Debug)]
pub enum KeyError {
    /// The connection is gone; a new one may do better.
    Io(io::Error),
    /// The access point answered, and will not hand the key out.
    Refused,
}

/// A logged-in connection.
pub struct Session<S> {
    connection: Connection<S>,
    credentials: Credentials,
    sequence: u32,
    product: Option<String>,
    country: Option<String>,
}

impl<S: Read + Write> Session<S> {
    /// The login to store, which does not expire on its own.
    pub fn credentials(&self) -> &Credentials {
        &self.credentials
    }

    /// `premium`, `free` and the like, once the access point has said.
    pub fn product(&self) -> Option<&str> {
        self.product.as_deref()
    }

    pub fn country(&self) -> Option<&str> {
        self.country.as_deref()
    }

    /// The AES key of `file_id`, an audio file of the track `track_gid`.
    pub fn audio_key(
        &mut self,
        track_gid: &[u8; 16],
        file_id: &[u8; 20],
    ) -> Result<[u8; 16], KeyError> {
        let sequence = self.sequence;
        self.sequence = self.sequence.wrapping_add(1);
        let mut request = Vec::with_capacity(42);
        request.extend_from_slice(file_id);
        request.extend_from_slice(track_gid);
        request.extend_from_slice(&sequence.to_be_bytes());
        request.extend_from_slice(&[0, 0]);
        self.connection
            .send(REQUEST_KEY, &request)
            .map_err(KeyError::Io)?;

        // The access point talks about other things in between: what the
        // account is, where it is, and pings that want an answer.
        for _ in 0..MAX_UNRELATED {
            let (command, payload) = self.connection.recv().map_err(KeyError::Io)?;
            let answers = payload.get(..4) == Some(&sequence.to_be_bytes()[..]);
            match command {
                AES_KEY if answers => {
                    return payload
                        .get(4..20)
                        .and_then(|key| key.try_into().ok())
                        .ok_or_else(|| KeyError::Io(invalid("the audio key is not 16 bytes")));
                }
                AES_KEY_ERROR if answers => return Err(KeyError::Refused),
                _ => self.other(command, &payload).map_err(KeyError::Io)?,
            }
        }
        Err(KeyError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            "the access point did not answer the key request",
        )))
    }

    fn other(&mut self, command: u8, payload: &[u8]) -> io::Result<()> {
        match command {
            PING => self.connection.send(PONG, &[0xde, 0xad, 0xbe, 0xef])?,
            COUNTRY_CODE => self.country = Some(String::from_utf8_lossy(payload).into_owned()),
            PRODUCT_INFO => {
                if let Some(product) = product_type(&String::from_utf8_lossy(payload)) {
                    self.product = Some(product);
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// The `<type>` of the account's product in the XML the access point sends.
fn product_type(xml: &str) -> Option<String> {
    let (_, rest) = xml.split_once("<type>")?;
    let (product, _) = rest.split_once("</type>")?;
    Some(product.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stream whose other side already said everything it will say.
    struct Script {
        incoming: io::Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl Script {
        fn saying(incoming: Vec<u8>) -> Self {
            Self {
                incoming: io::Cursor::new(incoming),
                written: Vec::new(),
            }
        }
    }

    impl Read for Script {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.incoming.read(buf)
        }
    }

    impl Write for Script {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    const SEND: [u8; 32] = [3; 32];
    const RECV: [u8; 32] = [9; 32];

    /// What the access point would put on the wire for `packets`.
    fn from_server(packets: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut server = Connection::with_keys(Script::saying(Vec::new()), &RECV, &SEND);
        for (command, payload) in packets {
            server.send(*command, payload).expect("send");
        }
        server.stream.written
    }

    /// The packets the client put on the wire, as the access point reads them.
    fn to_server(written: Vec<u8>) -> Vec<(u8, Vec<u8>)> {
        let mut server = Connection::with_keys(Script::saying(written), &RECV, &SEND);
        std::iter::from_fn(|| server.recv().ok()).collect()
    }

    fn client(packets: &[(u8, Vec<u8>)]) -> Connection<Script> {
        Connection::with_keys(Script::saying(from_server(packets)), &SEND, &RECV)
    }

    fn welcome() -> (u8, Vec<u8>) {
        let mut welcome = APWelcome::new();
        welcome.set_canonical_username("someone".into());
        welcome.set_account_type_logged_in(Default::default());
        welcome.set_credentials_type_logged_in(Default::default());
        welcome.set_reusable_auth_credentials_type(
            AuthenticationType::AUTHENTICATION_STORED_SPOTIFY_CREDENTIALS,
        );
        welcome.set_reusable_auth_credentials(vec![1, 2, 3]);
        (AP_WELCOME, welcome.write_to_bytes().expect("welcome"))
    }

    #[test]
    fn a_packet_survives_the_cipher_and_a_tampered_one_does_not() {
        let mut wire = from_server(&[(0x50, b"hello".to_vec()), (0x04, Vec::new())]);
        let mut reader = Connection::with_keys(Script::saying(wire.clone()), &SEND, &RECV);
        assert_eq!(reader.recv().expect("first"), (0x50, b"hello".to_vec()));
        assert_eq!(reader.recv().expect("second"), (0x04, Vec::new()));

        wire[4] ^= 1;
        let mut reader = Connection::with_keys(Script::saying(wire), &SEND, &RECV);
        assert!(reader.recv().is_err());
    }

    #[test]
    fn the_handshake_proves_the_shared_secret_and_keys_both_directions() {
        let server = DhKeys::from_private(&[7; 95]);
        let mut answer = APResponseMessage::new();
        let exchange = answer
            .challenge
            .mut_or_insert_default()
            .login_crypto_challenge
            .mut_or_insert_default()
            .diffie_hellman
            .mut_or_insert_default();
        exchange.set_gs(server.public.to_bytes_be());
        exchange.set_server_signature_key(0);
        exchange.set_gs_signature(vec![0; 256]);
        let challenge = answer.challenge.mut_or_insert_default();
        challenge.fingerprint_challenge.mut_or_insert_default();
        challenge.pow_challenge.mut_or_insert_default();
        challenge.crypto_challenge.mut_or_insert_default();
        challenge.set_server_nonce(vec![0; 16]);
        let body = answer.write_to_bytes().expect("answer");
        let mut incoming = ((body.len() + 4) as u32).to_be_bytes().to_vec();
        incoming.extend_from_slice(&body);
        // Followed by a first encrypted packet, which only the right keys read.
        let after_handshake = incoming.len();

        let unsigned = Connection::handshake_with(
            Script::saying(incoming.clone()),
            DhKeys::from_private(&[5; 95]),
            signed_by_spotify,
        );
        assert!(unsigned.is_err(), "a key Spotify did not sign is refused");

        let client_keys = DhKeys::from_private(&[5; 95]);
        let hello = client_hello(client_keys.public.to_bytes_be()).expect("hello");
        assert_eq!(&hello[..2], &[0, 4]);
        assert_eq!(
            u32::from_be_bytes(hello[2..6].try_into().expect("length")) as usize,
            hello.len()
        );

        let connection = Connection::handshake_with(
            Script::saying(incoming.clone()),
            DhKeys::from_private(&[5; 95]),
            |_, _| true,
        )
        .expect("handshake");
        let written = &connection.stream.written;
        let hello_size = u32::from_be_bytes(written[2..6].try_into().expect("length")) as usize;
        let sent_hello = ClientHello::parse_from_bytes(&written[6..hello_size]).expect("hello");
        let gc = sent_hello.login_crypto_hello.diffie_hellman.gc().to_vec();
        assert_eq!(gc, client_keys.public.to_bytes_be());

        // The server derives the same keys from its side of the exchange.
        let mut exchanged = written[..hello_size].to_vec();
        exchanged.extend_from_slice(&incoming[..after_handshake]);
        let derived = compute_keys(&server.shared_secret(&gc), &exchanged).expect("keys");
        let response = ClientResponsePlaintext::parse_from_bytes(&written[hello_size + 4..])
            .expect("response");
        assert_eq!(
            response.login_crypto_response.diffie_hellman.hmac(),
            derived.challenge
        );

        let mut server_side =
            Connection::with_keys(Script::saying(Vec::new()), &derived.recv, &derived.send);
        server_side.send(PING, b"hi").expect("send");
        let mut client_side = Connection {
            stream: Script::saying(server_side.stream.written),
            ..connection
        };
        assert_eq!(client_side.recv().expect("recv"), (PING, b"hi".to_vec()));
    }

    #[test]
    fn a_login_sends_the_stored_credentials_and_keeps_the_ones_it_is_given() {
        let stored = Credentials {
            username: "someone".into(),
            auth_data: vec![9, 9],
        };
        let session = client(&[welcome()])
            .login(Login::Stored(&stored), "device-1")
            .expect("login");
        assert_eq!(
            session.credentials(),
            &Credentials {
                username: "someone".into(),
                auth_data: vec![1, 2, 3]
            }
        );
        let sent = to_server(session.connection.stream.written);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, LOGIN);
        let packet = ClientResponseEncrypted::parse_from_bytes(&sent[0].1).expect("login packet");
        assert_eq!(packet.login_credentials.username(), "someone");
        assert_eq!(packet.login_credentials.auth_data(), [9, 9]);
        assert_eq!(
            packet.login_credentials.typ(),
            AuthenticationType::AUTHENTICATION_STORED_SPOTIFY_CREDENTIALS
        );
        assert_eq!(packet.system_info.device_id(), "device-1");
    }

    #[test]
    fn a_token_login_carries_the_token_and_no_username() {
        let session = client(&[welcome()])
            .login(Login::Token("oauth-token"), "device-1")
            .expect("login");
        let sent = to_server(session.connection.stream.written);
        let packet = ClientResponseEncrypted::parse_from_bytes(&sent[0].1).expect("login packet");
        assert!(!packet.login_credentials.has_username());
        assert_eq!(packet.login_credentials.auth_data(), b"oauth-token");
        assert_eq!(
            packet.login_credentials.typ(),
            AuthenticationType::AUTHENTICATION_SPOTIFY_TOKEN
        );
    }

    #[test]
    fn a_refused_login_says_whether_the_stored_one_is_spent() {
        let refusal = |code: ErrorCode| {
            let mut failed = APLoginFailed::new();
            failed.set_error_code(code);
            let packet = (AUTH_FAILURE, failed.write_to_bytes().expect("failure"));
            client(&[packet])
                .login(Login::Token("t"), "device-1")
                .err()
                .expect("refused")
        };
        assert!(refusal(ErrorCode::BadCredentials).expires_credentials());
        let travel = refusal(ErrorCode::TravelRestriction);
        assert!(!travel.expires_credentials());
        assert!(travel.message().contains("country or travel restriction"));
        assert!(!refusal(ErrorCode::TryAnotherAP).expires_credentials());
    }

    fn key_answer(command: u8, sequence: u32, rest: &[u8]) -> (u8, Vec<u8>) {
        let mut payload = sequence.to_be_bytes().to_vec();
        payload.extend_from_slice(rest);
        (command, payload)
    }

    #[test]
    fn a_key_request_answers_pings_and_learns_the_account_on_the_way() {
        let product = b"<products><product><type>premium</type></product></products>".to_vec();
        let mut session = client(&[
            welcome(),
            (PING, vec![0; 4]),
            (COUNTRY_CODE, b"BE".to_vec()),
            (PRODUCT_INFO, product),
            key_answer(AES_KEY, 0, &[0xaa; 16]),
            key_answer(AES_KEY_ERROR, 1, &[0, 1]),
        ])
        .login(Login::Token("t"), "device-1")
        .expect("login");

        let key = session.audio_key(&[1; 16], &[2; 20]).expect("key");
        assert_eq!(key, [0xaa; 16]);
        assert_eq!(session.product(), Some("premium"));
        assert_eq!(session.country(), Some("BE"));
        assert!(matches!(
            session.audio_key(&[1; 16], &[2; 20]),
            Err(KeyError::Refused)
        ));
        // Nothing more is coming, which is a dead connection, not a refusal.
        assert!(matches!(
            session.audio_key(&[1; 16], &[2; 20]),
            Err(KeyError::Io(_))
        ));

        let sent = to_server(session.connection.stream.written);
        let commands: Vec<u8> = sent.iter().map(|(command, _)| *command).collect();
        assert_eq!(
            commands,
            [LOGIN, REQUEST_KEY, PONG, REQUEST_KEY, REQUEST_KEY]
        );
        let mut request = vec![2; 20];
        request.extend_from_slice(&[1; 16]);
        request.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        assert_eq!(sent[1].1, request);
        assert_eq!(&sent[3].1[36..40], &1u32.to_be_bytes());
    }

    #[test]
    fn the_account_type_is_read_from_the_product_xml() {
        assert_eq!(
            product_type("<products><product><type> free </type></product></products>").as_deref(),
            Some("free")
        );
        assert_eq!(product_type("<products/>"), None);
    }

    /// Talks to Spotify, so it runs only when asked for:
    /// `cargo test -- --ignored access_point`.
    #[test]
    #[ignore = "needs the network"]
    fn a_real_access_point_answers_the_key_exchange_with_a_signed_key() {
        // An access point refuses a connection now and then.
        let stream = (0..5)
            .find_map(|_| std::net::TcpStream::connect("ap.spotify.com:443").ok())
            .expect("connect");
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("timeout");
        Connection::handshake(stream).expect("handshake");
    }

    #[test]
    fn only_spotifys_signature_passes() {
        assert!(!signed_by_spotify(&[1; 96], &[0; 256]));
        assert!(!signed_by_spotify(&[1; 96], &[1; 255]));
        assert!(!signed_by_spotify(&[1; 96], &[0xff; 256]));
    }
}

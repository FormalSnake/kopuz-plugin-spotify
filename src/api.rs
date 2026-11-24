//! Spotify's HTTP side: the access token a stored login buys, the client
//! token that goes with it, and requests to the client's own API.

use std::cell::RefCell;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use kopuz_plugin_sdk::http::{Client, Response};
use kopuz_plugin_sdk::{Result, SourceError};
use librespot_protocol::clienttoken_http::{
    ChallengeAnswer, ChallengeType, ClientTokenRequest, ClientTokenRequestType,
    ClientTokenResponse, ClientTokenResponseType,
};
use librespot_protocol::login5::login_response::Response as LoginAnswer;
use librespot_protocol::login5::{ChallengeSolution, LoginError, LoginRequest, LoginResponse};
use protobuf::Message as _;
use serde::{Deserialize, Serialize};
use sha1::{Digest as _, Sha1};

/// The desktop client's id, which is the one a stored login is bound to.
pub const CLIENT_ID: &str = "65b708073fc0480ea92a077233ca87bd";
/// The desktop client version the access point and the token endpoints are told.
pub const CLIENT_VERSION: &str = "1.2.52.442";
pub const CLIENT_VERSION_NUMBER: u64 = 124200290;

const APRESOLVE: &str = "https://apresolve.spotify.com/?type=accesspoint&type=dealer&type=spclient";
const FALLBACK_SPCLIENT: &str = "spclient.wg.spotify.com:443";
const FALLBACK_ACCESS_POINT: &str = "ap.spotify.com:443";

/// A hashcash that is not solved by then has expired.
const HASHCASH_LIMIT: Duration = Duration::from_secs(5);
const TRIES: usize = 3;

/// What a sign-in stores: the login the access point hands back, which does
/// not expire on its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credentials {
    pub username: String,
    #[serde(with = "base64_bytes")]
    pub auth_data: Vec<u8>,
}

mod base64_bytes {
    use super::*;

    pub fn serialize<S: serde::Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        STANDARD.decode(text).map_err(serde::de::Error::custom)
    }
}

impl Credentials {
    pub fn pack(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Nothing for a token another build stored, which is a sign-in again.
    pub fn unpack(stored: &str) -> Option<Self> {
        serde_json::from_str::<Self>(stored)
            .ok()
            .filter(|credentials| !credentials.auth_data.is_empty())
    }
}

struct Token {
    value: String,
    until: Instant,
}

impl Token {
    fn new(value: String, seconds: i64) -> Self {
        // Renewed a minute early, so a request never leaves with one about to lapse.
        let lifetime = u64::try_from(seconds).unwrap_or(3600).saturating_sub(60);
        Self {
            value,
            until: Instant::now() + Duration::from_secs(lifetime),
        }
    }

    fn live(&self) -> Option<String> {
        (Instant::now() < self.until).then(|| self.value.clone())
    }
}

#[derive(Deserialize, Default)]
struct Resolved {
    #[serde(default)]
    accesspoint: Vec<String>,
    #[serde(default)]
    spclient: Vec<String>,
}

pub struct Api {
    http: Client,
    credentials: Option<Credentials>,
    device_id: String,
    access: RefCell<Option<Token>>,
    client: RefCell<Option<Token>>,
    resolved: RefCell<Option<Resolved>>,
}

impl Api {
    pub fn new(credentials: Option<Credentials>, device_id: &str) -> Self {
        Self {
            http: Client::new().with_timeout(Duration::from_secs(20)),
            credentials,
            device_id: device_id.to_string(),
            access: RefCell::new(None),
            client: RefCell::new(None),
            resolved: RefCell::new(None),
        }
    }

    pub fn http(&self) -> &Client {
        &self.http
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn credentials(&self) -> Result<&Credentials> {
        self.credentials.as_ref().ok_or(SourceError::Auth)
    }

    /// The account's canonical user name, as it appears in `spotify:user:` URIs.
    pub fn username(&self) -> Result<&str> {
        Ok(&self.credentials()?.username)
    }

    fn resolve<T>(&self, pick: impl Fn(&Resolved) -> T) -> T {
        let mut resolved = self.resolved.borrow_mut();
        let resolved = resolved.get_or_insert_with(|| {
            self.http
                .get(APRESOLVE)
                .send()
                .ok()
                .filter(Response::is_success)
                .and_then(|response| response.json::<Resolved>().ok())
                .unwrap_or_default()
        });
        pick(resolved)
    }

    /// Access points as `(host, port)`, best first, ending in the fixed one.
    pub fn access_points(&self) -> Vec<(String, u16)> {
        let mut listed = self.resolve(|resolved| resolved.accesspoint.clone());
        listed.push(FALLBACK_ACCESS_POINT.to_string());
        listed
            .iter()
            .filter_map(|entry| {
                let (host, port) = entry.rsplit_once(':')?;
                Some((host.to_string(), port.parse().ok()?))
            })
            .collect()
    }

    fn base_url(&self) -> String {
        let host = self
            .resolve(|resolved| resolved.spclient.first().cloned())
            .unwrap_or_else(|| FALLBACK_SPCLIENT.to_string());
        format!("https://{host}")
    }

    /// The token requests to the API carry, bought with the stored login.
    pub fn access_token(&self) -> Result<String> {
        if let Some(token) = self.access.borrow().as_ref().and_then(Token::live) {
            return Ok(token);
        }
        let credentials = self.credentials()?;
        let mut request = LoginRequest::new();
        let info = request.client_info.mut_or_insert_default();
        info.client_id = CLIENT_ID.to_string();
        info.device_id = self.device_id.clone();
        let stored = request.mut_stored_credential();
        stored.username = credentials.username.clone();
        stored.data = credentials.auth_data.clone();

        for _ in 0..TRIES {
            let answer = self.login5(&request)?;
            match answer.response {
                Some(LoginAnswer::Ok(ok)) => {
                    let token = Token::new(ok.access_token, ok.access_token_expires_in.into());
                    let value = token.value.clone();
                    *self.access.borrow_mut() = Some(token);
                    return Ok(value);
                }
                Some(LoginAnswer::Error(error)) => match error.enum_value() {
                    Ok(LoginError::TIMEOUT | LoginError::TOO_MANY_ATTEMPTS) => {}
                    Ok(LoginError::INVALID_CREDENTIALS | LoginError::BAD_REQUEST) => {
                        return Err(SourceError::Auth);
                    }
                    other => {
                        return Err(SourceError::Backend(format!(
                            "Spotify refused the login: {other:?}"
                        )));
                    }
                },
                Some(LoginAnswer::Challenges(challenges)) => {
                    for challenge in &challenges.challenges {
                        if !challenge.has_hashcash() {
                            continue;
                        }
                        let hashcash = challenge.hashcash();
                        let started = Instant::now();
                        let suffix = solve_hashcash(
                            &answer.login_context,
                            &hashcash.prefix,
                            hashcash.length,
                        )
                        .ok_or_else(|| backend("Spotify's login challenge expired"))?;
                        let took = started.elapsed();
                        let mut solution = ChallengeSolution::new();
                        let solved = solution.mut_hashcash();
                        solved.suffix = suffix.to_vec();
                        let duration = solved.duration.mut_or_insert_default();
                        duration.seconds = took.as_secs() as i64;
                        duration.nanos = took.subsec_nanos() as i32;
                        request
                            .challenge_solutions
                            .mut_or_insert_default()
                            .solutions
                            .push(solution);
                    }
                    request.login_context = answer.login_context;
                }
                _ => return Err(backend("Spotify's login answered nothing")),
            }
        }
        Err(backend("Spotify's login did not finish"))
    }

    fn login5(&self, request: &LoginRequest) -> Result<LoginResponse> {
        let body = request.write_to_bytes().map_err(encode_error)?;
        let mut builder = self
            .http
            .post("https://login5.spotify.com/v3/login")
            .header("Accept", "application/x-protobuf")
            .header("Content-Type", "application/x-protobuf")
            .body(body);
        if let Some(token) = self.client_token() {
            builder = builder.header("client-token", token);
        }
        let response = builder.send().map_err(request_error)?;
        if !response.is_success() {
            return Err(SourceError::from_status(response.status(), "Spotify login"));
        }
        LoginResponse::parse_from_bytes(response.bytes()).map_err(decode_error)
    }

    /// Identifies the client build to the API. Requests have worked without
    /// one, so a failure to get it is not a failure of the request.
    pub fn client_token(&self) -> Option<String> {
        if let Some(token) = self.client.borrow().as_ref().and_then(Token::live) {
            return Some(token);
        }
        let token = self
            .request_client_token()
            .inspect_err(|error| {
                kopuz_plugin_sdk::debug!("no client token: {}", error.message());
            })
            .ok()?;
        let value = token.value.clone();
        *self.client.borrow_mut() = Some(token);
        Some(value)
    }

    fn request_client_token(&self) -> Result<Token> {
        let mut request = ClientTokenRequest::new();
        request.request_type = ClientTokenRequestType::REQUEST_CLIENT_DATA_REQUEST.into();
        let data = request.mut_client_data();
        data.client_version = CLIENT_VERSION.to_string();
        data.client_id = CLIENT_ID.to_string();
        let sdk = data.mut_connectivity_sdk_data();
        sdk.device_id = self.device_id.clone();
        let linux = sdk
            .platform_specific_data
            .mut_or_insert_default()
            .mut_desktop_linux();
        linux.system_name = "Linux".to_string();
        linux.system_release = "0".to_string();
        linux.system_version = "0".to_string();
        linux.hardware = "x86_64".to_string();

        let mut answer = self.client_token_request(&request)?;
        for _ in 0..TRIES {
            match answer.response_type.enum_value() {
                Ok(ClientTokenResponseType::RESPONSE_GRANTED_TOKEN_RESPONSE) => {
                    let granted = answer.granted_token();
                    return Ok(Token::new(
                        granted.token.clone(),
                        granted.refresh_after_seconds.into(),
                    ));
                }
                Ok(ClientTokenResponseType::RESPONSE_CHALLENGES_RESPONSE) => {
                    let challenges = answer.challenges();
                    let challenge = challenges
                        .challenges
                        .first()
                        .ok_or_else(|| backend("Spotify sent no client token challenge"))?;
                    let parameters = challenge.evaluate_hashcash_parameters();
                    let prefix = unhex(&parameters.prefix)
                        .ok_or_else(|| backend("Spotify's client token challenge is malformed"))?;
                    let suffix = solve_hashcash(&[], &prefix, parameters.length)
                        .ok_or_else(|| backend("Spotify's client token challenge expired"))?;
                    let mut solved = ChallengeAnswer::new();
                    solved.mut_hash_cash().suffix = crate::ids::hex(&suffix).to_uppercase();
                    solved.ChallengeType = ChallengeType::CHALLENGE_HASH_CASH.into();
                    let mut reply = ClientTokenRequest::new();
                    reply.request_type =
                        ClientTokenRequestType::REQUEST_CHALLENGE_ANSWERS_REQUEST.into();
                    let answers = reply.mut_challenge_answers();
                    answers.state = challenges.state.clone();
                    answers.answers.push(solved);
                    answer = self.client_token_request(&reply)?;
                }
                _ => return Err(backend("Spotify's client token answer is unknown")),
            }
        }
        Err(backend("Spotify's client token challenges did not end"))
    }

    fn client_token_request(&self, request: &ClientTokenRequest) -> Result<ClientTokenResponse> {
        let body = request.write_to_bytes().map_err(encode_error)?;
        let response = self
            .http
            .post("https://clienttoken.spotify.com/v1/clienttoken")
            .header("Accept", "application/x-protobuf")
            .header("Content-Type", "application/x-protobuf")
            .body(body)
            .send()
            .map_err(request_error)?;
        if !response.is_success() {
            return Err(SourceError::from_status(
                response.status(),
                "Spotify client token",
            ));
        }
        ClientTokenResponse::parse_from_bytes(response.bytes()).map_err(decode_error)
    }

    /// A request to the client's own API. `endpoint` starts with `/`. A 401
    /// buys a fresh access token and asks once more.
    pub fn spclient(
        &self,
        method: &str,
        endpoint: &str,
        headers: &[(&str, &str)],
        body: Option<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        self.authorized(
            method,
            &format!("{}{endpoint}", self.base_url()),
            headers,
            body,
        )
    }

    /// A request to any Spotify host that takes the same two tokens.
    pub fn authorized(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        let mut renewed = false;
        loop {
            let mut request = self
                .http
                .request(method, url)
                .bearer_auth(self.access_token()?);
            if let Some(token) = self.client_token() {
                request = request.header("client-token", token);
            }
            for (name, value) in headers {
                request = request.header(*name, *value);
            }
            if let Some(body) = &body {
                request = request.body(body.clone());
            }
            let response = request.send().map_err(request_error)?;
            if response.status() == 401 && !renewed {
                renewed = true;
                *self.access.borrow_mut() = None;
                continue;
            }
            if !response.is_success() {
                return Err(SourceError::from_status(response.status(), "Spotify"));
            }
            return Ok(response.into_bytes());
        }
    }

    /// A protobuf request to the client's own API.
    pub fn spclient_proto<M: protobuf::Message>(
        &self,
        method: &str,
        endpoint: &str,
        body: Option<&dyn protobuf::MessageDyn>,
    ) -> Result<M> {
        let body = body
            .map(|body| body.write_to_bytes_dyn())
            .transpose()
            .map_err(encode_error)?;
        let headers: &[(&str, &str)] = match body {
            Some(_) => &[
                ("Accept", "application/x-protobuf"),
                ("Content-Type", "application/x-protobuf"),
            ],
            None => &[("Accept", "application/x-protobuf")],
        };
        let bytes = self.spclient(method, endpoint, headers, body)?;
        M::parse_from_bytes(&bytes).map_err(decode_error)
    }
}

pub fn backend(message: impl Into<String>) -> SourceError {
    SourceError::Backend(message.into())
}

pub fn request_error(error: kopuz_plugin_sdk::http::Error) -> SourceError {
    if error.is_connectivity() {
        SourceError::Connectivity
    } else {
        SourceError::Backend(error.to_string())
    }
}

pub fn decode_error(error: protobuf::Error) -> SourceError {
    backend(format!("Spotify's answer could not be read: {error}"))
}

fn encode_error(error: protobuf::Error) -> SourceError {
    backend(format!("the request could not be written: {error}"))
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect()
}

/// Sixteen bytes that, hashed after `prefix`, end in `length` zero bits.
/// Nothing once the challenge has expired.
fn solve_hashcash(context: &[u8], prefix: &[u8], length: i32) -> Option<[u8; 16]> {
    let started = Instant::now();
    let tail = |digest: &[u8]| i64::from_be_bytes(digest[12..20].try_into().unwrap_or_default());
    let target = tail(&Sha1::digest(context));
    let mut counter: i64 = 0;
    loop {
        if counter % 4096 == 0 && started.elapsed() >= HASHCASH_LIMIT {
            return None;
        }
        let mut suffix = [0; 16];
        suffix[..8].copy_from_slice(&target.wrapping_add(counter).to_be_bytes());
        suffix[8..].copy_from_slice(&counter.to_be_bytes());
        let digest = Sha1::new()
            .chain_update(prefix)
            .chain_update(suffix)
            .finalize();
        if tail(&digest).trailing_zeros() >= length.max(0) as u32 {
            return Some(suffix);
        }
        counter += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_survive_the_token_column() {
        let credentials = Credentials {
            username: "someone".into(),
            auth_data: vec![1, 2, 3, 250],
        };
        assert_eq!(Credentials::unpack(&credentials.pack()), Some(credentials));
    }

    #[test]
    fn a_token_from_another_build_is_a_sign_in_again() {
        assert_eq!(Credentials::unpack("access\nrefresh"), None);
        assert_eq!(Credentials::unpack(""), None);
        assert_eq!(
            Credentials::unpack(r#"{"username":"someone","auth_data":""}"#),
            None
        );
    }

    #[test]
    fn a_hashcash_solution_ends_in_the_zero_bits_asked_for() {
        let prefix = [0x12, 0x34, 0x56, 0x78];
        let suffix = solve_hashcash(b"context", &prefix, 10).expect("solved");
        let digest = Sha1::new()
            .chain_update(prefix)
            .chain_update(suffix)
            .finalize();
        let tail = i64::from_be_bytes(digest[12..20].try_into().expect("eight bytes"));
        assert!(tail.trailing_zeros() >= 10);
        // The counter is the second half, and the first is offset by the context's hash.
        let counter = i64::from_be_bytes(suffix[8..].try_into().expect("eight bytes"));
        let context = Sha1::digest(b"context");
        let target = i64::from_be_bytes(context[12..20].try_into().expect("eight bytes"));
        assert_eq!(
            i64::from_be_bytes(suffix[..8].try_into().expect("eight bytes")),
            target.wrapping_add(counter)
        );
    }

    #[test]
    fn hex_reads_both_cases_and_refuses_the_rest() {
        assert_eq!(unhex("0aFF"), Some(vec![0x0a, 0xff]));
        assert_eq!(unhex("0aF"), None);
        assert_eq!(unhex("zz"), None);
    }

    #[test]
    fn a_token_is_live_until_a_minute_before_it_lapses() {
        assert_eq!(Token::new("a".into(), 3600).live().as_deref(), Some("a"));
        assert_eq!(Token::new("a".into(), 30).live(), None);
    }
}

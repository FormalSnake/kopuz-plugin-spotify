//! Sign-in: Authorization Code with PKCE and a loopback redirect, as the
//! desktop client does it. The token it ends in is used once, to log in to
//! the access point, which answers with a login that does not expire.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use kopuz_plugin_sdk::{Result, SourceError, browser};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::api::{Api, CLIENT_ID, backend, request_error};

/// The desktop client's id takes a loopback redirect at this path.
const REDIRECT_PORT: u16 = 8898;
const REDIRECT_PATH: &str = "/login";
const REDIRECT_URI: &str = "http://127.0.0.1:8898/login";
const AUTHORIZE_URL: &str = "https://accounts.spotify.com/authorize";
const TOKEN_URL: &str = "https://accounts.spotify.com/api/token";
/// Everything the desktop client may ask for, since the token is traded for
/// a session rather than used against one endpoint.
const SCOPES: &str = "app-remote-control playlist-modify playlist-modify-private \
     playlist-modify-public playlist-read playlist-read-collaborative playlist-read-private \
     streaming ugc-image-upload user-follow-modify user-follow-read user-library-modify \
     user-library-read user-modify user-modify-playback-state user-modify-private \
     user-personalized user-read-birthdate user-read-currently-playing user-read-email \
     user-read-play-history user-read-playback-position user-read-playback-state \
     user-read-private user-read-recently-played user-top-read";

fn challenge_of(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn authorize_url(challenge: &str, state: &str) -> String {
    let query = [
        ("client_id", CLIENT_ID),
        ("response_type", "code"),
        ("redirect_uri", REDIRECT_URI),
        ("code_challenge_method", "S256"),
        ("code_challenge", challenge),
        ("scope", SCOPES),
        ("state", state),
    ];
    let query: Vec<String> = query
        .iter()
        .map(|(key, value)| format!("{key}={}", percent_encode(value)))
        .collect();
    format!("{AUTHORIZE_URL}?{}", query.join("&"))
}

fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                char::from(byte).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

/// The authorization code the redirect carries, once it is the answer to
/// the request that was made.
fn code_of(redirect: &browser::Redirect, state: &str) -> Result<String> {
    if let Some(error) = redirect.param("error") {
        return Err(backend(format!(
            "Spotify authorization was denied: {error}"
        )));
    }
    if redirect.param("state").as_deref() != Some(state) {
        return Err(backend(
            "Spotify sign-in failed a security check (state mismatch)",
        ));
    }
    redirect
        .param("code")
        .filter(|code| !code.is_empty())
        .ok_or_else(|| backend("Spotify's redirect carried no authorization code"))
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

/// Run the sign-in in the person's browser and return an access token.
pub fn sign_in(api: &Api) -> Result<String> {
    let verifier = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 64]>());
    let state = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>());
    let url = authorize_url(&challenge_of(&verifier), &state);
    let redirect = browser::sign_in(&url, REDIRECT_PORT, REDIRECT_PATH)
        .map_err(|error| backend(browser::message(&error)))?;
    let code = code_of(&redirect, &state)?;

    let response = api
        .http()
        .post(TOKEN_URL)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", CLIENT_ID),
            ("code_verifier", verifier.as_str()),
        ])
        .send()
        .map_err(request_error)?;
    if !response.is_success() {
        return Err(SourceError::Backend(format!(
            "Spotify's token endpoint answered {}: {}",
            response.status(),
            response.text()
        )));
    }
    response
        .json::<TokenResponse>()
        .map(|token| token.access_token)
        .map_err(|error| backend(format!("Spotify's token answer could not be read: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_challenge_is_the_verifiers_hash_url_safe_and_unpadded() {
        // RFC 7636, appendix B.
        assert_eq!(
            challenge_of("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn the_authorize_url_names_the_client_the_redirect_and_the_challenge() {
        let url = authorize_url("challenge", "state-1");
        assert!(url.starts_with("https://accounts.spotify.com/authorize?client_id="));
        assert!(url.contains(&format!("client_id={CLIENT_ID}")));
        assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A8898%2Flogin"));
        assert!(url.contains("code_challenge=challenge&"));
        assert!(url.contains("scope=app-remote-control%20playlist-modify%20"));
        assert!(url.ends_with("state=state-1"));
    }

    #[test]
    fn a_redirect_yields_its_code_only_for_the_state_that_was_sent() {
        let redirect = |target: &str| browser::Redirect::from(target.to_string());
        assert_eq!(
            code_of(&redirect("/login?code=abc&state=s1"), "s1"),
            Ok("abc".to_string())
        );
        let forged = code_of(&redirect("/login?code=abc&state=other"), "s1");
        assert!(matches!(forged, Err(SourceError::Backend(m)) if m.contains("state mismatch")));
        let denied = code_of(&redirect("/login?error=access_denied&state=s1"), "s1");
        assert!(matches!(denied, Err(SourceError::Backend(m)) if m.contains("access_denied")));
        assert!(code_of(&redirect("/login?state=s1"), "s1").is_err());
    }
}

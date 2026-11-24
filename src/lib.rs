//! Spotify as a Kopuz source. The catalogue and the library come from the
//! client's own API over HTTP; audio keys come from an access point over
//! TCP; the host fetches and decrypts the audio itself.

pub mod ap;
pub mod api;
pub mod auth;
pub mod catalog;
pub mod ids;
pub mod search;
pub mod stream;

use kopuz_plugin_sdk::{
    AuthOutcome, AuthSession, Check, CheckStep, Connection, LibrarySnapshot, PlaylistMeta, Result,
    SearchResults, Source, SourceError, StreamInfo, StreamQuality, Track, TrackPage,
};

use crate::ap::Login;
use crate::api::{Api, Credentials};

/// Liked songs are one list on Spotify's side, read a page of this many at a time.
const FAVORITES_PAGE: usize = 50;

pub struct Spotify {
    api: Api,
    keys: stream::Keys,
}

impl Source for Spotify {
    /// The browser sign-in ends in a token the access point takes once, in
    /// exchange for the login that is stored.
    fn login(connection: Connection, _username: &str, _password: &str) -> Result<AuthSession> {
        let api = Api::new(None, &connection.device_id);
        let token = auth::sign_in(&api)?;
        let session = stream::connect(&api, Login::Token(&token))?;
        let credentials = session.credentials();
        Ok(AuthSession {
            access_token: credentials.pack(),
            user_id: credentials.username.clone(),
        })
    }

    fn open(connection: Connection) -> Self {
        Self {
            api: Api::new(
                Credentials::unpack(&connection.token),
                &connection.device_id,
            ),
            keys: stream::Keys::default(),
        }
    }

    fn validate(&self) -> AuthOutcome {
        if self.api.credentials().is_err() {
            return AuthOutcome::Expired;
        }
        match catalog::probe(&self.api) {
            Ok(()) => AuthOutcome::Valid,
            Err(SourceError::Auth) => AuthOutcome::Expired,
            Err(_) => AuthOutcome::Unreachable,
        }
    }

    fn diagnose(&self) -> Result<Vec<Check>> {
        let session = match self.validate() {
            AuthOutcome::Valid => Ok(()),
            AuthOutcome::Expired => Err("the sign-in is no longer accepted".to_string()),
            AuthOutcome::Unreachable => Err("Spotify did not answer".to_string()),
        };
        Ok(vec![
            Check::of(CheckStep::Reach, stream::reach(&self.api), |access_point| {
                format!("key exchange with {access_point}")
            }),
            Check::of(CheckStep::Session, session, |()| "accepted".to_string()),
        ])
    }

    fn user_id(&self) -> Result<Option<String>> {
        Ok(Some(self.api.username()?.to_string()))
    }

    fn fetch_library(&self) -> Result<LibrarySnapshot> {
        let (albums, tracks) = catalog::saved_albums(&self.api)?;
        Ok(LibrarySnapshot {
            albums,
            tracks,
            artists: Vec::new(),
        })
    }

    fn fetch_album_tracks(&self, album_id: &str) -> Result<Vec<Track>> {
        catalog::album_tracks(&self.api, album_id)
    }

    fn fetch_track(&self, item_id: &str) -> Result<Option<Track>> {
        catalog::track(&self.api, item_id)
    }

    fn search(&self, query: &str) -> Result<SearchResults> {
        search::search(&self.api, query)
    }

    fn fetch_playlists(&self) -> Result<Vec<PlaylistMeta>> {
        catalog::playlists(&self.api)
    }

    fn fetch_playlist_entries(&self, playlist_id: &str) -> Result<Vec<Track>> {
        catalog::playlist_tracks(&self.api, playlist_id)
    }

    fn fetch_favorites(&self) -> Result<Vec<String>> {
        catalog::liked_ids(&self.api)
    }

    fn fetch_favorites_page(&self, cursor: Option<&str>) -> Result<TrackPage> {
        let offset: usize = cursor.and_then(|cursor| cursor.parse().ok()).unwrap_or(0);
        let liked = catalog::liked_ids(&self.api)?;
        let page: Vec<String> = liked
            .iter()
            .skip(offset)
            .take(FAVORITES_PAGE)
            .cloned()
            .collect();
        let end = offset + FAVORITES_PAGE;
        Ok(TrackPage {
            tracks: catalog::tracks(&self.api, &page)?,
            next: (end < liked.len()).then(|| end.to_string()),
        })
    }

    fn push_favorite(&self, item_id: &str, on: bool) -> Result<()> {
        catalog::set_liked(&self.api, item_id, on)
    }

    fn resolve_stream(&self, item_id: &str, quality: StreamQuality) -> Result<StreamInfo> {
        stream::resolve(&self.api, &self.keys, item_id, quality)
    }
}

kopuz_plugin_sdk::export_source!(Spotify);

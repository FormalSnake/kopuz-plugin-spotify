//! A track's audio: an Ogg Vorbis (or MP3) file on Spotify's CDN, encrypted
//! with a key of its own that the access point hands to a logged-in Premium
//! session. The plugin finds the file and its key; the host fetches and
//! decrypts it.

use std::cell::RefCell;
use std::time::Duration;

use kopuz_plugin_sdk::tcp::Stream;
use kopuz_plugin_sdk::{Result, SourceError, StreamInfo, StreamQuality};
use librespot_protocol::metadata::audio_file::Format;
use librespot_protocol::metadata::{AudioFile, Track};
use librespot_protocol::storage_resolve::StorageResolveResponse;
use librespot_protocol::storage_resolve::storage_resolve_response::Result as Storage;

use crate::ap::{Connection, KeyError, Login, LoginError, Session};
use crate::api::{Api, backend};
use crate::ids;

/// Every file is encrypted in CTR mode from this same counter block.
const AUDIO_IV: [u8; 16] = [
    0x72, 0xe0, 0x67, 0xfb, 0xdd, 0xcb, 0xcf, 0x77, 0xeb, 0xe8, 0xbc, 0x64, 0x3f, 0x63, 0x0d, 0x93,
];

/// An Ogg file opens with a header of Spotify's own (normalisation data)
/// that no demuxer understands; the Ogg stream starts after it.
const OGG_HEADER_END: u32 = 0xa7;

/// The CDN hosts the manifest lets the host fetch from.
const CDN_DOMAINS: [&str; 2] = ["spotifycdn.com", "scdn.co"];

const AP_TIMEOUT: Duration = Duration::from_secs(5);
/// Access points tried before a login is given up on.
const AP_TRIES: usize = 3;

/// Log in to an access point, trying the next one when one does not answer
/// or says to go elsewhere.
pub fn connect(api: &Api, login: Login<'_>) -> Result<Session<Stream>> {
    let mut last = SourceError::Connectivity;
    for (host, port) in api.access_points().into_iter().take(AP_TRIES) {
        let attempt = Stream::connect(&host, port, Some(AP_TIMEOUT))
            .map_err(std::io::Error::from)
            .and_then(|mut stream| {
                stream.set_read_timeout(Some(AP_TIMEOUT));
                Connection::handshake(stream)
            })
            .map_err(LoginError::Io)
            .and_then(|connection| {
                let login = match &login {
                    Login::Token(token) => Login::Token(token),
                    Login::Stored(stored) => Login::Stored(stored),
                };
                connection.login(login, api.device_id())
            });
        match attempt {
            Ok(session) => return Ok(session),
            Err(error) if error.expires_credentials() => return Err(SourceError::Auth),
            Err(error) => {
                kopuz_plugin_sdk::debug!("access point {host}:{port}: {}", error.message());
                let elsewhere = matches!(
                    error,
                    LoginError::Io(_)
                        | LoginError::Refused(
                            librespot_protocol::keyexchange::ErrorCode::TryAnotherAP
                        )
                );
                last = match error {
                    LoginError::Io(_) => SourceError::Connectivity,
                    refused => backend(refused.message()),
                };
                if !elsewhere {
                    break;
                }
            }
        }
    }
    Err(last)
}

/// The access point a key exchange succeeded with, which takes no login.
pub fn reach(api: &Api) -> std::result::Result<String, String> {
    let (host, port) = api
        .access_points()
        .into_iter()
        .next()
        .ok_or("Spotify named no access point")?;
    let mut stream = Stream::connect(&host, port, Some(AP_TIMEOUT))
        .map_err(|error| kopuz_plugin_sdk::tcp::message(&error))?;
    stream.set_read_timeout(Some(AP_TIMEOUT));
    Connection::handshake(stream).map_err(|error| error.to_string())?;
    Ok(format!("{host}:{port}"))
}

/// The access point session audio keys come from, connected on first use
/// and again when the connection has gone away.
#[derive(Default)]
pub struct Keys {
    session: RefCell<Option<Session<Stream>>>,
}

impl Keys {
    fn request(&self, api: &Api, track_gid: &[u8; 16], file_id: &[u8; 20]) -> Result<[u8; 16]> {
        let mut slot = self.session.borrow_mut();
        // An idle connection may have been closed under us, which only the
        // first read shows.
        for fresh in [false, true] {
            if slot.is_none() || fresh {
                *slot = Some(connect(api, Login::Stored(api.credentials()?))?);
            }
            let Some(session) = slot.as_mut() else {
                continue;
            };
            match session.audio_key(track_gid, file_id) {
                Ok(key) => return Ok(key),
                Err(KeyError::Refused) => {
                    return Err(backend(refusal_message(session.product())));
                }
                Err(KeyError::Io(error)) => {
                    kopuz_plugin_sdk::debug!("audio key request failed: {error}");
                    *slot = None;
                }
            }
        }
        Err(backend(
            "Could not request the audio key from Spotify. Try again.",
        ))
    }
}

fn refusal_message(product: Option<&str>) -> String {
    match product {
        Some("free") => "Spotify reports this account as Free. Playback in Kopuz requires \
                         Premium. If you just upgraded, sign in again."
            .to_string(),
        Some("premium") => "Spotify refused the audio key even though this account is Premium. \
                            Try again later or play it in the official Spotify app."
            .to_string(),
        _ => "Spotify refused the audio key. Check the account's Premium status or try again \
              later."
            .to_string(),
    }
}

fn kbps(format: Format) -> u32 {
    match format {
        Format::OGG_VORBIS_320 | Format::MP3_320 => 320,
        Format::MP3_256 => 256,
        Format::OGG_VORBIS_160 | Format::MP3_160 => 160,
        _ => 96,
    }
}

fn is_ogg(format: Format) -> bool {
    matches!(
        format,
        Format::OGG_VORBIS_320 | Format::OGG_VORBIS_160 | Format::OGG_VORBIS_96
    )
}

/// The formats the host can decode, the one closest to `quality` first and
/// MP3 as the fallback Spotify keeps for some of its catalogue.
fn preference(quality: StreamQuality) -> [Format; 7] {
    let ogg = match quality {
        StreamQuality::High => [
            Format::OGG_VORBIS_320,
            Format::OGG_VORBIS_160,
            Format::OGG_VORBIS_96,
        ],
        StreamQuality::Normal => [
            Format::OGG_VORBIS_160,
            Format::OGG_VORBIS_96,
            Format::OGG_VORBIS_320,
        ],
        StreamQuality::Low => [
            Format::OGG_VORBIS_96,
            Format::OGG_VORBIS_160,
            Format::OGG_VORBIS_320,
        ],
    };
    [
        ogg[0],
        ogg[1],
        ogg[2],
        Format::MP3_320,
        Format::MP3_256,
        Format::MP3_160,
        Format::MP3_96,
    ]
}

fn pick(files: &[AudioFile], quality: StreamQuality) -> Option<(Format, [u8; 20])> {
    preference(quality).into_iter().find_map(|format| {
        files
            .iter()
            .find(|file| file.format() == format)
            .and_then(|file| Some((format, file.file_id().try_into().ok()?)))
    })
}

/// The track itself when it has audio, else the first alternative that does
/// (a re-release of the same recording). The key is bound to the track
/// whose file is read, so that is the one returned.
fn playable(track: &Track) -> Option<&Track> {
    std::iter::once(track)
        .chain(track.alternative.iter())
        .find(|candidate| !candidate.file.is_empty())
}

/// A URL on a host the manifest lists, which is all the host will fetch.
fn cdn_url(urls: &[String]) -> Option<&String> {
    urls.iter().find(|url| {
        let host = url
            .strip_prefix("https://")
            .and_then(|rest| rest.split(['/', ':', '?']).next())
            .unwrap_or_default();
        CDN_DOMAINS.iter().any(|domain| {
            host.strip_suffix(domain)
                .is_some_and(|rest| rest.is_empty() || rest.ends_with('.'))
        })
    })
}

pub fn resolve(
    api: &Api,
    keys: &Keys,
    item_id: &str,
    quality: StreamQuality,
) -> Result<StreamInfo> {
    let gid = ids::gid_from_base62(item_id)
        .ok_or_else(|| SourceError::InvalidInput(format!("{item_id} is not a Spotify track id")))?;
    let track: Track = api.spclient_proto(
        "GET",
        &format!("/metadata/4/track/{}", ids::hex(&gid)),
        None,
    )?;
    let source = playable(&track)
        .ok_or_else(|| backend(format!("\"{}\" has no audio on Spotify here", track.name())))?;
    let (format, file_id) = pick(&source.file, quality).ok_or_else(|| {
        backend(format!(
            "Spotify offers \"{}\" in no format Kopuz can play",
            track.name()
        ))
    })?;
    let key_gid: [u8; 16] = source
        .gid()
        .try_into()
        .map_err(|_| backend("Spotify's track has no id"))?;

    // Asked for before the file is located, so an account that may not
    // stream hears why instead of a decoder error.
    let key = keys.request(api, &key_gid, &file_id)?;

    let storage: StorageResolveResponse = api.spclient_proto(
        "GET",
        &format!(
            "/storage-resolve/files/audio/interactive/{}",
            ids::hex(&file_id)
        ),
        None,
    )?;
    if storage.result.enum_value() != Ok(Storage::CDN) {
        return Err(backend(format!(
            "Spotify would not stream \"{}\"",
            track.name()
        )));
    }
    let url = cdn_url(&storage.cdnurl)
        .ok_or_else(|| backend("Spotify named no CDN this plugin may reach"))?;

    let skip = if is_ogg(format) { OGG_HEADER_END } else { 0 };
    kopuz_plugin_sdk::report_stream_key(url, &key, &AUDIO_IV, skip);
    Ok(StreamInfo {
        duration_secs: u64::try_from(source.duration())
            .ok()
            .filter(|millis| *millis > 0)
            .map(|millis| millis / 1000),
        bitrate: Some(kbps(format) * 1000),
        ..StreamInfo::url(url)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(format: Format, id: u8) -> AudioFile {
        let mut file = AudioFile::new();
        file.set_format(format);
        file.set_file_id(vec![id; 20]);
        file
    }

    #[test]
    fn the_quality_asked_for_comes_first_and_mp3_last() {
        let files = [
            file(Format::MP3_320, 1),
            file(Format::OGG_VORBIS_96, 2),
            file(Format::OGG_VORBIS_320, 3),
            file(Format::AAC_24, 4),
        ];
        assert_eq!(
            pick(&files, StreamQuality::High),
            Some((Format::OGG_VORBIS_320, [3; 20]))
        );
        assert_eq!(
            pick(&files, StreamQuality::Low),
            Some((Format::OGG_VORBIS_96, [2; 20]))
        );
        // No 160, so the next one down.
        assert_eq!(
            pick(&files, StreamQuality::Normal),
            Some((Format::OGG_VORBIS_96, [2; 20]))
        );
        assert_eq!(
            pick(&files[..1], StreamQuality::High),
            Some((Format::MP3_320, [1; 20]))
        );
        assert_eq!(pick(&files[3..], StreamQuality::High), None);
    }

    #[test]
    fn a_file_id_of_the_wrong_length_is_not_a_file() {
        let mut short = file(Format::OGG_VORBIS_320, 1);
        short.set_file_id(vec![1; 4]);
        assert_eq!(pick(&[short], StreamQuality::High), None);
    }

    #[test]
    fn a_track_without_audio_plays_its_first_alternative_that_has_some() {
        let mut track = Track::new();
        track.set_gid(vec![1; 16]);
        assert!(playable(&track).is_none());

        let mut empty = Track::new();
        empty.set_gid(vec![2; 16]);
        let mut rerelease = Track::new();
        rerelease.set_gid(vec![3; 16]);
        rerelease.file.push(file(Format::OGG_VORBIS_160, 9));
        track.alternative.push(empty);
        track.alternative.push(rerelease);
        assert_eq!(playable(&track).map(Track::gid), Some(&[3u8; 16][..]));

        track.file.push(file(Format::OGG_VORBIS_320, 8));
        assert_eq!(playable(&track).map(Track::gid), Some(&[1u8; 16][..]));
    }

    #[test]
    fn only_a_cdn_the_manifest_lists_is_used() {
        let urls = [
            "https://audio-ak-spotify-com.akamaized.net/audio/abc?token=1".to_string(),
            "https://evil.example/audio-fa.scdn.co/abc".to_string(),
            "https://notscdn.co/audio/abc".to_string(),
            "https://audio-fa.scdn.co/audio/abc?token=2".to_string(),
            "https://audio4-ak.spotifycdn.com/audio/abc".to_string(),
        ];
        assert_eq!(cdn_url(&urls), Some(&urls[3]));
        assert_eq!(cdn_url(&urls[4..]), Some(&urls[4]));
        assert_eq!(cdn_url(&urls[..3]), None);
    }

    #[test]
    fn a_refused_key_is_explained_by_the_account_type() {
        assert!(refusal_message(Some("free")).contains("requires Premium"));
        assert!(refusal_message(Some("premium")).contains("even though this account is Premium"));
        let unknown = refusal_message(None);
        assert!(!unknown.contains("Free") && !unknown.contains("is Premium"));
    }

    #[test]
    fn only_an_ogg_file_carries_the_header_to_skip() {
        assert!(is_ogg(Format::OGG_VORBIS_160));
        assert!(!is_ogg(Format::MP3_320));
        assert_eq!(kbps(Format::OGG_VORBIS_320), 320);
        assert_eq!(kbps(Format::MP3_256), 256);
        assert_eq!(kbps(Format::OGG_VORBIS_96), 96);
    }
}

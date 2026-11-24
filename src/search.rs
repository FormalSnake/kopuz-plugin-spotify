//! Search through the web player's GraphQL gateway, which is what the
//! desktop client uses too. The gateway only answers persisted queries: the
//! request names an operation and the SHA-256 of its text, taken from the
//! web player's bundle. A new bundle can retire the hash, and the gateway
//! then answers `PersistedQueryNotFound`, which surfaces as a search error
//! rather than wrong results.

use kopuz_plugin_sdk::{Album, ArtistCredit, Result, SearchResults, SourceError, Track, cover};
use serde_json::{Value, json};

use crate::api::Api;
use crate::ids::id_of_uri;

const GATEWAY: &str = "https://api-partner.spotify.com/pathfinder/v1/query";
/// `searchDesktop` from `xpui-routes-search`, web player build 5cec5e91.
const SEARCH_DESKTOP: &str = "eef7cc54888d91bdd6802623477873caa3948ae173a0c34fd86827b267e94c03";
const SAMPLE_RATE: u32 = 44100;
const BITRATE_KBPS: u32 = 320;

/// Tracks and albums matching `query`, as the web player's search shows them.
pub fn search(api: &Api, query: &str) -> Result<SearchResults> {
    let query = query.trim();
    if query.is_empty() {
        return Ok(SearchResults {
            tracks: Vec::new(),
            albums: Vec::new(),
        });
    }
    let body = serde_json::to_vec(&request(query)).map_err(|error| {
        SourceError::Backend(format!("the search could not be written: {error}"))
    })?;
    let answer = api.authorized(
        "POST",
        GATEWAY,
        &[
            ("Content-Type", "application/json"),
            ("Accept", "application/json"),
            ("app-platform", "WebPlayer"),
        ],
        Some(body),
    )?;
    let json: Value = serde_json::from_slice(&answer).map_err(|error| {
        SourceError::Backend(format!(
            "Spotify's search answer could not be read: {error}"
        ))
    })?;
    parse_search(&json)
}

fn request(query: &str) -> Value {
    json!({
        "operationName": "searchDesktop",
        "variables": {
            "searchTerm": query,
            "offset": 0,
            "limit": 20,
            "numberOfTopResults": 5,
            "includeAudiobooks": false,
            "includeArtistHasConcertsField": false,
            "includePreReleases": false,
            "includeLocalConcertsField": false,
            "includeAuthors": false,
        },
        "extensions": { "persistedQuery": { "version": 1, "sha256Hash": SEARCH_DESKTOP } },
    })
}

fn parse_search(json: &Value) -> Result<SearchResults> {
    if let Some(message) = json["errors"][0]["message"].as_str() {
        return Err(SourceError::Backend(format!(
            "Spotify search refused the query: {message}"
        )));
    }
    let results = &json["data"]["searchV2"];
    let tracks = results["tracksV2"]["items"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| parse_track(&item["item"]["data"]))
                .collect()
        })
        .unwrap_or_default();
    let albums = results["albumsV2"]["items"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| parse_album(&item["data"]))
                .collect()
        })
        .unwrap_or_default();
    Ok(SearchResults { tracks, albums })
}

fn id_of(uri: &Value, kind: &str) -> Option<String> {
    id_of_uri(uri.as_str()?, kind).map(str::to_string)
}

fn artist_credits(data: &Value) -> Vec<ArtistCredit> {
    data["artists"]["items"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|artist| {
                    let name = artist["profile"]["name"].as_str()?;
                    Some(match id_of(&artist["uri"], "artist") {
                        Some(id) => ArtistCredit::linked(name, id),
                        None => ArtistCredit::unlinked(name),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The widest of a `coverArt.sources` list.
fn cover_of(data: &Value) -> Option<String> {
    data["coverArt"]["sources"]
        .as_array()?
        .iter()
        .max_by_key(|source| source["width"].as_u64().unwrap_or(0))
        .and_then(|source| source["url"].as_str())
        .filter(|url| !url.is_empty())
        .map(cover::url)
}

fn parse_track(data: &Value) -> Option<Track> {
    let item_id = id_of(&data["uri"], "track")?;
    let credits = artist_credits(data);
    let artists: Vec<String> = credits.iter().map(|credit| credit.name.clone()).collect();
    let album = &data["albumOfTrack"];
    Some(Track {
        item_id,
        cover: cover_of(album),
        album_id: id_of(&album["uri"], "album").unwrap_or_default(),
        title: data["name"].as_str().unwrap_or_default().to_string(),
        artist: artists.first().cloned().unwrap_or_default(),
        album: album["name"].as_str().unwrap_or_default().to_string(),
        duration_secs: data["duration"]["totalMilliseconds"].as_u64().unwrap_or(0) / 1000,
        sample_rate: SAMPLE_RATE,
        bitrate_kbps: BITRATE_KBPS,
        artists,
        credits,
        ..Track::default()
    })
}

fn parse_album(data: &Value) -> Option<Album> {
    let id = id_of(&data["uri"], "album")?;
    let lead = artist_credits(data).into_iter().next();
    Some(Album {
        id,
        title: data["name"].as_str().unwrap_or_default().to_string(),
        artist: lead
            .as_ref()
            .map(|credit| credit.name.clone())
            .unwrap_or_default(),
        genre: String::new(),
        year: data["date"]["year"]
            .as_u64()
            .and_then(|year| u16::try_from(year).ok())
            .unwrap_or(0),
        cover: cover_of(data),
        artist_id: lead.and_then(|credit| credit.id),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_web_players_search_shape() {
        let json = json!({
            "data": { "searchV2": {
                "tracksV2": { "items": [
                    { "item": { "data": {
                        "uri": "spotify:track:4PTG3Z6ehGkBFwjybzWkR8",
                        "name": "Never Gonna Give You Up",
                        "duration": { "totalMilliseconds": 213573 },
                        "artists": { "items": [ {
                            "uri": "spotify:artist:0gxyHStUsqpMadRV0Di1Qt",
                            "profile": { "name": "Rick Astley" }
                        } ] },
                        "albumOfTrack": {
                            "uri": "spotify:album:6eUW0wxWtzkFdaEFsTJto6",
                            "name": "Whenever You Need Somebody",
                            "coverArt": { "sources": [
                                { "width": 64, "url": "https://i.scdn.co/image/small" },
                                { "width": 640, "url": "https://i.scdn.co/image/large" }
                            ] }
                        }
                    } } },
                    { "item": { "data": { "uri": "spotify:episode:4PTG3Z6ehGkBFwjybzWkR8" } } }
                ] },
                "albumsV2": { "items": [ { "data": {
                    "uri": "spotify:album:0W1gLfsJ17r7hRT7jW7KUT",
                    "name": "An Album",
                    "date": { "year": 2022 },
                    "artists": { "items": [ { "profile": { "name": "Someone" } } ] },
                    "coverArt": { "sources": [ { "width": 300, "url": "https://i.scdn.co/image/a" } ] }
                } } ] }
            } }
        });
        let results = parse_search(&json).expect("results");
        assert_eq!(results.tracks.len(), 1);
        let track = &results.tracks[0];
        assert_eq!(track.item_id, "4PTG3Z6ehGkBFwjybzWkR8");
        assert_eq!(track.duration_secs, 213);
        assert_eq!(track.artist, "Rick Astley");
        assert_eq!(track.artists, vec!["Rick Astley"]);
        assert_eq!(
            track.credits,
            vec![ArtistCredit::linked(
                "Rick Astley",
                "0gxyHStUsqpMadRV0Di1Qt"
            )]
        );
        assert_eq!(track.album, "Whenever You Need Somebody");
        assert_eq!(track.album_id, "6eUW0wxWtzkFdaEFsTJto6");
        assert_eq!(
            track.cover.as_deref(),
            Some("directurl:https://i.scdn.co/image/large")
        );
        assert_eq!((track.sample_rate, track.bitrate_kbps), (44100, 320));

        assert_eq!(results.albums.len(), 1);
        let album = &results.albums[0];
        assert_eq!(album.id, "0W1gLfsJ17r7hRT7jW7KUT");
        assert_eq!(album.year, 2022);
        assert_eq!(album.artist, "Someone");
        assert_eq!(album.artist_id, None);
        assert_eq!(
            album.cover.as_deref(),
            Some("directurl:https://i.scdn.co/image/a")
        );
    }

    #[test]
    fn an_album_keeps_its_lead_artists_identity() {
        let album = parse_album(&json!({
            "uri": "spotify:album:6eUW0wxWtzkFdaEFsTJto6",
            "name": "Album",
            "artists": { "items": [
                { "uri": "spotify:artist:0gxyHStUsqpMadRV0Di1Qt", "profile": { "name": "Artist" } },
                { "uri": "spotify:artist:1111111111111111111111", "profile": { "name": "Guest" } }
            ] }
        }))
        .expect("album");
        assert_eq!(album.artist, "Artist");
        assert_eq!(album.artist_id.as_deref(), Some("0gxyHStUsqpMadRV0Di1Qt"));
        assert_eq!(album.cover, None);
    }

    #[test]
    fn a_refused_query_is_an_error() {
        let json = json!({ "errors": [ { "message": "PersistedQueryNotFound" } ] });
        let error = parse_search(&json).expect_err("an error");
        assert!(error.message().contains("PersistedQueryNotFound"));
    }

    #[test]
    fn an_empty_answer_has_no_results() {
        let results = parse_search(&json!({ "data": {} })).expect("results");
        assert!(results.tracks.is_empty() && results.albums.is_empty());
    }

    #[test]
    fn the_request_names_the_persisted_query() {
        let body = request("rick");
        assert_eq!(body["operationName"], "searchDesktop");
        assert_eq!(body["variables"]["searchTerm"], "rick");
        assert_eq!(
            body["extensions"]["persistedQuery"]["sha256Hash"],
            SEARCH_DESKTOP
        );
    }
}

//! The library and the catalogue, read over the endpoints the desktop client
//! uses itself. The public Web API throttles the desktop client id every
//! stored login is bound to, so a token from it gets an instant 429 there.

use std::collections::HashMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use kopuz_plugin_sdk::{Album, ArtistCredit, PlaylistMeta, Result, SourceError, Track, cover};
use librespot_protocol::extended_metadata::{
    BatchedEntityRequest, BatchedExtensionResponse, EntityRequest, ExtensionQuery,
};
use librespot_protocol::extension_kind::ExtensionKind;
use librespot_protocol::metadata::{self, image::Size};
use librespot_protocol::playlist4_external::SelectedListContent;
use protobuf::{EnumOrUnknown, Message as _};

use crate::api::{Api, decode_error};
use crate::ids::{base62_from_gid, gid_from_base62, hex, id_of_uri};

const IMAGE_URL: &str = "https://i.scdn.co/image/";
/// Ids per extended-metadata request. The client sends batches of this
/// order; larger ones start being refused.
const BATCH: usize = 50;
/// Folders count as rootlist items, so a page over-asks a bit.
const ROOTLIST_PAGE: usize = 200;
const ROOTLIST_DECORATE: &str = "revision,attributes,length,owner,capabilities,status_code";
const COLLECTION_V2: &str = "application/vnd.collection-v2.spotify.proto";
/// What the client is served: Ogg Vorbis at 320 kbit/s for a premium account.
const SAMPLE_RATE: u32 = 44100;
const BITRATE_KBPS: u32 = 320;

/// The cheapest authenticated round trip.
pub fn probe(api: &Api) -> Result<()> {
    rootlist(api, 0, 1).map(|_| ())
}

/// Liked tracks, newest first.
pub fn liked_ids(api: &Api) -> Result<Vec<String>> {
    Ok(collection(api)?
        .into_iter()
        .filter(|item| item.kind == CollectionKind::Track)
        .map(|item| item.id)
        .collect())
}

/// Full tracks for `ids`, in the same order, without the ones the service
/// has nothing for.
pub fn tracks(api: &Api, ids: &[String]) -> Result<Vec<Track>> {
    let uris: Vec<String> = ids
        .iter()
        .filter(|id| gid_from_base62(id).is_some())
        .map(|id| format!("spotify:track:{id}"))
        .collect();
    let mut found = extended(api, ExtensionKind::TRACK_V4, &uris)?;
    Ok(uris
        .iter()
        .filter_map(|uri| found.remove(uri))
        .filter_map(|bytes| metadata::Track::parse_from_bytes(&bytes).ok())
        .filter_map(|track| track_from(&track))
        .collect())
}

pub fn track(api: &Api, id: &str) -> Result<Option<Track>> {
    Ok(tracks(api, &[id.to_string()])?.into_iter().next())
}

/// Likes or unlikes one track with the collection's v2 write, which is a
/// delta. The legacy JSON endpoint's `PUT` replaces the whole set.
pub fn set_liked(api: &Api, id: &str, on: bool) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    let update = format!("kopuz-{now}-{:08x}", rand::random::<u32>());
    let body = like_request(api.username()?, id, on, now, &update);
    api.spclient(
        "POST",
        "/collection/v2/write",
        &[("Content-Type", COLLECTION_V2), ("Accept", COLLECTION_V2)],
        Some(body),
    )
    .map(|_| ())
}

/// An album's tracks in disc order.
pub fn album_tracks(api: &Api, album_id: &str) -> Result<Vec<Track>> {
    let uri = format!("spotify:album:{album_id}");
    let bytes = extended(api, ExtensionKind::ALBUM_V4, std::slice::from_ref(&uri))?
        .remove(&uri)
        .ok_or_else(|| SourceError::InvalidInput(format!("Spotify has no album {album_id}")))?;
    let album = metadata::Album::parse_from_bytes(&bytes).map_err(decode_error)?;
    let mut entries = tracks(api, &album_track_ids(&album))?;
    let cover = album_cover(&album);
    for track in &mut entries {
        if track.cover.is_none() {
            track.cover = cover.clone();
        }
        if track.album.is_empty() {
            track.album = album.name().to_string();
            track.album_id = album_id.to_string();
        }
    }
    Ok(entries)
}

/// Saved albums with all their tracks, for the library snapshot.
pub fn saved_albums(api: &Api) -> Result<(Vec<Album>, Vec<Track>)> {
    let uris: Vec<String> = collection(api)?
        .into_iter()
        .filter(|item| item.kind == CollectionKind::Album)
        .map(|item| format!("spotify:album:{}", item.id))
        .collect();
    let mut found = extended(api, ExtensionKind::ALBUM_V4, &uris)?;
    let mut albums = Vec::new();
    let mut all_tracks = Vec::new();
    for uri in &uris {
        let parsed = found
            .remove(uri)
            .and_then(|bytes| metadata::Album::parse_from_bytes(&bytes).ok());
        let Some((message, album)) =
            parsed.and_then(|message| album_from(&message).map(|album| (message, album)))
        else {
            kopuz_plugin_sdk::debug!("spotify saved album unavailable: {uri}");
            continue;
        };
        let mut entries = tracks(api, &album_track_ids(&message))?;
        for track in &mut entries {
            track.album = album.title.clone();
            track.album_id = album.id.clone();
            if track.cover.is_none() {
                track.cover = album.cover.clone();
            }
        }
        all_tracks.extend(entries);
        albums.push(album);
    }
    Ok((albums, all_tracks))
}

/// The account's own and followed playlists, in the client's order.
pub fn playlists(api: &Api) -> Result<Vec<PlaylistMeta>> {
    let mut out = Vec::new();
    let mut from = 0;
    loop {
        let list = rootlist(api, from, ROOTLIST_PAGE)?;
        let read = list.contents.items.len();
        if read == 0 {
            break;
        }
        out.extend(rootlist_playlists(&list));
        from += read;
        if from >= usize::try_from(list.length()).unwrap_or(0) {
            break;
        }
    }
    Ok(out)
}

/// A playlist's tracks in order. Local files and episodes are left out.
pub fn playlist_tracks(api: &Api, playlist_id: &str) -> Result<Vec<Track>> {
    let list: SelectedListContent =
        api.spclient_proto("GET", &format!("/playlist/v2/playlist/{playlist_id}"), None)?;
    tracks(api, &playlist_track_ids(&list))
}

fn rootlist(api: &Api, from: usize, length: usize) -> Result<SelectedListContent> {
    let user = api.username()?;
    api.spclient_proto(
        "GET",
        &format!(
            "/playlist/v2/user/{user}/rootlist?decorate={ROOTLIST_DECORATE}&from={from}&length={length}"
        ),
        None,
    )
}

/// The raw message behind each of `uris`, keyed by URI, asked for in batches.
fn extended(api: &Api, kind: ExtensionKind, uris: &[String]) -> Result<HashMap<String, Vec<u8>>> {
    let mut found = HashMap::with_capacity(uris.len());
    for chunk in uris.chunks(BATCH) {
        let response: BatchedExtensionResponse = api.spclient_proto(
            "POST",
            "/extended-metadata/v0/extended-metadata",
            Some(&batch_request(kind, chunk)),
        )?;
        found.extend(extension_payloads(response));
    }
    Ok(found)
}

fn batch_request(kind: ExtensionKind, uris: &[String]) -> BatchedEntityRequest {
    BatchedEntityRequest {
        entity_request: uris
            .iter()
            .map(|uri| EntityRequest {
                entity_uri: uri.clone(),
                query: vec![ExtensionQuery {
                    extension_kind: EnumOrUnknown::new(kind),
                    ..Default::default()
                }],
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    }
}

fn extension_payloads(response: BatchedExtensionResponse) -> HashMap<String, Vec<u8>> {
    response
        .extended_metadata
        .into_iter()
        .flat_map(|array| array.extension_data)
        .filter_map(|mut data| {
            let payload = data.extension_data.take()?;
            (!payload.value.is_empty()).then_some((data.entity_uri, payload.value))
        })
        .collect()
}

fn image_url(images: &[metadata::Image]) -> Option<String> {
    let best = images
        .iter()
        .find(|image| image.size() == Size::LARGE)
        .or_else(|| images.iter().find(|image| image.size() == Size::DEFAULT))
        .or_else(|| images.first())?;
    let file = best.file_id();
    (!file.is_empty()).then(|| cover::url(&format!("{IMAGE_URL}{}", hex(file))))
}

fn album_cover(album: &metadata::Album) -> Option<String> {
    image_url(&album.cover_group.image).or_else(|| image_url(&album.cover))
}

fn credit(artist: &metadata::Artist) -> Option<ArtistCredit> {
    let name = artist.name();
    if name.is_empty() {
        return None;
    }
    Some(match base62_from_gid(artist.gid()) {
        Some(id) => ArtistCredit::linked(name, id),
        None => ArtistCredit::unlinked(name),
    })
}

fn positive(value: i32) -> Option<u32> {
    u32::try_from(value).ok().filter(|value| *value > 0)
}

/// `None` for a track with no id, which the service returns for removed items.
fn track_from(track: &metadata::Track) -> Option<Track> {
    let item_id = base62_from_gid(track.gid())?;
    let credits: Vec<ArtistCredit> = track.artist.iter().filter_map(credit).collect();
    let artists: Vec<String> = credits.iter().map(|credit| credit.name.clone()).collect();
    let album = track.album.get_or_default();
    Some(Track {
        item_id,
        cover: album_cover(album),
        album_id: base62_from_gid(album.gid()).unwrap_or_default(),
        title: track.name().to_string(),
        artist: artists.first().cloned().unwrap_or_default(),
        album: album.name().to_string(),
        duration_secs: u64::try_from(track.duration()).unwrap_or(0) / 1000,
        sample_rate: SAMPLE_RATE,
        bitrate_kbps: BITRATE_KBPS,
        track_number: positive(track.number()),
        disc_number: positive(track.disc_number()),
        artists,
        credits,
        explicit: track.explicit(),
        ..Track::default()
    })
}

fn album_from(album: &metadata::Album) -> Option<Album> {
    let lead = album.artist.first();
    Some(Album {
        id: base62_from_gid(album.gid())?,
        title: album.name().to_string(),
        artist: lead
            .map(|artist| artist.name().to_string())
            .unwrap_or_default(),
        genre: String::new(),
        year: u16::try_from(album.date.year()).unwrap_or(0),
        cover: album_cover(album),
        artist_id: lead.and_then(|artist| base62_from_gid(artist.gid())),
    })
}

fn album_track_ids(album: &metadata::Album) -> Vec<String> {
    album
        .disc
        .iter()
        .flat_map(|disc| &disc.track)
        .filter_map(|track| base62_from_gid(track.gid()))
        .collect()
}

fn playlist_track_ids(list: &SelectedListContent) -> Vec<String> {
    list.contents
        .items
        .iter()
        .filter_map(|item| id_of_uri(item.uri(), "track"))
        .map(str::to_string)
        .collect()
}

/// Folder markers in the rootlist are skipped. `meta_items` runs beside
/// `items`, one per entry.
fn rootlist_playlists(list: &SelectedListContent) -> Vec<PlaylistMeta> {
    list.contents
        .items
        .iter()
        .enumerate()
        .filter_map(|(index, item)| {
            let id = id_of_uri(item.uri(), "playlist")?;
            let attributes = list
                .contents
                .meta_items
                .get(index)
                .map(|meta| meta.attributes.get_or_default());
            let picture = attributes
                .map(|attributes| attributes.picture())
                .unwrap_or_default();
            Some(PlaylistMeta {
                id: id.to_string(),
                name: attributes
                    .map(|attributes| attributes.name().to_string())
                    .unwrap_or_default(),
                image_tag: (!picture.is_empty())
                    .then(|| cover::url(&format!("{IMAGE_URL}{}", hex(picture)))),
            })
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CollectionItem {
    kind: CollectionKind,
    id: String,
    added_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CollectionKind {
    Track,
    Album,
}

/// The whole collection, newest first. A collection never written to is a
/// 404, which is an empty one.
fn collection(api: &Api) -> Result<Vec<CollectionItem>> {
    let user = api.username()?;
    // Without the `product=0` the client appends elsewhere: with it the
    // collection answers as it would for a free account, which is empty.
    let body = match api.spclient(
        "GET",
        &format!("/collection/collection/{user}?format=json"),
        &[("Accept", "application/json")],
        None,
    ) {
        Ok(body) => body,
        Err(SourceError::Backend(message)) if message.ends_with("HTTP 404") => {
            return Ok(Vec::new());
        }
        Err(error) => return Err(error),
    };
    parse_collection(&body)
}

fn parse_collection(body: &[u8]) -> Result<Vec<CollectionItem>> {
    let json: serde_json::Value = serde_json::from_slice(body).map_err(|error| {
        SourceError::Backend(format!("Spotify's collection could not be read: {error}"))
    })?;
    let mut items: Vec<CollectionItem> = json["item"]
        .as_array()
        .map(|items| items.iter().filter_map(collection_item).collect())
        .unwrap_or_default();
    items.sort_by_key(|item| std::cmp::Reverse(item.added_at));
    Ok(items)
}

fn collection_item(item: &serde_json::Value) -> Option<CollectionItem> {
    let kind = match item["type"].as_str()? {
        "TRACK" => CollectionKind::Track,
        "ALBUM" => CollectionKind::Album,
        _ => return None,
    };
    let gid = STANDARD.decode(item["identifier"].as_str()?).ok()?;
    Some(CollectionItem {
        kind,
        id: base62_from_gid(&gid)?,
        added_at: item["added_at"].as_u64().unwrap_or(0),
    })
}

/// `WriteRequest { username = 1, set = 2, items = 3, client_update_id = 4 }`
/// around one `CollectionItem { uri = 1, added_at = 2, is_removed = 3 }`.
/// The collection protos are not in the protocol crate.
fn like_request(username: &str, id: &str, on: bool, now: u64, update: &str) -> Vec<u8> {
    let mut item = Vec::new();
    proto_string(&mut item, 1, &format!("spotify:track:{id}"));
    proto_varint(&mut item, 2, if on { now } else { 0 });
    proto_varint(&mut item, 3, u64::from(!on));
    let mut body = Vec::new();
    proto_string(&mut body, 1, username);
    proto_string(&mut body, 2, "collection");
    proto_bytes(&mut body, 3, &item);
    proto_string(&mut body, 4, update);
    body
}

fn proto_varint_raw(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn proto_varint(out: &mut Vec<u8>, field: u32, value: u64) {
    proto_varint_raw(out, u64::from(field << 3));
    proto_varint_raw(out, value);
}

fn proto_bytes(out: &mut Vec<u8>, field: u32, bytes: &[u8]) {
    proto_varint_raw(out, u64::from((field << 3) | 2));
    proto_varint_raw(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn proto_string(out: &mut Vec<u8>, field: u32, value: &str) {
    proto_bytes(out, field, value.as_bytes());
}

#[cfg(test)]
mod tests {
    use librespot_protocol::entity_extension_data::EntityExtensionData;
    use librespot_protocol::extended_metadata::EntityExtensionDataArray;
    use librespot_protocol::playlist4_external::{Item, ListAttributes, ListItems, MetaItem};
    use protobuf::well_known_types::any::Any;

    use super::*;

    const TRACK_ID: &str = "4uLU6hMCjMI75M1A2tKUQC";
    const ALBUM_ID: &str = "6eUW0wxWtzkFdaEFsTJto6";
    const ARTIST_ID: &str = "0gxyHStUsqpMadRV0Di1Qt";

    fn gid(id: &str) -> Vec<u8> {
        gid_from_base62(id).expect("an id").to_vec()
    }

    fn image(file: &[u8], size: Size) -> metadata::Image {
        let mut image = metadata::Image::new();
        image.set_file_id(file.to_vec());
        image.set_size(size);
        image
    }

    fn artist(name: &str, id: Option<&str>) -> metadata::Artist {
        let mut artist = metadata::Artist::new();
        artist.set_name(name.into());
        if let Some(id) = id {
            artist.set_gid(gid(id));
        }
        artist
    }

    fn sample_album() -> metadata::Album {
        let mut album = metadata::Album::new();
        album.set_gid(gid(ALBUM_ID));
        album.set_name("Whenever You Need Somebody".into());
        album.artist.push(artist("Rick Astley", Some(ARTIST_ID)));
        album.date.mut_or_insert_default().set_year(1987);
        let group = album.cover_group.mut_or_insert_default();
        group.image.push(image(&[0xaa], Size::SMALL));
        group.image.push(image(&[0xab, 0xcd], Size::LARGE));
        album
    }

    fn sample_track() -> metadata::Track {
        let mut track = metadata::Track::new();
        track.set_gid(gid(TRACK_ID));
        track.set_name("Never Gonna Give You Up".into());
        track.set_duration(213_573);
        track.set_number(1);
        track.set_disc_number(1);
        track.set_explicit(true);
        track.artist.push(artist("Rick Astley", Some(ARTIST_ID)));
        track.artist.push(artist("Uncredited", None));
        track.artist.push(artist("", Some(ARTIST_ID)));
        track.album = protobuf::MessageField::some(sample_album());
        track
    }

    #[test]
    fn a_track_message_becomes_a_wire_track() {
        let track = track_from(&sample_track()).expect("a track");
        assert_eq!(track.item_id, TRACK_ID);
        assert_eq!(track.title, "Never Gonna Give You Up");
        assert_eq!(track.album, "Whenever You Need Somebody");
        assert_eq!(track.album_id, ALBUM_ID);
        assert_eq!(track.artist, "Rick Astley");
        assert_eq!(track.artists, vec!["Rick Astley", "Uncredited"]);
        assert_eq!(
            track.credits,
            vec![
                ArtistCredit::linked("Rick Astley", ARTIST_ID),
                ArtistCredit::unlinked("Uncredited"),
            ]
        );
        assert_eq!(track.duration_secs, 213);
        assert_eq!(track.track_number, Some(1));
        assert_eq!(track.disc_number, Some(1));
        assert!(track.explicit);
        assert_eq!((track.sample_rate, track.bitrate_kbps), (44100, 320));
        assert_eq!(
            track.cover.as_deref(),
            Some("directurl:https://i.scdn.co/image/abcd")
        );
    }

    #[test]
    fn a_removed_track_has_no_id_and_is_dropped() {
        let mut track = sample_track();
        track.clear_gid();
        assert!(track_from(&track).is_none());
    }

    #[test]
    fn zero_numbers_are_unknown() {
        let mut track = sample_track();
        track.set_number(0);
        track.clear_disc_number();
        let track = track_from(&track).expect("a track");
        assert_eq!((track.track_number, track.disc_number), (None, None));
    }

    #[test]
    fn an_album_message_keeps_its_lead_artist_and_year() {
        let album = album_from(&sample_album()).expect("an album");
        assert_eq!(album.id, ALBUM_ID);
        assert_eq!(album.artist, "Rick Astley");
        assert_eq!(album.artist_id.as_deref(), Some(ARTIST_ID));
        assert_eq!(album.year, 1987);
        assert_eq!(
            album.cover.as_deref(),
            Some("directurl:https://i.scdn.co/image/abcd")
        );
    }

    #[test]
    fn a_cover_falls_back_to_the_loose_images() {
        let mut album = sample_album();
        album.cover_group.clear();
        album.cover.push(image(&[0x01], Size::DEFAULT));
        assert_eq!(
            album_cover(&album).as_deref(),
            Some("directurl:https://i.scdn.co/image/01")
        );
        album.cover.clear();
        assert_eq!(album_cover(&album), None);
    }

    #[test]
    fn album_tracks_come_in_disc_order() {
        let mut album = sample_album();
        let ids = [
            "0000000000000000000001",
            "0000000000000000000002",
            "0000000000000000000003",
        ];
        for chunk in [&ids[..2], &ids[2..]] {
            let mut disc = metadata::Disc::new();
            for id in chunk {
                let mut track = metadata::Track::new();
                track.set_gid(gid(id));
                disc.track.push(track);
            }
            album.disc.push(disc);
        }
        assert_eq!(album_track_ids(&album), ids);
    }

    #[test]
    fn extension_payloads_are_keyed_by_uri() {
        let payload = sample_track().write_to_bytes().expect("encodes");
        let mut data = EntityExtensionData::new();
        data.entity_uri = format!("spotify:track:{TRACK_ID}");
        let mut any = Any::new();
        any.value = payload.clone();
        data.extension_data = protobuf::MessageField::some(any);
        let mut empty = EntityExtensionData::new();
        empty.entity_uri = "spotify:track:0000000000000000000000".into();
        let mut array = EntityExtensionDataArray::new();
        array.extension_data.extend([data, empty]);
        let mut response = BatchedExtensionResponse::new();
        response.extended_metadata.push(array);

        let encoded = response.write_to_bytes().expect("encodes");
        let decoded = BatchedExtensionResponse::parse_from_bytes(&encoded).expect("decodes");
        let found = extension_payloads(decoded);
        assert_eq!(found.len(), 1);
        assert_eq!(found[&format!("spotify:track:{TRACK_ID}")], payload);
    }

    #[test]
    fn a_batch_asks_one_extension_per_uri() {
        let uris = vec!["spotify:track:a".to_string(), "spotify:track:b".to_string()];
        let request = batch_request(ExtensionKind::TRACK_V4, &uris);
        assert_eq!(request.entity_request.len(), 2);
        assert_eq!(request.entity_request[1].entity_uri, "spotify:track:b");
        assert_eq!(
            request.entity_request[0].query[0]
                .extension_kind
                .enum_value(),
            Ok(ExtensionKind::TRACK_V4)
        );
    }

    /// An entry's URI, and its name and picture when it has attributes.
    type Entry<'a> = (&'a str, Option<(&'a str, &'a [u8])>);

    fn list(entries: &[Entry]) -> SelectedListContent {
        let mut contents = ListItems::new();
        contents.set_pos(0);
        contents.set_truncated(false);
        for (uri, meta) in entries {
            let mut item = Item::new();
            item.set_uri((*uri).into());
            contents.items.push(item);
            let mut meta_item = MetaItem::new();
            if let Some((name, picture)) = meta {
                let mut attributes = ListAttributes::new();
                attributes.set_name((*name).into());
                attributes.set_picture(picture.to_vec());
                meta_item.attributes = protobuf::MessageField::some(attributes);
            }
            contents.meta_items.push(meta_item);
        }
        let mut list = SelectedListContent::new();
        list.set_length(entries.len() as i32);
        list.contents = protobuf::MessageField::some(contents);
        list
    }

    #[test]
    fn the_rootlist_skips_folders_and_keeps_names_and_pictures() {
        let playlist = "37i9dQZF1DXcBWIGoYBM5M";
        let other = "1111111111111111111111";
        let list = list(&[
            ("spotify:start-group:abc:Folder", None),
            (
                &format!("spotify:playlist:{playlist}"),
                Some(("Hits", &[0x0f, 0xa0])),
            ),
            ("spotify:end-group:abc", None),
            (&format!("spotify:playlist:{other}"), Some(("Mine", &[]))),
        ]);
        let encoded = list.write_to_bytes().expect("encodes");
        let list = SelectedListContent::parse_from_bytes(&encoded).expect("decodes");
        let found = rootlist_playlists(&list);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].id, playlist);
        assert_eq!(found[0].name, "Hits");
        assert_eq!(
            found[0].image_tag.as_deref(),
            Some("directurl:https://i.scdn.co/image/0fa0")
        );
        assert_eq!(found[1].name, "Mine");
        assert_eq!(found[1].image_tag, None);
    }

    #[test]
    fn a_playlist_keeps_only_its_tracks_in_order() {
        let list = list(&[
            ("spotify:track:0000000000000000000002", None),
            ("spotify:local:Artist:Album:Title:180", None),
            ("spotify:episode:0000000000000000000009", None),
            ("spotify:track:0000000000000000000001", None),
        ]);
        assert_eq!(
            playlist_track_ids(&list),
            ["0000000000000000000002", "0000000000000000000001"]
        );
    }

    #[test]
    fn the_collection_is_newest_first_and_skips_other_kinds() {
        let body = serde_json::json!({ "item": [
            { "type": "TRACK", "identifier": "AAAAAAAAAAAAAAAAAAAAAA==", "added_at": 10 },
            { "type": "SHOW", "identifier": "AAAAAAAAAAAAAAAAAAAAAA==", "added_at": 30 },
            { "type": "ALBUM", "identifier": STANDARD.encode(gid(ALBUM_ID)), "added_at": 20 },
            { "type": "TRACK", "identifier": "not base64", "added_at": 40 },
        ] });
        let items = parse_collection(body.to_string().as_bytes()).expect("parses");
        assert_eq!(
            items,
            vec![
                CollectionItem {
                    kind: CollectionKind::Album,
                    id: ALBUM_ID.into(),
                    added_at: 20,
                },
                CollectionItem {
                    kind: CollectionKind::Track,
                    id: "0000000000000000000000".into(),
                    added_at: 10,
                },
            ]
        );
        assert!(parse_collection(b"{}").expect("parses").is_empty());
        assert!(parse_collection(b"not json").is_err());
    }

    #[test]
    fn varints_and_strings_encode_as_protobuf() {
        let mut out = Vec::new();
        proto_string(&mut out, 1, "ab");
        proto_varint(&mut out, 2, 300);
        proto_varint(&mut out, 3, 1);
        assert_eq!(out, vec![0x0a, 2, b'a', b'b', 0x10, 0xac, 0x02, 0x18, 1]);
    }

    #[test]
    fn an_unlike_is_a_removed_item_with_no_timestamp() {
        let body = like_request("me", TRACK_ID, false, 99, "u");
        let mut item = Vec::new();
        proto_string(&mut item, 1, &format!("spotify:track:{TRACK_ID}"));
        proto_varint(&mut item, 2, 0);
        proto_varint(&mut item, 3, 1);
        let mut expected = Vec::new();
        proto_string(&mut expected, 1, "me");
        proto_string(&mut expected, 2, "collection");
        proto_bytes(&mut expected, 3, &item);
        proto_string(&mut expected, 4, "u");
        assert_eq!(body, expected);

        let like = like_request("me", TRACK_ID, true, 99, "u");
        assert!(like.windows(2).any(|pair| pair == [0x10, 99]));
        assert!(like.windows(2).any(|pair| pair == [0x18, 0]));
    }
}

# kopuz-plugin-spotify

A [Kopuz](https://github.com/Kopuz-org/kopuz) plugin that adds Spotify as a
source: your saved albums, liked songs and playlists, and search across the
catalogue. Tracks play in Kopuz's own audio engine, like any other source's.

Playback needs Spotify Premium. Spotify hands the key to a track's audio only
to a Premium session, and a Free account gets a message saying so instead of
audio. The plugin does not download tracks, and Kopuz does not cache them.

## Using it

It needs a Kopuz build with plugin API 0.2. Install **Spotify** from
**Settings → Library → Plugins**, add a source, pick **Spotify** and press
Sign in. Your browser opens Spotify's own sign-in page, and once you approve it
the tab says you can go back to Kopuz. The sign-in listens on
`http://127.0.0.1:8898/login` while it waits, so that port has to be free.

Sync the source to pull in the library. Liked songs sync a page at a time.
Liking and unliking a track in Kopuz is written back to Spotify. Playlists are
read-only.

## How it works

The plugin speaks the protocol of Spotify's desktop client, following
[librespot](https://github.com/librespot-org/librespot).

Sign-in is OAuth with PKCE and a loopback redirect. The token it ends in is
used once, to log in to an access point, which answers with a login that does
not expire. Kopuz stores that login, never your password. The library and
search come from the client's own HTTP API.

A track's audio is an Ogg Vorbis file on Spotify's CDN (MP3 for the few tracks
that have nothing else), encrypted with a key of its own. The plugin asks an
access point for the key over TCP and hands Kopuz the CDN address and the key.
Kopuz fetches the file in ranges and decrypts it as it plays.

It runs in Kopuz's WebAssembly sandbox and may reach `*.spotify.com`,
`*.spotifycdn.com` and `*.scdn.co`, nothing else.

## Building

```sh
rustup target add wasm32-wasip2
cargo test
scripts/package.sh
```

`scripts/package.sh` leaves `dist/kopuz-plugin.toml` and `dist/plugin.wasm`,
the two files a release carries, and prints the listing for
[Kopuz-org/plugins](https://github.com/Kopuz-org/plugins). Pushing a `v*` tag
builds and publishes the release.

One test talks to a real access point and runs only when asked for:

```sh
cargo test -- --ignored access_point
```

To install a local build by hand, copy the two files in `dist/` into
`plugins/spotify/` next to the Kopuz database.

This project is not affiliated with Spotify.

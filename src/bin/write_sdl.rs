//! Prints the federation SDL for the ln-address subgraph to stdout.
//! Used by `make subgraph-generate` / `subgraph-check`.

use async_graphql::SDLExportOptions;

fn main() {
    let schema_sdl = lnurl::graphql::schema::<lnurl::sqlite::LnurlRepository>(None)
        .sdl_with_options(SDLExportOptions::new().federation());

    // Downgrade federation v2.5 -> v2.3 and drop @requiresScopes (v2.5+ only),
    // matching the router's pinned federation version.
    let corrected = schema_sdl
        .replace(
            "https://specs.apollo.dev/federation/v2.5",
            "https://specs.apollo.dev/federation/v2.3",
        )
        .replace(r#", "@requiresScopes""#, "");

    println!("{}", corrected.trim());
}

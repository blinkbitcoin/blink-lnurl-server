//! Federated GraphQL subgraph owning the receive-side convenience operations
//! for Blink lightning addresses (custodial + Spark). Contract mirrors the
//! `blinkbitcoin/blink#767` reference; resolvers call `crate::ln_address`,
//! sharing one owner with the public LNURL routes.

pub mod auth;
mod schema;
pub mod server;

pub use schema::{LnurlSchema, MutationRoot, QueryRoot};

use async_graphql::{EmptySubscription, Schema};
use std::marker::PhantomData;

use crate::state::State;

/// Build the federation-aware schema. `state` is `None` when generating the
/// SDL (no repository available), `Some` when serving requests.
pub fn schema<DB>(state: Option<State<DB>>) -> LnurlSchema<DB>
where
    DB: crate::repository::LnurlRepository
        + crate::webhooks::WebhookRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    let builder = Schema::build(
        QueryRoot::<DB>(PhantomData),
        MutationRoot::<DB>(PhantomData),
        EmptySubscription,
    );
    match state {
        Some(state) => builder.data(state).finish(),
        None => builder.finish(),
    }
}

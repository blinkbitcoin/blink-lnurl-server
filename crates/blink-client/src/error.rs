use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct GraphqlError {
    pub message: String,
}

#[derive(Debug, Error)]
pub enum BlinkClientError {
    #[error("Blink transport failure: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("Blink GraphQL errors: {0:?}")]
    Graphql(Vec<GraphqlError>),
    #[error("Blink malformed response: {0}")]
    MalformedResponse(&'static str),
    #[error("Blink API failure: {0}")]
    ApiFailure(String),
}

//! Shared data-fetching plumbing: a `use_api` hook that runs an async API call,
//! tracks loading/error state, and routes a `401` back to the login view (any
//! unauthorized response clears the token and re-auths).

use std::future::Future;
use std::rc::Rc;

use yew::prelude::*;

use crate::api::{ApiError, ApiResult};
use crate::auth::use_session;

/// The state of an in-flight or completed fetch.
#[derive(Clone, PartialEq)]
pub enum Fetch<T: PartialEq> {
    /// The request is in flight (initial load or a refresh).
    Loading,
    /// The request succeeded with this value.
    Ready(T),
    /// The request failed (non-401; a 401 has already signed the user out).
    Failed(ApiError),
}

/// A handle returned by [`use_api`]: the current [`Fetch`] state plus a
/// `reload` callback to re-run the request (e.g. after a mutation).
#[derive(Clone)]
pub struct FetchHandle<T: PartialEq> {
    /// The current state.
    pub state: Fetch<T>,
    /// Re-run the fetch.
    pub reload: Callback<()>,
}

/// Run an async API call on mount (and on demand via the returned `reload`),
/// applying the `401` interceptor: an [`ApiError::Unauthorized`] signs the
/// session out (which routes back to login) instead of surfacing as an error.
///
/// `make_future` is called with a fresh [`crate::api::ApiClient`] each run, so
/// the closure captures only its inputs (e.g. a site name), not the client.
#[hook]
pub fn use_api<T, F, Fut>(make_future: F) -> FetchHandle<T>
where
    T: PartialEq + Clone + 'static,
    F: Fn(crate::api::ApiClient) -> Fut + 'static,
    Fut: Future<Output = ApiResult<T>> + 'static,
{
    let session = use_session();
    let state = use_state(|| Fetch::Loading);
    // A bump counter: incrementing it re-runs the effect (the reload trigger).
    let nonce = use_state(|| 0u32);
    let make_future = Rc::new(make_future);

    {
        let state = state.clone();
        let session = session.clone();
        let make_future = make_future.clone();
        let nonce_val = *nonce;
        use_effect_with(nonce_val, move |_| {
            state.set(Fetch::Loading);
            let client = session.client();
            let fut = make_future(client);
            wasm_bindgen_futures::spawn_local(async move {
                match fut.await {
                    Ok(value) => state.set(Fetch::Ready(value)),
                    Err(err) if err.is_unauthorized() => session.sign_out(),
                    Err(err) => state.set(Fetch::Failed(err)),
                }
            });
            || ()
        });
    }

    let reload = {
        let nonce = nonce.clone();
        Callback::from(move |_| nonce.set(*nonce + 1))
    };

    FetchHandle {
        state: (*state).clone(),
        reload,
    }
}

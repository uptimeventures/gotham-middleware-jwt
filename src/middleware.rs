// Copyright 2018 Uptime Ventures, Ltd. All rights reserved.
//
// Released under a 3-Clause BSD License. See the LICENSE file
// at the top of this source tree. Alternatively, visit
// https://opensource.org/licenses/BSD-3-Clause to acquire a copy.
use futures::{future, Future};
use gotham::{
    handler::HandlerFuture, helpers::http::response::create_response,
    middleware::{Middleware, NewMiddleware}, state::{request_id, FromState, State},
};
use hyper::{
    header::{Authorization, Bearer, Headers}, StatusCode,
};
use jsonwebtoken::{decode, Validation};
use serde::de::Deserialize;
use std::io;
use std::marker::PhantomData;
use std::panic::RefUnwindSafe;

/// Verifies JSON Web tokens provided via the `Authorization`
/// header, allowing valid requests to pass. Other requests are
/// returned as `StatusCode::Unauthorized`.
pub struct JWTMiddleware<T> {
    secret: &'static str,
    validation: Validation,
    claims: PhantomData<T>,
}

impl<T> JWTMiddleware<T>
where
    T: for<'de> Deserialize<'de> + Send + Sync,
{
    /// Creates a JWTMiddleware instance from the provided secret,
    /// which, by default, uses HS256 as the crypto scheme.
    pub fn new(secret: &'static str) -> Self {
        let validation = Validation::default();

        JWTMiddleware {
            secret,
            validation,
            claims: PhantomData,
        }
    }
}

impl<T> Middleware for JWTMiddleware<T>
where
    T: for<'de> Deserialize<'de> + Send + Sync,
{
    fn call<Chain>(self, state: State, chain: Chain) -> Box<HandlerFuture>
    where
        Chain: FnOnce(State) -> Box<HandlerFuture>,
    {
        trace!("[{}] pre-chain authentication", request_id(&state));
        let token = {
            Headers::borrow_from(&state)
                .get::<Authorization<Bearer>>()
                .map(|a| a.token.to_owned())
                .unwrap_or_else(|| "".to_owned())
        };

        match decode::<T>(&token, self.secret.as_ref(), &self.validation) {
            Ok(_token) => Box::new(chain(state).and_then(|(state, response)| {
                trace!("[{}] post-chain jwt middleware", request_id(&state));
                future::ok((state, response))
            })),
            Err(_) => {
                let res = create_response(&state, StatusCode::Unauthorized, None);
                return Box::new(future::ok((state, res)));
            }
        }
    }
}

impl<T> NewMiddleware for JWTMiddleware<T>
where
    T: for<'de> Deserialize<'de> + RefUnwindSafe + Send + Sync,
{
    type Instance = JWTMiddleware<T>;

    fn new_middleware(&self) -> io::Result<Self::Instance> {
        Ok(JWTMiddleware {
            secret: self.secret.clone(),
            validation: self.validation.clone(),
            claims: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future;
    use gotham::{
        handler::HandlerFuture, pipeline::{new_pipeline, single::*}, router::{builder::*, Router},
        state::State, test::TestServer,
    };
    use hyper::{
        header::{Authorization, Bearer}, StatusCode,
    };

    #[derive(Debug, Deserialize)]
    pub struct Claims {}

    fn handler(state: State) -> Box<HandlerFuture> {
        let res = create_response(&state, StatusCode::Ok, None);
        Box::new(future::ok((state, res)))
    }

    fn router() -> Router {
        let secret = "some-secret".as_ref();

        // Create JWTMiddleware with HS256 algorithm (default).
        let (chain, pipelines) = single_pipeline(
            new_pipeline()
                .add(JWTMiddleware::<Claims>::new(secret))
                .build(),
        );

        build_router(chain, pipelines, |route| {
            route.get("/").to(handler);
        })
    }

    #[test]
    fn jwt_middleware_no_token_test() {
        let test_server = TestServer::new(router()).unwrap();
        let res = test_server
            .client()
            .get("https://example.com")
            .perform()
            .unwrap();

        assert_eq!(res.status(), StatusCode::Unauthorized);
    }

    #[test]
    fn jwt_middleware_malformatted_token_test() {
        let test_server = TestServer::new(router()).unwrap();
        let res = test_server
            .client()
            .get("https://example.com")
            .with_header(Authorization(Bearer {
                token: "xxxx".to_string(),
            }))
            .perform()
            .unwrap();

        assert_eq!(res.status(), StatusCode::Unauthorized);
    }

    #[test]
    fn jwt_middleware_invalid_algorithm_token_test() {
        let test_server = TestServer::new(router()).unwrap();
        let res = test_server
            .client()
            .get("https://example.com")
            .with_header(Authorization(Bearer{token: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE1MzA0MDE1MjcsImlhdCI6MTUzMDM5OTcyN30.lhg7K9SK3DXsvimVb6o_h6VcsINtkT-qHR-tvDH1bGI".to_string()}))
            .perform()
            .unwrap();

        assert_eq!(res.status(), StatusCode::Unauthorized);
    }

    #[test]
    fn jwt_middleware_valid_token_test() {
        let test_server = TestServer::new(router()).unwrap();
        let res = test_server
            .client()
            .get("https://example.com")
            .with_header(Authorization(Bearer{token: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE1MzA4MjcyNjQsImlhdCI6MTUzMDgyNTQ2NCwiaXNzIjoidXB0aW1lLnZlbnR1cmVzIiwic3ViIjoidGVzdEB1cHRpbWUudmVudHVyZXMifQ.PBnfs1fzql53EmywyQzmCHYVr4om9wUqfzRM6uRBtug".to_string()}))
            .perform()
            .unwrap();

        assert_eq!(res.status(), StatusCode::Ok);
    }
}

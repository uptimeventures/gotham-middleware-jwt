// Copyright 2018 Uptime Ventures, Ltd. All rights reserved.
//
// Released under a 3-Clause BSD License. See the LICENSE file
// at the top of this source tree. Alternatively, visit
// https://opensource.org/licenses/BSD-3-Clause to acquire a copy.

//! Verifies JSON Web Tokens provided via the `Authorization`
//! header, allowing valid requests to pass through with the token
//! data stored in `State`. Requests that lack a token or fail
//! validation are returned as `StatusCode::Unauthorized`.
#![warn(missing_docs, deprecated)]
extern crate futures;
extern crate gotham;
#[macro_use]
extern crate gotham_derive;
extern crate hyper;
extern crate jsonwebtoken;
extern crate serde;
#[macro_use]
extern crate log;
#[cfg(test)]
#[macro_use]
extern crate serde_derive;

mod middleware;
mod state_data;

pub use middleware::JWTMiddleware;
pub use state_data::AuthorizationToken;

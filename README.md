# JWT Authentication Middleware

[![GitLab CI Pipeline Status](https://gitlab.com/uptimeventures/gotham-middleware-jwt/badges/master/pipeline.svg)](https://gitlab.com/uptimeventures/gotham-middleware-jwt/commits/master)
[![BSD 3-Clause
License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://spdx.org/licenses/BSD-3-Clause.html)
[![Dependency Status](https://deps.rs/repo/gitlab/uptimeventures/gotham-middleware-jwt/status.svg)](https://deps.rs/repo/gitlab/uptimeventures/gotham-middleware-jwt)
[![Made by Uptime
Ventures](https://img.shields.io/badge/made_by-Uptime_Ventures-fcb040.svg)](https://www.uptime.ventures)

A middleware for the [Gotham][gotham] Web Framework that verifies JSON
Web Tokens, returning `StatusCode::UNAUTHORIZED` if a request fails
validation.

## Usage

First, ensure you're using at least Gotham version `0.3`. Then, add the
following to your `Cargo.toml`: `gotham_middleware_jwt = "0.2"`.

Second, create a struct you wish to deserialize into. For our example below,
we've used `Claims`:

```rust
extern crate gotham;
extern crate gotham_middleware_jwt;
extern crate hyper;
extern crate serde;
#[macro_use]
extern crate serde_derive;

use gotham::{
    helpers::http::response::create_response,
    pipeline::{
        new_pipeline, set::{finalize_pipeline_set, new_pipeline_set},
    },
    router::{builder::*, Router}, state::State,
};
use gotham_middleware_jwt::{JWTMiddleware, AuthorizationToken};
use hyper::{Response, StatusCode};

#[derive(Deserialize, Serialize, Debug)]
pub struct Claims {
  sub: String,
  exp: usize,
}

fn handler(state: State) -> (State, Response) {
    {
        let auth = AuthorizationToken::<Claims>::borrow_from(&state);
        // auth.token -> TokenData
    }
    let res = create_empty_response(&state, StatusCode::OK);
    (state, res)
}

fn router() -> Router {
    let pipelines = new_pipeline_set();
    let (pipelines, defaults) = pipelines.add(
        new_pipeline()
            .add(JWTMiddleware::<Claims>::new("secret".as_ref()))
            .build(),
    );
    let default_chain = (defaults, ());
    let pipeline_set = finalize_pipeline_set(pipelines);
    build_router(default_chain, pipeline_set, |route| {
        route.get("/").to(handler)
    })
}
```

## Contributing

We (Uptime Ventures) welcome contributions from all. Take a look at the
[Contributing Guide](CONTRIBUTING.md) to get started. If you're comfortable
working on GitHub (where this project is mirrored), contribute there. Otherwise,
primary development happens on
[GitLab](https://gitlab.com/uptimeventures/gotham-middleware-jwt).

## License

Copyright 2018 Uptime Ventures, Ltd. All rights reserved. Released under a
[3-Clause BSD License][license].

[gotham]: https://gotham.rs
[license]: LICENSE

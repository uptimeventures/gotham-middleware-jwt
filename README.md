# gotham-middleware-jwt

A middleware for the [Gotham][gotham] Web Framework that verifies JSON
Web Tokens, returning `StatusCode::Unauthorized` if a request fails
validation.

**Compatibility Note:** This library currently uses Gotham 0.3 features, which
require building from `master`.

## Usage

First, add `gotham_middleware_jwt = "0.1"` to `Cargo.toml`.

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
use gotham_middleware_jwt::JWTMiddleware;
use hyper::{Response, StatusCode};

#[derive(Deserialize, Serialize, Debug)]
pub struct Claims {}

fn handler(state: State) -> (State, Response) {
    let res = create_response(&state, StatusCode::Ok, None);
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

## License

Copyright 2018 Uptime Ventures, Ltd. All rights reserved. Released under a
[3-Clause BSD License][license].

[gotham]: https://gotham.rs
[license]: LICENSE

# JWT Authentication Middleware

[![Made by Uptime
Ventures](https://img.shields.io/badge/made_by-Uptime_Ventures-fcb040.svg)](https://www.uptime.ventures)

**Note:** This middleware is now developed in the [Gotham repository][gotham].
Please submit PRs and support requests there.

---

A middleware for the [Gotham][gotham] Web Framework that verifies JSON
Web Tokens, returning `StatusCode::UNAUTHORIZED` if a request fails
validation.

## Usage

First, ensure you're using at least Gotham version `0.3`. Then, add the
following to your `Cargo.toml`: `gotham_middleware_jwt = "0.3"`.

Second, create a struct you wish to deserialize into. For our example below,
we've used `Claims`:

```rust
extern crate futures;
extern crate gotham;
extern crate gotham_middleware_jwt;
extern crate hyper;
extern crate serde;
#[macro_use]
extern crate serde_derive;

use futures::future;
use gotham::{
  helpers::http::response::create_empty_response,
  handler::HandlerFuture,
  pipeline::{
    new_pipeline,
    set::{finalize_pipeline_set, new_pipeline_set},
  },
  router::{builder::*, Router},
  state::{State, FromState},
};
use gotham_middleware_jwt::{JWTMiddleware, AuthorizationToken};
use hyper::{Response, StatusCode};

#[derive(Deserialize, Debug)]
struct Claims {
  sub: String,
  exp: usize,
}

fn handler(state: State) -> Box<HandlerFuture> {
  {
    let token = AuthorizationToken::<Claims>::borrow_from(&state);
    // token -> TokenData
  }
  let res = create_empty_response(&state, StatusCode::OK);
  Box::new(future::ok((state, res)))
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
    route.get("/").to(handler);
  })
}
```

[gotham]: https://gotham.rs

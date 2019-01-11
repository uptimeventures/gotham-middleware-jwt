// Copyright 2018 Uptime Ventures, Ltd. All rights reserved.
//
// Released under a 3-Clause BSD License. See the LICENSE file
// at the top of this source tree. Alternatively, visit
// https://opensource.org/licenses/BSD-3-Clause to acquire a copy.
pub use jsonwebtoken::TokenData;

/// Struct to contain the JSON Web Token on a per-request basis.
#[derive(StateData, Debug)]
pub struct AuthorizationToken<T: Send + 'static>(pub TokenData<T>);

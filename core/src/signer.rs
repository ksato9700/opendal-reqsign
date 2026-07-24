// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

use crate::Context;
use crate::Error;
use crate::ProvideCredential;
use crate::ProvideCredentialDyn;
use crate::Result;
use crate::SignRequest;
use crate::SignRequestDyn;
use crate::SigningCredential;
use crate::time::Timestamp;
use futures::lock::Mutex;
use std::any::type_name;
use std::sync::Arc;
use std::time::Duration;

/// Loads credentials and atomically signs request heads.
///
/// The service-specific [`SignRequest`] runs against a private candidate. Only the
/// candidate URI and headers are committed after successful signing.
#[derive(Clone, Debug)]
pub struct Signer<K: SigningCredential> {
    ctx: Context,
    loader: Arc<dyn ProvideCredentialDyn<Credential = K>>,
    builder: Arc<dyn SignRequestDyn<Credential = K>>,
    credential: Arc<Mutex<Option<K>>>,
}

impl<K: SigningCredential> Signer<K> {
    /// Create a new signer.
    pub fn new(
        ctx: Context,
        loader: impl ProvideCredential<Credential = K>,
        builder: impl SignRequest<Credential = K>,
    ) -> Self {
        Self {
            ctx,

            loader: Arc::new(loader),
            builder: Arc::new(builder),
            credential: Arc::new(Mutex::new(None)),
        }
    }

    /// Replace the context while keeping credential provider and request signer.
    pub fn with_context(mut self, ctx: Context) -> Self {
        self.ctx = ctx;
        self
    }

    /// Replace the credential provider while keeping context and request signer.
    pub fn with_credential_provider(
        mut self,
        provider: impl ProvideCredential<Credential = K>,
    ) -> Self {
        self.loader = Arc::new(provider);
        self.credential = Arc::new(Mutex::new(None)); // Clear cached credential
        self
    }

    /// Replace the request signer while keeping context and credential provider.
    pub fn with_request_signer(mut self, signer: impl SignRequest<Credential = K>) -> Self {
        self.builder = Arc::new(signer);
        self
    }

    /// Sign a wire-ready request head.
    ///
    /// The request URI must satisfy the input contract of the configured
    /// [`SignRequest`]. Built-in signers require an authority and expect path and query
    /// data to be percent-encoded exactly once before this call. Signing does not
    /// perform general-purpose URI encoding for the caller.
    ///
    /// If credential loading or request signing returns an error, `req` is unchanged.
    /// On success, only `req.uri` and `req.headers` may change; the method, version, and
    /// extensions retain their input values.
    ///
    /// `expires_in` is a service-specific validity input and does not universally
    /// select query authentication. The configured service signer and credential type
    /// determine how it is interpreted.
    pub async fn sign(
        &self,
        req: &mut http::request::Parts,
        expires_in: Option<Duration>,
    ) -> Result<()> {
        // Held across the fetch below so concurrent callers serialize onto a single
        // refresh instead of each independently hitting the credential provider: a
        // waiter that acquires this lock after a refresh re-checks validity first and
        // finds the credential the winning caller just stored.
        let mut guard = self.credential.lock().await;
        let credential = if guard.is_valid()
            && expires_in.is_none_or(|d| guard.is_valid_at(Timestamp::now() + d))
        {
            guard.clone()
        } else {
            // Debugging aid: logs which underlying credential cell is fetching, so concurrent
            // fetches around a rate-limit error can be told apart (same cell repeated => truly
            // serialized through one Signer; different pointers => multiple Signer instances,
            // each with their own independent cache, not actually sharing single-flight
            // protection). Not for production use -- remove once the investigation concludes.
            log::info!(
                "reqsign-core: signer credential-cell {:p} fetching fresh credential",
                Arc::as_ptr(&self.credential)
            );
            let ctx = self.loader.provide_credential_dyn(&self.ctx).await?;
            *guard = ctx.clone();
            ctx
        };
        drop(guard);

        let credential_ref = credential.as_ref().ok_or_else(|| {
            Error::credential_invalid("failed to load signing credential")
                .with_context(format!("credential_type: {}", type_name::<K>()))
        })?;

        let mut candidate = req.clone();
        self.builder
            .sign_request_dyn(&self.ctx, &mut candidate, Some(credential_ref), expires_in)
            .await?;

        req.uri = candidate.uri;
        req.headers = candidate.headers;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProvideCredential, SignRequest};
    use http::{HeaderValue, Method, Request, Version};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[derive(Clone, Debug)]
    struct TestCredential;

    impl SigningCredential for TestCredential {
        fn is_valid(&self) -> bool {
            true
        }
    }

    #[derive(Debug)]
    struct StaticProvider;

    impl ProvideCredential for StaticProvider {
        type Credential = TestCredential;

        async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
            Ok(Some(TestCredential))
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Extension(&'static str);

    #[derive(Debug)]
    struct MutatingSigner {
        fail: bool,
    }

    impl SignRequest for MutatingSigner {
        type Credential = TestCredential;

        async fn sign_request(
            &self,
            _ctx: &Context,
            req: &mut http::request::Parts,
            _credential: Option<&Self::Credential>,
            _expires_in: Option<Duration>,
        ) -> Result<()> {
            req.method = Method::POST;
            req.uri = "https://signed.example.com/result?auth=1"
                .parse()
                .expect("URI must parse");
            req.version = Version::HTTP_2;
            req.headers.clear();
            req.headers
                .insert("authorization", HeaderValue::from_static("signed"));
            req.extensions.insert(Extension("candidate"));

            if self.fail {
                Err(Error::unexpected("injected signing failure"))
            } else {
                Ok(())
            }
        }
    }

    fn request_parts() -> http::request::Parts {
        let mut parts = Request::get("https://example.com/original?x=%2F")
            .version(Version::HTTP_11)
            .header("x-original", "value")
            .body(())
            .expect("request must build")
            .into_parts()
            .0;
        parts.extensions.insert(Extension("caller"));
        parts
    }

    #[test]
    fn failure_leaves_entire_request_head_unchanged() {
        let signer = Signer::new(
            Context::new(),
            StaticProvider,
            MutatingSigner { fail: true },
        );
        let mut parts = request_parts();
        let original = parts.clone();

        let result = futures::executor::block_on(signer.sign(&mut parts, None));

        assert!(result.is_err());
        assert_eq!(parts.method, original.method);
        assert_eq!(parts.uri, original.uri);
        assert_eq!(parts.version, original.version);
        assert_eq!(parts.headers, original.headers);
        assert_eq!(
            parts.extensions.get::<Extension>(),
            original.extensions.get::<Extension>()
        );
    }

    #[test]
    fn success_commits_only_uri_and_headers() {
        let signer = Signer::new(
            Context::new(),
            StaticProvider,
            MutatingSigner { fail: false },
        );
        let mut parts = request_parts();
        let original = parts.clone();

        futures::executor::block_on(signer.sign(&mut parts, None)).expect("signing must succeed");

        assert_eq!(parts.method, original.method);
        assert_eq!(parts.version, original.version);
        assert_eq!(
            parts.extensions.get::<Extension>(),
            original.extensions.get::<Extension>()
        );
        assert_eq!(
            parts.uri,
            "https://signed.example.com/result?auth=1"
                .parse::<http::Uri>()
                .expect("URI must parse")
        );
        assert_eq!(
            parts.headers.get("authorization"),
            Some(&HeaderValue::from_static("signed"))
        );
        assert!(!parts.headers.contains_key("x-original"));
    }

    #[derive(Clone, Debug)]
    struct FlaggedCredential {
        valid: Arc<AtomicBool>,
    }

    impl SigningCredential for FlaggedCredential {
        fn is_valid(&self) -> bool {
            self.valid.load(Ordering::SeqCst)
        }
    }

    /// Counts every call it receives and hands out a credential backed by the same
    /// shared `valid` flag every time, so a test can flip that flag to simulate the
    /// cached credential expiring without needing to reach into the signer's cache.
    #[derive(Debug)]
    struct CountingProvider {
        calls: Arc<AtomicUsize>,
        delay: Duration,
        valid: Arc<AtomicBool>,
    }

    impl ProvideCredential for CountingProvider {
        type Credential = FlaggedCredential;

        async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            self.valid.store(true, Ordering::SeqCst);
            Ok(Some(FlaggedCredential {
                valid: self.valid.clone(),
            }))
        }
    }

    #[derive(Debug)]
    struct NoopSigner;

    impl SignRequest for NoopSigner {
        type Credential = FlaggedCredential;

        async fn sign_request(
            &self,
            _ctx: &Context,
            _req: &mut http::request::Parts,
            _credential: Option<&Self::Credential>,
            _expires_in: Option<Duration>,
        ) -> Result<()> {
            Ok(())
        }
    }

    /// Fires `n` concurrent `sign()` calls against `signer` on real OS threads and
    /// waits for all of them to succeed.
    async fn sign_concurrently(signer: &Arc<Signer<FlaggedCredential>>, n: usize) {
        let handles: Vec<_> = (0..n)
            .map(|_| {
                let signer = signer.clone();
                tokio::spawn(async move {
                    let mut parts = request_parts();
                    signer.sign(&mut parts, None).await
                })
            })
            .collect();

        for handle in handles {
            handle
                .await
                .expect("signing task must not panic")
                .expect("signing must succeed");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_callers_with_no_cached_credential_single_flight_the_refresh() {
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = CountingProvider {
            calls: calls.clone(),
            delay: Duration::from_millis(20),
            valid: Arc::new(AtomicBool::new(false)),
        };
        let signer = Arc::new(Signer::new(Context::new(), provider, NoopSigner));

        sign_concurrently(&signer, 8).await;

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "8 concurrent callers racing an empty credential cache must trigger exactly one fetch"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_callers_after_credential_expiry_single_flight_the_refresh() {
        let calls = Arc::new(AtomicUsize::new(0));
        let valid = Arc::new(AtomicBool::new(false));
        let provider = CountingProvider {
            calls: calls.clone(),
            delay: Duration::from_millis(20),
            valid: valid.clone(),
        };
        let signer = Arc::new(Signer::new(Context::new(), provider, NoopSigner));

        // Warm the cache with a single call, then simulate the cached credential
        // expiring (e.g. its TTL lapsing) before hitting it with concurrent callers.
        sign_concurrently(&signer, 1).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        valid.store(false, Ordering::SeqCst);

        sign_concurrently(&signer, 8).await;

        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "8 concurrent callers racing an expired credential must trigger exactly one more fetch"
        );
    }
}

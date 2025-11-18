// backend/src/compute/mod.rs

use crate::models::{Session, SessionRequest};

pub mod local_provider;

#[async_trait::async_trait]
pub trait ComputeProvider: Send + Sync + std::fmt::Debug {
    fn id(&self) -> &'static str;

    async fn start_session(
        &self,
        session: &mut Session,
        request: &SessionRequest,
    ) -> anyhow::Result<()>;

    async fn terminate_session(
        &self,
        session: &Session,
    ) -> anyhow::Result<()>;
}

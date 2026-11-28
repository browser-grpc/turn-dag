//! Embedded grpc-dc Echo service (generated pb/stub copied from
//! browser-grpc/grpc-over-datachannels, Apache-2.0; see vendor/).
//! Served over the grpc-dc rendezvous listener by `serve-grpc`.

#[allow(warnings)]
#[path = "echo_gen/echo_pb.rs"]
pub mod pb;
#[allow(warnings)]
#[path = "echo_gen/pb_message_impl.rs"]
mod pb_message_impl;
#[allow(warnings)]
#[path = "echo_gen/echo_grpc_dc.rs"]
pub mod stub;

use futures_util::StreamExt;
use grpc_dc::{CallCtx, RequestStream, ResponseStream, Status};
use stub::Echo;

pub struct EchoService;

#[grpc_dc::async_trait]
impl Echo for EchoService {
    async fn unary(&self, req: pb::EchoRequest, _ctx: CallCtx) -> Result<pb::EchoResponse, Status> {
        Ok(pb::EchoResponse {
            message: format!("echo: {}", req.message),
            index: 0,
            ..Default::default()
        })
    }
    async fn server_stream(
        &self,
        req: pb::EchoRequest,
        _ctx: CallCtx,
    ) -> Result<ResponseStream<pb::EchoResponse>, Status> {
        let responses = (0..req.count.max(0)).map(move |i| {
            Ok(pb::EchoResponse {
                message: req.message.clone(),
                index: i,
                ..Default::default()
            })
        });
        Ok(Box::pin(futures_util::stream::iter(responses)))
    }
    async fn client_stream(
        &self,
        mut reqs: RequestStream<pb::EchoRequest>,
        _ctx: CallCtx,
    ) -> Result<pb::EchoResponse, Status> {
        let mut parts = Vec::new();
        while let Some(req) = reqs.next().await {
            parts.push(req?.message);
        }
        Ok(pb::EchoResponse {
            message: parts.join("+"),
            index: parts.len() as i32,
            ..Default::default()
        })
    }
    async fn bidi(
        &self,
        reqs: RequestStream<pb::EchoRequest>,
        _ctx: CallCtx,
    ) -> Result<ResponseStream<pb::EchoResponse>, Status> {
        let stream = futures_util::stream::unfold((reqs, 0i32), |(mut reqs, mut i)| async move {
            match reqs.next().await {
                Some(Ok(req)) => {
                    let r = pb::EchoResponse {
                        message: req.message,
                        index: i,
                        ..Default::default()
                    };
                    i += 1;
                    Some((Ok(r), (reqs, i)))
                }
                Some(Err(e)) => Some((Err(e), (reqs, i))),
                None => None,
            }
        });
        Ok(Box::pin(stream))
    }
}

pub fn echo_services() -> Vec<grpc_dc::ServiceDef> {
    vec![stub::echo_service(std::sync::Arc::new(EchoService))]
}

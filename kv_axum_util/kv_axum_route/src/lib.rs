use axum::{Router, routing::MethodRouter};
pub use inventory;

#[derive(Clone)]
pub struct RouteEntry {
    pub path: &'static str,
    pub method_router: MethodRouter,
}

// 路由注册项
inventory::collect!(RouteEntry);

pub fn build_router() -> Router {
    let mut router = Router::new();

    for entry in inventory::iter::<RouteEntry> {
        router = router.route(entry.path, entry.method_router.clone());
    }

    router
}

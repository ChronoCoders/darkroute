//! Outbound relay-to-relay connection pool.
//!
//! ARCHITECTURE.md §5.5 mandates: `Mutex<HashMap<...>>` with short
//! critical sections; the mutex is acquired only long enough to take or
//! return a connection handle, NEVER held across any I/O await. Dead
//! connections are evicted by an age-based sweep and re-dialed on demand.
//!
//! The pool is a registry of outbound TCP streams from this relay to
//! its peer relays (guard → middle, middle → exit). Each entry carries
//! the peer's address and a last-used timestamp; the link is otherwise
//! treated as opaque bytes (the inner AES-GCM frames are keyed by the
//! client-relay handshake, not the link).
//!
//! Phase 4b semantics:
//!   * `acquire(addr)` removes a connection from the pool if one is
//!     idle; otherwise returns `None` so the caller dials fresh.
//!   * `release(addr, conn)` returns a usable connection to the pool.
//!   * `evict_older_than(ttl)` drops entries idle for longer than `ttl`;
//!     run periodically from a sweep task so dead/stale connections do
//!     not accumulate.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct PooledConn<S> {
    pub stream: S,
    last_used: Instant,
}

impl<S> PooledConn<S> {
    /// Wrap a freshly handshaked stream for storage in the pool.
    /// Production callers create these when releasing an outbound
    /// stream at the end of a circuit; the stream is in the
    /// "between-circuits" protocol state (the listener side is blocked
    /// reading the next CIRCUIT_START signal byte).
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            last_used: Instant::now(),
        }
    }

    fn idle_for(&self) -> Duration {
        Instant::now().duration_since(self.last_used)
    }
}

pub struct ConnectionPool<S> {
    inner: Mutex<HashMap<SocketAddr, Vec<PooledConn<S>>>>,
}

impl<S> ConnectionPool<S> {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Remove and return one idle connection to `addr`, if any. The
    /// mutex is held only for the duration of the map lookup; no I/O
    /// happens while locked.
    pub fn acquire(&self, addr: &SocketAddr) -> Option<PooledConn<S>> {
        let mut guard = self.inner.lock().expect("connection pool mutex poisoned");
        let bucket = guard.get_mut(addr)?;
        let conn = bucket.pop();
        if bucket.is_empty() {
            guard.remove(addr);
        }
        conn
    }

    /// Return a connection to the pool for future reuse. After Phase
    /// 4c's CIRCUIT_START signal protocol, an outbound stream is in
    /// the "listener waiting for next pk" state at circuit end and is
    /// safe to hand back. The next `acquire` will write a fresh
    /// CIRCUIT_START + client pubkey to reuse this stream.
    pub fn release(&self, addr: SocketAddr, mut conn: PooledConn<S>) {
        conn.last_used = Instant::now();
        let mut guard = self.inner.lock().expect("connection pool mutex poisoned");
        guard.entry(addr).or_default().push(conn);
    }

    /// Drop any pooled connection that has been idle for longer than
    /// `ttl`. Returns the number of evicted entries so a metric or log
    /// can record the sweep.
    pub fn evict_older_than(&self, ttl: Duration) -> usize {
        let mut guard = self.inner.lock().expect("connection pool mutex poisoned");
        let mut evicted = 0usize;
        let mut empty_addrs: Vec<SocketAddr> = Vec::new();
        for (addr, bucket) in guard.iter_mut() {
            let before = bucket.len();
            bucket.retain(|c| c.idle_for() < ttl);
            evicted += before - bucket.len();
            if bucket.is_empty() {
                empty_addrs.push(*addr);
            }
        }
        for a in empty_addrs {
            guard.remove(&a);
        }
        evicted
    }

    /// Total number of pooled connections across all addresses.
    pub fn len(&self) -> usize {
        let guard = self.inner.lock().expect("connection pool mutex poisoned");
        guard.values().map(|v| v.len()).sum()
    }

    /// Convenience around `len()` — used by tests and by the pool-
    /// sweep log to skip noisy "0 evicted" messages when nothing was
    /// pooled to begin with.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<S> Default for ConnectionPool<S> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    /// Bind a local listener so we can produce a real TcpStream pair
    /// for testing pool operations; the streams are owned by the pool
    /// and never written to, but they exercise the real type.
    async fn local_stream() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (server_side, _) = listener.accept().await.unwrap();
        let client_side = connect.await.unwrap();
        (client_side, server_side)
    }

    #[tokio::test]
    async fn acquire_empty_returns_none() {
        let pool: ConnectionPool<TcpStream> = ConnectionPool::new();
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert!(pool.acquire(&addr).is_none());
        assert!(pool.is_empty());
    }

    #[tokio::test]
    async fn release_then_acquire_round_trip() {
        let pool: ConnectionPool<TcpStream> = ConnectionPool::new();
        let (a, _b) = local_stream().await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        pool.release(addr, PooledConn::new(a));
        assert_eq!(pool.len(), 1);
        let got = pool.acquire(&addr).expect("released connection");
        let _ = got;
        assert!(pool.is_empty());
    }

    #[tokio::test]
    async fn evict_drops_stale_entries() {
        let pool: ConnectionPool<TcpStream> = ConnectionPool::new();
        let (a, _b) = local_stream().await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        pool.release(addr, PooledConn::new(a));
        // Sleep just past the eviction threshold.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let evicted = pool.evict_older_than(Duration::from_millis(10));
        assert_eq!(evicted, 1);
        assert!(pool.is_empty());
    }

    #[tokio::test]
    async fn evict_keeps_fresh_entries() {
        let pool: ConnectionPool<TcpStream> = ConnectionPool::new();
        let (a, _b) = local_stream().await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        pool.release(addr, PooledConn::new(a));
        let evicted = pool.evict_older_than(Duration::from_secs(60));
        assert_eq!(evicted, 0);
        assert_eq!(pool.len(), 1);
    }

    #[tokio::test]
    async fn acquire_returns_lifo() {
        let pool: ConnectionPool<TcpStream> = ConnectionPool::new();
        let (a, _b) = local_stream().await;
        let (c, _d) = local_stream().await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let a_peer = a.peer_addr().unwrap();
        let c_peer = c.peer_addr().unwrap();
        pool.release(addr, PooledConn::new(a));
        pool.release(addr, PooledConn::new(c));
        let first = pool.acquire(&addr).unwrap();
        assert_eq!(first.stream.peer_addr().unwrap(), c_peer);
        let second = pool.acquire(&addr).unwrap();
        assert_eq!(second.stream.peer_addr().unwrap(), a_peer);
        assert!(pool.acquire(&addr).is_none());
    }
}

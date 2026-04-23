//! json 格式化时使用自定义的write, 分块格式化并提交

use std::{
    collections::VecDeque,
    io::Write,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use futures::stream::Stream;
use serde::Serialize;

use crate::if_else;

// 固定缓冲区大小：1024 字节
const CHUNK_SIZE: usize = 1024;

// ============ 真正的流式写入器 ============

// 自定义写入器，每次写满 1024 字节就生成一个块
struct ChunkWriter {
    current_chunk: BytesMut,
    completed_chunks: VecDeque<Bytes>,
}

impl ChunkWriter {
    fn new() -> Self {
        Self {
            current_chunk: BytesMut::with_capacity(CHUNK_SIZE),
            completed_chunks: VecDeque::new(),
        }
    }

    // 获取当前未完成的块（用于最后提交）
    fn finish(mut self) -> VecDeque<Bytes> {
        if !self.current_chunk.is_empty() {
            let bytes = self.current_chunk.freeze();
            self.completed_chunks.push_back(bytes);
        }
        self.completed_chunks
    }
}

impl Write for ChunkWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut remaining = buf;
        let mut written = 0;

        while !remaining.is_empty() {
            let space_left = CHUNK_SIZE - self.current_chunk.len();

            // 如果当前块已满，提交并创建新块
            if space_left == 0 {
                let mut new_chunk = BytesMut::with_capacity(CHUNK_SIZE);
                // 交换后, new_chunk 变成 self.current_chunk
                std::mem::swap(&mut self.current_chunk, &mut new_chunk);
                self.completed_chunks.push_back(new_chunk.freeze());
                continue;
            }

            let to_copy = remaining.len().min(space_left);
            self.current_chunk.extend_from_slice(&remaining[..to_copy]);
            remaining = &remaining[to_copy..];
            written += to_copy;
        }

        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // 不自动提交，保持当前块状态
        Ok(())
    }
}

// 流式序列化器
pub struct JsonStream {
    chunks: VecDeque<Bytes>,
}

impl JsonStream {
    pub fn new<T: Serialize>(result: T) -> Self {
        let mut chunk_writer = ChunkWriter::new();

        // 使用流式序列化，直接写入到 ChunkWriter
        {
            let mut serializer = serde_json::Serializer::new(&mut chunk_writer);
            // 序列化时，数据会通过 chunk_writer 自动分块
            result.serialize(&mut serializer).expect("Serialization failed");
        }

        // 获取所有块
        let chunks = chunk_writer.finish();

        // 如果没有生成任何块（空数据），创建一个空块
        let chunks = if_else!(chunks.is_empty(), VecDeque::new(), chunks);

        Self { chunks }
    }
}

impl Stream for JsonStream {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(chunk) = self.chunks.pop_front() {
            Poll::Ready(Some(Ok(chunk)))
        } else {
            Poll::Ready(None)
        }
    }
}

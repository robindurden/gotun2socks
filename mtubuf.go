package gotun2socks

// mtubuf.go 提供固定 MTU 大小的字节池，尽量复用内存。

import (
	"sync"
)

var (
	// bufPool 复用 MTU 大小的缓冲区，避免频繁分配。
	bufPool *sync.Pool = &sync.Pool{
		New: func() interface{} {
			return make([]byte, MTU)
		},
	}
)

// newBuffer 从池中取缓冲区。
func newBuffer() []byte {
	return bufPool.Get().([]byte)
}

// releaseBuffer 将缓冲区放回池中。
func releaseBuffer(buf []byte) {
	bufPool.Put(buf)
}

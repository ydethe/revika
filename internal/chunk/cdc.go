package chunk

import (
    "fmt"
    "io"
    "iter"
)

// Default CDC parameters. Target is a power of two so the bit-mask trick works.
const (
    DefaultCDCTarget = DefaultSize     // 4 MiB average chunk
    DefaultCDCMin    = DefaultSize / 4 // 1 MiB minimum
    DefaultCDCMax    = DefaultSize * 4 // 16 MiB maximum
)

// gearTable is a precomputed 256-entry array of random uint64 values used by
// the gear-hash rolling function. Values are fixed constants so that the same
// byte sequence always produces the same chunk boundaries on any platform and
// build (determinism is required for dedup: different boundaries → different
// shard IDs, defeating the purpose).
var gearTable = [256]uint64{
    0x9f34e5c3c0f16e4a, 0x6a7b1d2e39f8c420, 0x3b8e2f1a7c4d9056, 0xd1c4a8e5b2730f91,
    0x47f3d0629a8e1c5b, 0x8c1e6b3f4a920d7e, 0xe2a50d7819c634bf, 0x5d9f324e6b801ac7,
    0xb4e71c8a3f0d5296, 0x29c068d51e4b9f73, 0x7f3a94b2c0851e6d, 0xc8d31f7a640e92b5,
    0x1a6e8b4f3c9d0257, 0xf0824c1d9e3b6a78, 0x63b9e5d2471a8c0f, 0xa5071c3e6b924df8,
    0x4c3f8a0d21e96b57, 0x8b14d63c7f0e5a29, 0xe94a2f810c736d4b, 0x261d5c9e4a807f38,
    0x7038bc4d1e6a2951, 0xd56f193a80c4e72b, 0x4b827e0d39f15c6a, 0x9c0e61db2a845f37,
    0x53d1f4820e9b7c16, 0xb7e80a3c64952d1f, 0x2a6c197f4d031be8, 0x8e3541b0c762d9f4,
    0x167f9d4a3c810e2b, 0xf48c3256b09d7e14, 0x65b01d8a3942fc7e, 0xab7c5e1628034d9f,
    0x3980b2fd14c76e5a, 0xd0c5a81e6b392f74, 0x4e2f97d01b836c58, 0x94b13f6820c45a7d,
    0x5c7e02a4d91b8f36, 0xb8604c3d1a7f52e9, 0x27934ab0c56e1d80, 0x81d65f2c0e4b9a73,
    0x462c9f350d817be4, 0xc0971a8e4f235d6b, 0x1b83d40c6f9e52a7, 0x7f5e2c04a8319bd6,
    0xd246e8b13c7a059f, 0x3b9f5d7021c4ea68, 0x8e04c1a36b5f9d27, 0x64a83e2019b7f50c,
    0xa15f72d048c39e6b, 0x503c8e1b962da4f7, 0xb7920d4a3fc16e58, 0x2dc48f71a0361b9e,
    0x7361b2c54e09d8af, 0xcf8a4d1736b250e9, 0x1540dc93e07b2a6f, 0x8b27f16e4d39c05a,
    0xe95014c83a7fd26b, 0x4c73ba2d0f81659e, 0x9681c5f34a0e2d7b, 0x3d0f4e8a17962c51,
    0xb2e7901c4a5f3d86, 0x67c34b1fe0928d5a, 0x1a8fd0752b4c9e63, 0xdc132e40f79b6a85,
    0x4f8b60c31d725ea9, 0xa3712de58c046f9b, 0x5e9c84f1270b3da6, 0x0b4e27d3a6819c5f,
    0x6834af09c1752de8, 0xc97d52be3f018a46, 0x2b0e16f980c73d54, 0x85fc3a4e7d19b0c2,
    0x41d08ce62b79f35a, 0xfb6e41a08c250d97, 0x30c8953d7b146fe2, 0x8e5f20c61a7d4b93,
    0x673ba14df8090e5c, 0xca921e83b540fd27, 0x1d6f4c0b7a83e251, 0x78b039d46c1ae09f,
    0xb4c72d8a0f451396, 0x2530f1c78d69b4ae, 0x8ec0461ba3972d50, 0x5d17c4f0b82a6e39,
    0xa3fb29d01c7e4586, 0x4180da56c3f90b2e, 0xec361bc94a870d75, 0x1a79f5d32b0c8e46,
    0x7bc3042f8e561da9, 0xd5817a3c4f92e06b, 0x2e4cd0b18a7935f6, 0x90b74e2a6c013d58,
    0x531ef8a4d0269cb7, 0xba90c5f42d0e3176, 0x06d23e9b5f7c84a1, 0x69c4017de83f52b8,
    0xdc3e85a0f1624b97, 0x418c7b2fe0931d56, 0xb7f0d5c42a8e6019, 0x2e64b98c3d1075af,
    0x8931c4a57f0eb2d6, 0x40dc2f936b75e8a1, 0xfbc1568d2a034e97, 0x1f8a4e7b6c920d53,
    0x75c803b14d2fe6a8, 0xd03f6c5a1e8b2974, 0x4ae9718d3f0c4b52, 0x921b45dc7f6e03a8,
    0x5678f1a30c4d9e2b, 0xbfd0382e95014a67, 0x2c4b1f7980da35e6, 0x8309dc2e4f7b1a5c,
    0x6fa5381c0d79c4be, 0xc02f9b74e3051d68, 0x1753e0c48b2a6df9, 0x7b8da4f31c590e27,
    0xdf2060bc4e1a8375, 0x439c15f7a2086de0, 0xacf8302db5671c49, 0x0d4e1b7836c09fa5,
    0x7081d5e43a2cb916, 0xcfe4093b17802d5a, 0x23b6f80a4c5d1e97, 0x8c19743de06b2fa5,
    0x5a2e9f0b1d73c486, 0xb03f61c74a85d2e9, 0x2749c8e53d1f0a6b, 0x81ba057c3f4d9e20,
    0x4c671ae83090b5d2, 0xf8bd35a14d206c97, 0x163c07e5b8491da2, 0x79e8b0f34256ca1d,
    0xd1408dca7b3f1962, 0x3e8c02f41b7a5d86, 0x9051b67ae23c4f08, 0x47c8290db53e6fa1,
    0xab7f50d312086c4e, 0x0e3ab16c7f45d982, 0x6c84d0f25a39107b, 0xc9053e7b4d821fa6,
    0x1548a0d37b96f2ce, 0x70b92e15f4831cd6, 0xda6f80b23c4917e5, 0x3105e4b97c2d6fa8,
    0x8cd3a0516e2f4b97, 0x5b9e42f30a7c1d86, 0xbf031a6e9c7840d2, 0x26d45b0f83e10ca7,
    0x8f60c2de1a4937b5, 0x421f7e8b30950ca6, 0xec8d3b5f7c0241a9, 0x0934f1a7c86d05be,
    0x7b5ce4230f1a8d96, 0xd81b7690f34a25ce, 0x4053a2db7f6e1c89, 0xac97348b201f6d5e,
    0x1e4f8b0d37c69a52, 0x7890d5ea4b2c13f6, 0xdf2461c0893b7a15, 0x3a685f9e1d4c20b7,
    0x93c0d4f72e815b46, 0x50a7831cd4f09e2b, 0xb4e01f5a3c86d297, 0x2b6d94c7f0a31058,
    0x8751c0e43d6b9f2a, 0x4c0e25f980b37a16, 0xfb8d47c01a3296e5, 0x1239b0c87e6f4d5a,
    0x7e64fa2c130b8d97, 0xd90e7b3f4a251c86, 0x3dc8014e7b9f6250, 0x921b58a43c0fd7e6,
    0x5f83d01c2a796eb4, 0xbc4e2f07639d1a58, 0x0a718db54c2e6f93, 0x68c0349fe72b15a0,
    0xd1f5820b3c4a9e67, 0x3a4d7b9c610e58f2, 0x9560af2e1b4d73c8, 0x52b8e0f43c0a19d6,
    0xb04f93e71d56c28a, 0x2d8a17046c3b9fe5, 0x87f5e24c0b391da6, 0x43160cb98e7f52d0,
    0xfe924a7b3d0158c6, 0x1bc5d48e7a236f90, 0x7831f9c04b6ad25e, 0xd4c2057a3b91e6f8,
    0x3069bd4ef5280ca1, 0x9a5f234c1e7d60b8, 0x57c0ba8e4f319d26, 0xb1e4380d73956ca0,
    0x2cf7104a86b3d59e, 0x8340b2f5c96e01d7, 0x48d2e93b7a0c5f61, 0xf5081c6adb730e94,
    0x13e9d0c47f8b625a, 0x7a4b25f83c609de1, 0xde01c7a48b5f23e6, 0x36f84e92c1a7d05b,
    0x9c2b06d15f4a38e7, 0x5971b38e2c0df4a6, 0xb4e0d2f43a815c09, 0x21c7809e5b4d3fa6,
    0x86f3c41d7a029e58, 0x4a08b69fd23c517e, 0xfc7d412a8e053b96, 0x1043a6c87b9f2d5e,
    0x7e69bc30f5214a98, 0xd204f8c1b3760e5a, 0x3e90d24a79f1b58c, 0x9b56a403d20e7c1f,
    0x5731cf8a4b960d2e, 0xb8e04d1672853acf, 0x2509b3e7c8f01d46, 0x8ac4701b3f9d6528,
    0x4618fe2b0c4a97d5, 0xf0cd38a17b652e09, 0x1d72b0c58a94f63e, 0x79e5c4d030b21fa8,
    0xd361f85a4c027b9e, 0x3c8d017e4b69af52, 0x9a20e6b53d810c47, 0x57b4fa028c3619de,
    0xbc01e7539f2d4a86, 0x2de4930b7f618c50, 0x83f76c4d1a09b52e, 0x410cb9e27f3d8065,
    0xfeb2574c0a81d39e, 0x1c674b8f3d520ea9, 0x7a08d3c65e9b24f1, 0xd4bf290a3c1e7658,
}

// CDC returns an iterator over content-defined chunks of r using a gear-hash
// rolling function. Each yielded slice is freshly allocated and owned by the
// caller. Iteration stops after the first error.
//
// The average chunk size is targetSize (which must be a power of two and
// positive). Chunk sizes are clamped to [minSize, maxSize]. The gear hash
// makes chunk boundaries content-defined: an edit only rewrites the one or two
// chunks it touches, so unchanged regions produce identical shards across
// revisions (enabling dedup and efficient incremental re-upload).
//
// Callers that want the defaults may pass DefaultCDCMin, DefaultCDCTarget,
// DefaultCDCMax.
func CDC(r io.Reader, minSize, targetSize, maxSize int) iter.Seq2[[]byte, error] {
    return func(yield func([]byte, error) bool) {
        if minSize <= 0 || targetSize <= 0 || maxSize <= 0 {
            yield(nil, fmt.Errorf("chunk: CDC sizes must be positive"))
            return
        }
        if minSize > targetSize || targetSize > maxSize {
            yield(nil, fmt.Errorf("chunk: CDC requires minSize <= targetSize <= maxSize"))
            return
        }
        // mask has (log2(targetSize)) trailing set bits. When gear & mask == 0,
        // cut — giving an average cut probability of 1/targetSize per byte.
        // We do not require targetSize to be exactly a power of two; we compute
        // the nearest power-of-two mask.
        bits := 0
        for (1 << bits) < targetSize {
            bits++
        }
        mask := uint64((1 << bits) - 1)

        buf := make([]byte, maxSize)
        for {
            n := 0
            var gear uint64
            for n < maxSize {
                // Read one byte at a time to avoid buffering a whole chunk
                // before deciding the boundary.
                nn, err := r.Read(buf[n : n+1])
                if nn > 0 {
                    gear = (gear << 1) ^ gearTable[buf[n]]
                    n++
                    if n >= minSize && gear&mask == 0 {
                        break // content-defined cut point
                    }
                }
                if err != nil {
                    if n > 0 {
                        chunk := make([]byte, n)
                        copy(chunk, buf[:n])
                        yield(chunk, nil)
                    }
                    return // EOF or other error — stop cleanly
                }
            }
            if n == 0 {
                return
            }
            chunk := make([]byte, n)
            copy(chunk, buf[:n])
            if !yield(chunk, nil) {
                return
            }
        }
    }
}

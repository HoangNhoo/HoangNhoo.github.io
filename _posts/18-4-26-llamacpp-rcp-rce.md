---
title: Reproducing PoC Of Llama.cpp RPC Heap-Overflow
date: 2026-04-18 01:23 +0700
categories: [Security_Research, Local_Inference]
tags: [AI, pwnable, binary]
author: HoangNhoo
math: true
---

## 1. Details

### 1.1 How to communicate with rpc server?

There are bunch of cmd to communcate with the rpc server.

### 1.2 Complex structures:

```cpp
struct ggml_backend_buffer_i {
    // (optional) free the buffer
    void         (*free_buffer)  (ggml_backend_buffer_t buffer);
    // base address of the buffer
    void *       (*get_base)     (ggml_backend_buffer_t buffer);
    // (optional) initialize a tensor in the buffer (eg. add tensor extras)
    void         (*init_tensor)  (ggml_backend_buffer_t buffer, struct ggml_tensor * tensor);
    // tensor data access
    void         (*memset_tensor)(ggml_backend_buffer_t buffer,       struct ggml_tensor * tensor,     uint8_t value, size_t offset, size_t size);
    void         (*set_tensor)   (ggml_backend_buffer_t buffer,       struct ggml_tensor * tensor, const void * data, size_t offset, size_t size);
    void         (*get_tensor)   (ggml_backend_buffer_t buffer, const struct ggml_tensor * tensor,       void * data, size_t offset, size_t size);
    // (optional) tensor copy: dst is in the buffer, src may be in any buffer, including buffers from a different backend (return false if not supported)
    bool         (*cpy_tensor)   (ggml_backend_buffer_t buffer, const struct ggml_tensor * src, struct ggml_tensor * dst);
    // clear the entire buffer
    void         (*clear)        (ggml_backend_buffer_t buffer, uint8_t value);
    // (optional) reset any internal state due to tensor initialization, such as tensor extras
    void         (*reset)        (ggml_backend_buffer_t buffer);
};

struct ggml_backend_buffer_type {
    struct ggml_backend_buffer_type_i  iface;
    ggml_backend_dev_t device;
    void * context;
};

struct ggml_backend_buffer {
    struct ggml_backend_buffer_i  iface;
    ggml_backend_buffer_type_t    buft;
    void * context;
    size_t size;
    enum ggml_backend_buffer_usage usage;
};

struct ggml_backend {
    ggml_guid_t guid;
    struct ggml_backend_i iface;
    ggml_backend_dev_t device;
    void * context;
};

typedef struct ggml_backend_buffer_type * ggml_backend_buffer_type_t;
typedef struct      ggml_backend_buffer * ggml_backend_buffer_t;
typedef struct             ggml_backend * ggml_backend_t;
```

```cpp
ggml_backend_buffer_t ggml_backend_buffer_init(
               ggml_backend_buffer_type_t buft,
        struct ggml_backend_buffer_i      iface,
               void *                     context,
               size_t                     size) {
    ggml_backend_buffer_t buffer = new ggml_backend_buffer {
        /* .interface = */ iface,
        /* .buft      = */ buft,
        /* .context   = */ context,
        /* .size      = */ size,
        /* .usage     = */ GGML_BACKEND_BUFFER_USAGE_ANY
    };

    return buffer;
}

ggml_backend_buffer_t ggml_backend_buft_alloc_buffer(ggml_backend_buffer_type_t buft, size_t size) {
    if (size == 0) {
        // return a dummy buffer for zero-sized allocations
        return ggml_backend_buffer_init(buft, {}, NULL, 0);
    }

    return buft->iface.alloc_buffer(buft, size);
}

GGML_CALL static ggml_backend_buffer_t ggml_backend_cpu_buffer_type_alloc_buffer(ggml_backend_buffer_type_t buft, size_t size) {
    size += TENSOR_ALIGNMENT;   // malloc may return an address that is not aligned
    void * data = malloc(size); // TODO: use GGML_ALIGNED_MALLOC (move to ggml-impl.h)
    if (data == NULL) {
        fprintf(stderr, "%s: failed to allocate buffer of size %zu\n", __func__, size);
        return NULL;
    }

    return ggml_backend_buffer_init(buft, cpu_backend_buffer_i, data, size);
}
```

get_base
```cpp
void * ggml_backend_buffer_get_base(ggml_backend_buffer_t buffer) {
    // get_base is optional if the buffer is zero-sized
    if (buffer->size == 0) {
        return NULL;
    }

    void * base = buffer->iface.get_base(buffer);

    GGML_ASSERT(base != NULL && "backend buffer base cannot be NULL");

    return base;
}

static void * ggml_backend_cpu_buffer_get_base(ggml_backend_buffer_t buffer) {
    uintptr_t data = (uintptr_t)buffer->context;

    // align the buffer
    if (data % TENSOR_ALIGNMENT != 0) {
        data = GGML_PAD(data, TENSOR_ALIGNMENT);
    }

    return (void *)data;
}
```

rpc_tensor structure and offset
```cpp
struct rpc_tensor {
    uint64_t id;
    uint32_t type;
    uint64_t buffer;
    uint32_t ne[GGML_MAX_DIMS];
    uint32_t nb[GGML_MAX_DIMS];
    uint32_t op;
    int32_t  op_params[GGML_MAX_OP_PARAMS / sizeof(int32_t)];
    int32_t  flags;
    uint64_t src[GGML_MAX_SRC];
    uint64_t view_src;
    uint64_t view_offs;
    uint64_t data;
    char name[GGML_MAX_NAME];
};

rpc_tensor
    +0x0000 id                   : uint64_t
    +0x0008 type                 : uint32_t
    +0x000c buffer               : uint64_t
    +0x0014 ne                   : uint32_t [4]
    +0x0024 nb                   : uint32_t [4]
    +0x0034 op                   : uint32_t
    +0x0038 op_params            : int32_t [16]
    +0x0078 flags                : int32_t
    +0x007c src                  : uint64_t [10]
    +0x00cc view_src             : uint64_t
    +0x00d4 view_offs            : uint64_t
    +0x00dc data                 : uint64_t
    +0x00e4 name                 : char [64]
    +0x0124 padding              : char [4]
```

ggml_tensor structure and offset
```cpp
struct ggml_tensor {
    enum ggml_type type;

    GGML_DEPRECATED(enum ggml_backend_type backend, "use the buffer type to find the storage location of the tensor");

    struct ggml_backend_buffer * buffer;

    int64_t ne[GGML_MAX_DIMS]; // number of elements
    size_t  nb[GGML_MAX_DIMS]; // stride in bytes:
                               // nb[0] = ggml_type_size(type)
                               // nb[1] = nb[0]   * (ne[0] / ggml_blck_size(type)) + padding
                               // nb[i] = nb[i-1] * ne[i-1]

    // compute data
    enum ggml_op op;

    // op params - allocated as int32_t for alignment
    int32_t op_params[GGML_MAX_OP_PARAMS / sizeof(int32_t)];

    int32_t flags;

    struct ggml_tensor * src[GGML_MAX_SRC];

    // source tensor and offset for views
    struct ggml_tensor * view_src;
    size_t               view_offs;

    void * data;

    char name[GGML_MAX_NAME];

    void * extra; // extra things e.g. for ggml-cuda.cu

    char padding[8];
};

ggml_tensor
    +0x0000 type                 : ggml_type
    +0x0004 backend              : ggml_backend_type
    +0x0008 buffer               : ggml_backend_buffer *
    +0x0010 ne                   : int64_t [4]
    +0x0030 nb                   : size_t [4]
    +0x0050 op                   : ggml_op
    +0x0054 op_params            : int32_t [16]
    +0x0094 flags                : int32_t
    +0x0098 src                  : ggml_tensor *[10]
    +0x00e8 view_src             : ggml_tensor *
    +0x00f0 view_offs            : size_t
    +0x00f8 data                 : void *
    +0x0100 name                 : char [64]
    +0x0140 extra                : void *
    +0x0148 padding              : char [8]
```

check, to make sure the your construct_tensor() true

```cpp
// ggml/src/ggml.c:1548
GGML_ASSERT(type >= 0 && type < GGML_TYPE_COUNT);
GGML_ASSERT(n_dims >= 1 && n_dims <= GGML_MAX_DIMS);

// ggml/src/ggml.c:1173
int64_t ggml_blck_size(enum ggml_type type) {
    return type_traits[type].blck_size;
}
assert(ne % ggml_blck_size(type) == 0);

// ggml/src/ggml.c:1570
GGML_ASSERT(view_src == NULL || data_size == 0 || data_size + view_offs <= ggml_nbytes(view_src));
```

what is `view_src` and `view_offs`?

example:

```
A = [0 1 2 3 4 5 6 7 8 9]
B = A[3:7] = [3 4 5 6]
```

then

```cpp
B.view_src  = A
B.view_offs = offset to 3rd element
B.data      = A.data + view_offs
```

/*
 * Copyright 2021 Andrei Pangin
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <dlfcn.h>
#include "mallocTracer.h"
#include "os.h"
#include "profiler.h"


#define WEAK_EXPORT  __attribute__((weak, visibility("default")))

extern "C" {
    static int malloc_tracer_enabled = 0;

    static int _malloc_init = 0;
    static void* _orig_malloc = NULL;
    static void* _orig_calloc = NULL;
    static void* _orig_free = NULL;
    static void* _orig_realloc = NULL;

    static bool malloc_init() {
        if (__sync_bool_compare_and_swap(&_malloc_init, 0, -1)) {
            _orig_malloc = dlsym(RTLD_NEXT, "malloc");
            _orig_calloc = dlsym(RTLD_NEXT, "calloc");
            _orig_free = dlsym(RTLD_NEXT, "free");
            _orig_realloc = dlsym(RTLD_NEXT, "realloc");
            __sync_bool_compare_and_swap(&_malloc_init, -1, 1);
            return true;
        }
        return false;
    }

    WEAK_EXPORT void* malloc(size_t size) {
        if (_orig_malloc == NULL && !malloc_init()) {
            return OS::safeAlloc(size);
        }

        void* result = ((void* (*)(size_t))_orig_malloc)(size);
        if (malloc_tracer_enabled && result != NULL && size > 0) {
            MallocTracer::recordMalloc(result, size);
        }
        return result;
    }

    WEAK_EXPORT void* calloc(size_t nmemb, size_t size) {
        if (_orig_calloc == NULL && !malloc_init()) {
            return OS::safeAlloc(nmemb * size);
        }

        void* result = ((void* (*)(size_t, size_t))_orig_calloc)(nmemb, size);
        if (malloc_tracer_enabled && result != NULL) {
            MallocTracer::recordMalloc(result, nmemb * size);
        }
        return result;
    }

    WEAK_EXPORT void free(void* ptr) {
        if (_orig_free == NULL && !malloc_init()) {
            return;
        }

        ((void (*)(void*))_orig_free)(ptr);
        if (malloc_tracer_enabled && ptr != NULL) {
            MallocTracer::recordFree(ptr);
        }
    }

    WEAK_EXPORT void* realloc(void* ptr, size_t size) {
        if (_orig_realloc == NULL && !malloc_init()) {
            return NULL;  // should not happen
        }

        void* result = ((void* (*)(void*, size_t))_orig_realloc)(ptr, size);
        if (malloc_tracer_enabled && ptr != NULL) {
            MallocTracer::recordFree(ptr);
        }
        if (malloc_tracer_enabled && result != NULL && size > 0) {
            MallocTracer::recordMalloc(result, size);
        }
        return result;
    }
}


u64 MallocTracer::_interval;
volatile u64 MallocTracer::_allocated_bytes;


Error MallocTracer::check(Arguments& args) {
    if (!_malloc_init) {
        return Error("Must LD_PRELOAD profiler library for native memory profiling");
    }
    return Error::OK;
}

Error MallocTracer::start(Arguments& args) {
    Error error = check(args);
    if (error) {
        return error;
    }

    _interval = args._interval;
    _allocated_bytes = 0;

    __sync_bool_compare_and_swap(&malloc_tracer_enabled, 0, 1);
    return Error::OK;
}

void MallocTracer::stop() {
    __sync_bool_compare_and_swap(&malloc_tracer_enabled, 1, 0);
}

void MallocTracer::recordMalloc(void* address, size_t size) {
    if (_interval > 1) {
        // Do not record allocation unless allocated at least _interval bytes
        while (true) {
            u64 prev = _allocated_bytes;
            u64 next = prev + size;
            if (next < _interval) {
                if (__sync_bool_compare_and_swap(&_allocated_bytes, prev, next)) {
                    return;
                }
            } else {
                if (__sync_bool_compare_and_swap(&_allocated_bytes, prev, next % _interval)) {
                    break;
                }
            }
        }
    }

    MallocEvent event;
    event._address = (uintptr_t)address;
    event._size = size;

    Profiler::instance()->recordSample(NULL, size, BCI_MALLOC, &event);
}

void MallocTracer::recordFree(void* address) {
    MallocEvent event;
    event._address = (uintptr_t)address;
    event._size = 0;

    Profiler::instance()->recordEventOnly(BCI_MALLOC, &event);
}

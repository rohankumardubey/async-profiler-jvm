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

#ifndef _MALLOCTRACER_H
#define _MALLOCTRACER_H

#include "arch.h"
#include "engine.h"


class MallocTracer : public Engine {
  private:
    static u64 _interval;
    static volatile u64 _allocated_bytes;

  public:
    const char* title() {
        return "Malloc profile";
    }

    const char* units() {
        return "bytes";
    }

    Error check(Arguments& args);
    Error start(Arguments& args);
    void stop();

    static void recordMalloc(void* address, size_t size);
    static void recordFree(void* address);
};

#endif // _MALLOCTRACER_H

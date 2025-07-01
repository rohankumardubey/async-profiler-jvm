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

import one.jfr.ClassRef;
import one.jfr.Dictionary;
import one.jfr.JfrReader;
import one.jfr.MethodRef;
import one.jfr.StackTrace;
import one.jfr.event.Event;
import one.jfr.event.EventAggregator;
import one.jfr.event.MallocEvent;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Parses .jfr containing 'nativemem' events,
 * matches 'malloc' and 'free' calls with each other,
 * and produces the FlameGraph of potential native memory leak sites.
 */
public class MallocReport {

    private static final int FRAME_CPP = 4;
    private static final int FRAME_KERNEL = 5;

    private final JfrReader jfr;
    private final Dictionary<String> methodNames = new Dictionary<>();

    public MallocReport(JfrReader jfr) {
        this.jfr = jfr;
    }

    public void convert(final FlameGraph fg, final boolean threads, final boolean total) throws IOException {
        Map<Long, MallocEvent> addresses = new HashMap<>();

        // Read all events to sort them in chronological order
        List<MallocEvent> events = jfr.readAllEvents(MallocEvent.class);
        for (MallocEvent e : events) {
            if (e.size > 0) {
                addresses.put(e.address, e);
            } else {
                addresses.remove(e.address);
            }
        }

        EventAggregator agg = new EventAggregator(threads, total);
        for (MallocEvent e : addresses.values()) {
            agg.collect(e);
        }

        // Don't use lambda for faster startup
        agg.forEach(new EventAggregator.Visitor() {
            @Override
            public void visit(Event event, long value) {
                StackTrace stackTrace = jfr.stackTraces.get(event.stackTraceId);
                if (stackTrace != null) {
                    long[] methods = stackTrace.methods;
                    byte[] types = stackTrace.types;

                    int skip = 0;
                    while (skip < types.length && types[skip] == FRAME_CPP) {
                        skip++;
                    }

                    String[] trace = new String[methods.length - skip + (threads ? 1 : 0)];
                    if (threads) {
                        trace[0] = getThreadFrame(event.tid);
                    }
                    int idx = trace.length;
                    for (int i = skip; i < methods.length; i++) {
                        trace[--idx] = getMethodName(methods[i], types[i]);
                    }
                    fg.addSample(trace, value);
                }
            }
        });
    }

    private String getThreadFrame(int tid) {
        String threadName = jfr.threads.get(tid);
        return threadName == null ? "[tid=" + tid + ']' : '[' + threadName + " tid=" + tid + ']';
    }

    private String getMethodName(long methodId, int type) {
        String result = methodNames.get(methodId);
        if (result != null) {
            return result;
        }

        MethodRef method = jfr.methods.get(methodId);
        if (method == null) {
            result = "unknown";
        } else {
            ClassRef cls = jfr.classes.get(method.cls);
            byte[] className = jfr.symbols.get(cls.name);
            byte[] methodName = jfr.symbols.get(method.name);

            if (className == null || className.length == 0) {
                String methodStr = new String(methodName, StandardCharsets.UTF_8);
                result = type == FRAME_KERNEL ? methodStr + "_[k]" : methodStr;
            } else {
                String classStr = new String(className, StandardCharsets.UTF_8);
                String methodStr = new String(methodName, StandardCharsets.UTF_8);
                result = classStr + '.' + methodStr + "_[j]";
            }
        }

        methodNames.put(methodId, result);
        return result;
    }

    public static void main(String[] args) throws Exception {
        FlameGraph fg = new FlameGraph(args);
        if (fg.input == null) {
            System.out.println("Usage: java " + MallocReport.class.getName() + " [options] input.jfr [output.html]");
            System.out.println();
            System.out.println("options include all supported FlameGraph options, plus the following:");
            System.out.println("  --threads  Split profile by threads");
            System.exit(1);
        }

        boolean threads = Arrays.asList(args).contains("--threads");

        try (JfrReader jfr = new JfrReader(fg.input)) {
            new MallocReport(jfr).convert(fg, threads, true);
        }

        fg.dump();
    }
}

/*
 * Copyright 2026 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.cloudfoundry.security;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

final class LogRecorder {

    private LogRecorder() {
    }

    // Records everything logged to the logger named after the given class while the action runs, at all levels.
    static List<LogRecord> record(Class<?> loggerClass, Action action) throws Exception {
        Logger logger = Logger.getLogger(loggerClass.getName());
        List<LogRecord> records = new ArrayList<>();
        Handler handler = new Handler() {

            @Override
            public void publish(LogRecord record) {
                records.add(record);
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }

        };

        Level level = logger.getLevel();
        logger.addHandler(handler);
        logger.setLevel(Level.ALL);
        try {
            action.run();
        } finally {
            logger.removeHandler(handler);
            logger.setLevel(level);
        }

        return records;
    }

    interface Action {

        void run() throws Exception;

    }

}

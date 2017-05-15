/*
 * Copyright 2017 the original author or authors.
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

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.logging.Logger;

import static java.nio.file.StandardWatchEventKinds.ENTRY_CREATE;
import static java.nio.file.StandardWatchEventKinds.ENTRY_DELETE;
import static java.nio.file.StandardWatchEventKinds.ENTRY_MODIFY;

final class FileWatcher implements Callable<Void> {

    private final Logger logger = Logger.getLogger(this.getClass().getName());

    private final Runnable callback;

    private final ExecutorService executorService;

    private final Path source;

    FileWatcher(Path source, Runnable callback) {
        this.callback = callback;
        this.executorService = Executors.newSingleThreadExecutor(new FileWatcherThreadFactory(source));
        this.source = source;
    }

    @Override
    public Void call() throws IOException, InterruptedException {
        this.logger.info(String.format("Started watching %s", this.source));

        final WatchService watchService = this.source.getFileSystem().newWatchService();
        final WatchKey expected = this.source.getParent().register(watchService, ENTRY_CREATE, ENTRY_DELETE, ENTRY_MODIFY);

        for (; ; ) {
            WatchKey actual = watchService.take();

            if (!actual.equals(expected)) {
                this.logger.warning(String.format("Unknown watch key: %s", actual));
                continue;
            }

            for (WatchEvent<?> watchEvent : actual.pollEvents()) {
                Path changed = (Path) watchEvent.context();

                if (!this.source.getFileName().equals(changed)) {
                    this.logger.fine(String.format("Discarding unimportant file change: %s", changed));
                    continue;
                }

                this.callback.run();
            }

            if (!actual.reset()) {
                this.logger.warning(String.format("Watch key is no longer valid: %s", actual));
                break;
            }
        }

        this.logger.info(String.format("Stopped watching %s", this.source));
        return null;
    }

    void watch() {
        this.executorService.submit(this);
    }

    private static class FileWatcherThreadFactory implements ThreadFactory {

        private final Path source;

        private FileWatcherThreadFactory(Path source) {
            this.source = source;
        }

        @Override
        public Thread newThread(Runnable r) {
            Thread thread = new Thread(r);
            thread.setDaemon(true);
            thread.setName(String.format("file-watcher-%s", this.source));

            return thread;
        }

    }

}

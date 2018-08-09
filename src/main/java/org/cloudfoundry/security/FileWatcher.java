/*
 * Copyright 2017-2018 the original author or authors.
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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.nio.file.StandardWatchEventKinds.ENTRY_CREATE;
import static java.nio.file.StandardWatchEventKinds.ENTRY_DELETE;
import static java.nio.file.StandardWatchEventKinds.ENTRY_MODIFY;

final class FileWatcher implements Runnable, Thread.UncaughtExceptionHandler, ThreadFactory {

    private final Logger logger = Logger.getLogger(this.getClass().getName());

    private final Runnable callback;

    private final AtomicInteger counter = new AtomicInteger();

    private final ExecutorService executorService;

    private final Path source;

    FileWatcher(Path source, Runnable callback) {
        this.callback = callback;
        this.executorService = Executors.newSingleThreadExecutor(this);
        this.source = source;
    }

    @Override
    public Thread newThread(Runnable r) {
        Thread thread = new Thread(r);
        thread.setDaemon(true);
        thread.setName(String.format("file-watcher-%s-%d", this.source.getName(this.source.getNameCount() - 1), this.counter.getAndIncrement()));
        thread.setUncaughtExceptionHandler(this);

        return thread;
    }

    @Override
    public void run() {
        this.logger.info(String.format("Start watching %s", this.source));

        WatchService watchService;
        WatchKey expected;

        try {
            watchService = this.source.getFileSystem().newWatchService();
            expected = this.source.getParent().register(watchService, ENTRY_CREATE, ENTRY_DELETE, ENTRY_MODIFY);
        } catch (IOException e) {
            this.logger.log(Level.SEVERE, "Unable to setup file watcher", e);
            return;
        }

        for (; ; ) {
            try {
                this.logger.fine("Waiting for event");
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
            } catch (InterruptedException e) {
                this.logger.warning("Thread interrupted");
                Thread.currentThread().interrupt();
                break;
            }
        }

        this.logger.info(String.format("Stop watching %s", this.source));
    }

    @Override
    public void uncaughtException(Thread t, Throwable e) {
        this.logger.log(Level.WARNING, "Suppressing watch error", e);
        watch();
    }

    void watch() {
        this.executorService.execute(this);
    }

}

package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// WorkerTaskTimeout is the maximum time allowed for a single worker task
const WorkerTaskTimeout = 30 * time.Second

// workerPool manages a pool of worker goroutines for asynchronous task processing
type workerPool struct {
	workers int            // Number of active workers
	queue   chan task      // Channel for receiving tasks
	wg      sync.WaitGroup // WaitGroup for graceful shutdown synchronization
	once    sync.Once      // Ensure Start is only called once
}

// task represents a unit of work to be processed by the worker pool
type task struct {
	deviceID string          // Target device identifier for the task
	taskType string          // Type of task to execute (see taskType constants)
	params   [][]interface{} // Parameters for parameter-setting tasks
}

// Start initializes the worker pool by launching all worker goroutines
func (wp *workerPool) Start() {
	// Create a specified number of worker goroutines
	for i := 0; i < wp.workers; i++ {
		wp.wg.Add(1)   // Increment WaitGroup counter
		go wp.worker() // Start a worker goroutine
	}
}

// Stop gracefully shuts down the worker pool by closing queue and waiting for completion
func (wp *workerPool) Stop() {
	wp.once.Do(func() { // Ensure Stop is only executed once
		close(wp.queue) // Close the task queue to signal workers to stop
		wp.wg.Wait()    // Wait for all workers to finish processing
	})
}

// worker is the goroutine that processes tasks from the queue
func (wp *workerPool) worker() {
	defer wp.wg.Done() // Signal completion when goroutine exits

	// Process tasks from queue until channel is closed
	for t := range wp.queue {
		// Create context with timeout for each task to prevent hanging
		ctx, cancel := context.WithTimeout(context.Background(), WorkerTaskTimeout)

		var err error
		// Execute appropriate function based on task type
		switch t.taskType {
		case taskTypeSetParams:
			err = setParameterValues(ctx, t.deviceID, t.params)
		case taskTypeApplyChanges:
			err = refreshWLANConfig(ctx, t.deviceID)
		case taskTypeRefreshWLAN:
			err = refreshWLANConfig(ctx, t.deviceID)
		default:
			err = fmt.Errorf("unknown task type: %s", t.taskType)
		}

		// Release context resources
		cancel()

		// Log any errors encountered during task execution
		if err != nil {
			logger.Error("Worker task failed",
				zap.String("deviceID", t.deviceID),
				zap.String("taskType", t.taskType),
				zap.Error(err),
			)
		}
	}
}

// Submit adds a new task to the worker pool queue for asynchronous processing
// This version uses non-blocking send to prevent deadlocks when queue is full
func (wp *workerPool) Submit(deviceID, taskType string, params [][]interface{}) {
	select {
	case wp.queue <- task{deviceID, taskType, params}:
		// Task successfully queued
	default:
		// Queue is full, log warning
		logger.Warn("Worker pool queue full, task dropped",
			zap.String("deviceID", deviceID),
			zap.String("taskType", taskType),
		)
	}
}

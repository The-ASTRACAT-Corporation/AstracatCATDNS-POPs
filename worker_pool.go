package main

import (
	"log"
	"sync"
)

// Job represents the interface for a task that can be executed by a worker.
type Job interface {
	Execute()
}

// WorkerPool manages a pool of workers that execute jobs.
type WorkerPool struct {
	maxWorkers int
	jobQueue   chan Job
	wg         sync.WaitGroup
	quit       chan struct{}
}

// NewWorkerPool creates a new WorkerPool.
func NewWorkerPool(maxWorkers int, jobQueueSize int) *WorkerPool {
	return &WorkerPool{
		maxWorkers: maxWorkers,
		jobQueue:   make(chan Job, jobQueueSize),
		quit:       make(chan struct{}),
	}
}

// Start creates and starts the worker goroutines.
func (wp *WorkerPool) Start() {
	wp.wg.Add(wp.maxWorkers)
	for i := 0; i < wp.maxWorkers; i++ {
		go func(workerID int) {
			defer wp.wg.Done()
			log.Printf("Worker %d starting", workerID)
			for {
				select {
				case job, ok := <-wp.jobQueue:
					if !ok {
						// Job channel is closed, worker should exit.
						log.Printf("Worker %d stopping as job queue is closed.", workerID)
						return
					}
					// Received a job, execute it.
					job.Execute()
				case <-wp.quit:
					// Pool is stopping, worker should exit.
					log.Printf("Worker %d stopping due to quit signal.", workerID)
					return
				}
			}
		}(i + 1)
	}
}

// Submit adds a job to the job queue for a worker to process.
func (wp *WorkerPool) Submit(job Job) {
	// Non-blocking submit: if the queue is full, we can choose to drop the job
	// or handle it in some other way. For now, this will block until a worker is free.
	wp.jobQueue <- job
}

// Stop signals all workers to stop and waits for them to finish.
func (wp *WorkerPool) Stop() {
	log.Println("Stopping WorkerPool...")
	// Close the quit channel to signal all workers to stop.
	close(wp.quit)
	// Wait for all worker goroutines to finish.
	wp.wg.Wait()
	log.Println("WorkerPool stopped.")
}
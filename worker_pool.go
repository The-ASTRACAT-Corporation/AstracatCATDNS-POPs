package main

import (
	"log"
	"sync"
)

// Job represents the interface for a task that can be executed by a worker.
type Job interface {
	Execute()
}

// Worker represents a single worker in the pool.
type Worker struct {
	id         int
	jobQueue   chan Job
	workerPool chan chan Job
	quit       chan bool
}

// NewWorker creates a new Worker.
func NewWorker(id int, workerPool chan chan Job) *Worker {
	return &Worker{
		id:         id,
		jobQueue:   make(chan Job),
		workerPool: workerPool,
		quit:       make(chan bool),
	}
}

// Start begins the worker's loop, listening for jobs.
func (w *Worker) Start() {
	go func() {
		for {
			// Add ourselves to the worker pool
			w.workerPool <- w.jobQueue

			select {
			case job := <-w.jobQueue:
				// Received a job, execute it
				job.Execute()
			case <-w.quit:
				// We have been asked to stop
				log.Printf("Worker %d stopping", w.id)
				return
			}
		}
	}()
}

// Stop tells the worker to stop.
func (w *Worker) Stop() {
	go func() {
		w.quit <- true
	}()
}

// WorkerPool manages a pool of workers.
type WorkerPool struct {
	maxWorkers int
	jobQueue   chan Job
	workerPool chan chan Job
	quit       chan bool
	wg         sync.WaitGroup
}

// NewWorkerPool creates a new WorkerPool.
func NewWorkerPool(maxWorkers int, jobQueueSize int) *WorkerPool {
	return &WorkerPool{
		maxWorkers: maxWorkers,
		jobQueue:   make(chan Job, jobQueueSize),
		workerPool: make(chan chan Job, maxWorkers),
		quit:       make(chan bool),
	}
}

// Start begins the dispatching of jobs to workers.
func (wp *WorkerPool) Start() {
	// Start all workers
	for i := 0; i < wp.maxWorkers; i++ {
		worker := NewWorker(i+1, wp.workerPool)
		worker.Start()
	}

	go wp.dispatch()
}

// dispatch listens for jobs and dispatches them to available workers.
func (wp *WorkerPool) dispatch() {
	for {
		select {
		case job := <-wp.jobQueue:
			// A job has been received, wait for an available worker job queue
			go func(job Job) {
				workerJobQueue := <-wp.workerPool
				workerJobQueue <- job
			}(job)
		case <-wp.quit:
			// We have been asked to stop
			log.Println("WorkerPool stopping")
			return
		}
	}
}

// Submit adds a job to the job queue.
func (wp *WorkerPool) Submit(job Job) {
	wp.wg.Add(1)
	go func() {
		defer wp.wg.Done()
		wp.jobQueue <- job
	}()
}

// Stop stops the worker pool and waits for all jobs to complete.
func (wp *WorkerPool) Stop() {
	log.Println("Stopping WorkerPool...")
	wp.quit <- true
	wp.wg.Wait() // Wait for all submitted jobs to be processed
	// TODO: Signal individual workers to stop
	log.Println("WorkerPool stopped.")
}
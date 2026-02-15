// Copyright 2026 Kedar Kulkarni
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package analyzer

import (
	"log"
	"sync"
)

// JobQueue is a channel for analysis jobs
var JobQueue = make(chan AnalysisJob, 100)

// AnalysisJob represents a PCAP analysis job
type AnalysisJob struct {
	AnalysisID int
	PcapPath   string
}

// Worker processes analysis jobs from the queue
type Worker struct {
	ID         int
	JobQueue   chan AnalysisJob
	quit       chan bool
	wg         *sync.WaitGroup
}

// NewWorker creates a new worker
func NewWorker(id int, jobQueue chan AnalysisJob, wg *sync.WaitGroup) *Worker {
	return &Worker{
		ID:       id,
		JobQueue: jobQueue,
		quit:     make(chan bool),
		wg:       wg,
	}
}

// Start begins processing jobs
func (w *Worker) Start() {
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		log.Printf("Worker %d started", w.ID)

		for {
			select {
			case job := <-w.JobQueue:
				log.Printf("Worker %d processing analysis %d", w.ID, job.AnalysisID)
				err := AnalyzePCAP(job.AnalysisID, job.PcapPath)
				if err != nil {
					log.Printf("Worker %d failed to analyze %d: %v", w.ID, job.AnalysisID, err)
				} else {
					log.Printf("Worker %d completed analysis %d", w.ID, job.AnalysisID)
				}
			case <-w.quit:
				log.Printf("Worker %d stopping", w.ID)
				return
			}
		}
	}()
}

// Stop stops the worker
func (w *Worker) Stop() {
	go func() {
		w.quit <- true
	}()
}

// WorkerPool manages a pool of workers
type WorkerPool struct {
	workers []*Worker
	wg      *sync.WaitGroup
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(numWorkers int) *WorkerPool {
	wg := &sync.WaitGroup{}
	workers := make([]*Worker, numWorkers)

	for i := 0; i < numWorkers; i++ {
		workers[i] = NewWorker(i+1, JobQueue, wg)
	}

	return &WorkerPool{
		workers: workers,
		wg:      wg,
	}
}

// Start starts all workers in the pool
func (wp *WorkerPool) Start() {
	log.Printf("Starting worker pool with %d workers", len(wp.workers))
	for _, worker := range wp.workers {
		worker.Start()
	}
}

// Stop stops all workers in the pool
func (wp *WorkerPool) Stop() {
	log.Println("Stopping worker pool")
	for _, worker := range wp.workers {
		worker.Stop()
	}
	wp.wg.Wait()
	log.Println("Worker pool stopped")
}

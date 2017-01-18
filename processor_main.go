/* processor_main - PostgreSQL-based workload engine
 * Written by Rob Stradling
 * Copyright (C) 2016-2017 COMODO CA Limited
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	_ "github.com/lib/pq"
)

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

func recoverErr(context string) {
	if r := recover(); r != nil {
		log.Printf("ERROR: %v [%s]", r, context)
	}
}

func doUpdateWorkItem(wi *WorkItem, update_statement *sql.Stmt) {
	result, err := wi.Update(update_statement)
	if err != nil {
		log.Printf("ERROR: UPDATE failed (%v)\n", err.Error)
	} else {
		rows_affected, err := result.RowsAffected()
		if err != nil {
			log.Printf("ERROR: UPDATE failed (%v)\n", err.Error)
		} else if rows_affected < 1 {
			log.Println("ERROR: No rows UPDATEd")
		}
	}
}

func doBatchOfWork(db *sql.DB, w *Work, batch_size int, concurrent_items int) int {
	// Fetch a batch of work to do from the DB
	log.Println("Initializing...")
	w.Begin(db)
	log.Println("Preparing...")
	select_query := w.SelectQuery(batch_size)
	log.Printf("Executing...%s", select_query)
	rows, err := db.Query(select_query)
	checkErr(err)
	defer rows.Close()

	// Prepare the UPDATE statement that will be run after performing each work item
	update_statement, err := db.Prepare(w.UpdateStatement())
	checkErr(err)
	defer update_statement.Close()

	// Do the batch of work, throttling the number of concurrent work items
	log.Println("Performing...")
	var wg sync.WaitGroup
	var chan_concurrency = make(chan int, concurrent_items)
	var i int
	for i = 0; rows.Next(); i++ {
		var wi WorkItem
		err = wi.Parse(rows)
		checkErr(err)
		wg.Add(1)
		go func() {
			defer func() {
				wg.Done()
			}()
			defer doUpdateWorkItem(&wi, update_statement)
			chan_concurrency <- 1
			defer func() { <-chan_concurrency }()
			defer recoverErr(wi.crl_url)
			wi.Perform(db, w)
		}()
	}

	// Wait for all work items to complete
	wg.Wait()
	w.End()

	return i
}

func main() {
	defer recoverErr("main")

	// Configure signal handling
	chan_signals := make(chan os.Signal, 20)
	signal.Notify(chan_signals, os.Interrupt, syscall.SIGTERM)

	// Parse common command line flags
	var conn_info string
	flag.StringVar(&conn_info, "conninfo", fmt.Sprintf("user=certwatch dbname=certwatch connect_timeout=5 sslmode=disable application_name=%s", os.Args[0][(strings.LastIndex(os.Args[0], "/") + 1):len(os.Args[0])]), "DB connection info")
	var conn_open int
	flag.IntVar(&conn_open, "connopen", 5, "Maximum number of open connections to the DB [0=unlimited]")
	var conn_idle int
	flag.IntVar(&conn_idle, "connidle", 0, "Maximum number of connections in the idle connection pool")
	var interval time.Duration
	flag.DurationVar(&interval, "interval", time.Second * 30, "How often to check for more work [0s=exit when no more work to do]")
	var batch_size int
	flag.IntVar(&batch_size, "batch", 100, "Maximum number of items per batch of work")
	var concurrent_items int
	flag.IntVar(&concurrent_items, "concurrent", 10, "Maximum number of items processed simultaneously")

	// Parse any custom flags
	var work Work
	custom_flags := work.CustomFlags()
	flag.Parse()
	work.Init()

	// Show configuration
	log.Printf("Configuration:\n  conninfo: %s\n  connopen: %d\n  connidle: %d\n  interval: %v\n  batch: %d\n  concurrent: %d\n%s", conn_info, conn_open, conn_idle, interval, batch_size, concurrent_items, custom_flags)

	// Connect to the database
	log.Println("Connecting...")
	db, err := sql.Open("postgres", conn_info)
	checkErr(err)
	defer db.Close()
	db.SetMaxOpenConns(conn_open)
	db.SetMaxIdleConns(conn_idle)

	// Perform work in batches
	next_time := time.Now()
	keep_looping := true
	for keep_looping {
		// Perform one batch of work
		items_processed := doBatchOfWork(db, &work, batch_size, concurrent_items)

		// Exit if interval=0s and there's no more work to do
		if (items_processed == 0) && (interval == 0) {
			break
		}

		// Schedule the next batch of work
		next_time = next_time.Add(interval)
		if (items_processed > 0) || (next_time.Before(time.Now())) {
			next_time = time.Now()
		}

		// Have a rest if possible.  Process any pending SIGINT or SIGTERM.
		log.Println("Resting...")
		select {
			case sig := <-chan_signals:
				log.Printf("Signal received: %v\n", sig)
				keep_looping = false
			case <-time.After(next_time.Sub(time.Now())):
		}
	}

	// We're done
	log.Println("Goodbye!")
}

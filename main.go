package main

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

//~~~~~~~~~
type route struct {
	pattern *regexp.Regexp
	handler http.Handler
}
type RegexpHandler struct {
	routes []*route
}

func (h *RegexpHandler) Handler(pattern *regexp.Regexp, handler http.Handler) {
	h.routes = append(h.routes, &route{pattern, handler})
}
func (h *RegexpHandler) HandleFunc(pattern *regexp.Regexp, handler func(http.ResponseWriter, *http.Request)) {
	h.routes = append(h.routes, &route{pattern, http.HandlerFunc(handler)})
}
func (h *RegexpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	for _, route := range h.routes {
		if route.pattern.MatchString(r.URL.Path) {
			route.handler.ServeHTTP(w, r)
			return
		}
	}
	http.NotFound(w, r)
}

//~~~~~~~~~~
type CommandType int

const (
	HashPasswordCommand = iota
	GetHashCommand
	GetStatsCommand
	CollectStatCommand
)

//HashCommand  ... channel that manipulates the hash info
//StatsCommand  ... channel that manipulates the stats /timing
type HashCommand struct {
	ty        CommandType
	data      HashData
	replyChan chan HashData
}
type StatsCommand struct {
	ty        CommandType
	replyChan chan StatCommandData
	payload   requestStats
}
type HashData struct {
	index int
	pw    string
	ok    bool
}
type StatCommandData struct {
	payload stats
	ok      bool
}
type stats struct {
	Total   int     `json:"total"`
	Average float64 `json:"average"`
}
type requestStats struct {
	reqTime int64
	path    string
}
type Server struct {
	mux              *http.ServeMux
	srv              *http.Server
	myhashes         map[int]string
	computeChannel   chan *HashData
	interruptChannel chan os.Signal
	requestTimes     []int64
	hashCmds         chan<- HashCommand
	statsCmds        chan<- StatsCommand
	workWaitGroup    sync.WaitGroup
}

func (l *Server) hashManager() chan<- HashCommand {
	myhashes := make(map[int]string)
	hashIndex := 0
	cmds := make(chan HashCommand)
	go func() {
		for cmd := range cmds {
			switch cmd.ty {
			case GetHashCommand:
				l.workWaitGroup.Add(1)
				log.Println("gethashcommand")
				if val, ok := myhashes[cmd.data.index]; ok {
					cmd.replyChan <- HashData{index: cmd.data.index, pw: val, ok: true}
				} else {
					cmd.replyChan <- HashData{ok: false}
				}
				l.workWaitGroup.Done()
			case HashPasswordCommand:
				l.workWaitGroup.Add(1)
				log.Println("hashpassword")
				myIndex := hashIndex
				go func() {
					afterFuncTimer := time.AfterFunc(time.Second*5, func() {
						h := sha512.New()
						_, _ = io.WriteString(h, cmd.data.pw)
						sha512Bytes := h.Sum(nil)
						log.Printf("SHA512 = %x\n", sha512Bytes)
						base64 := hex.EncodeToString(sha512Bytes)
						myhashes[myIndex] = base64
						l.workWaitGroup.Done()
					})
					defer afterFuncTimer.Stop()
					<-afterFuncTimer.C
				}()
				cmd.replyChan <- HashData{ok: true, index: hashIndex}
				hashIndex++
			}
		}
	}()
	return cmds
}

func (l *Server) statsManager() chan<- StatsCommand {
	cmds := make(chan StatsCommand)
	go func() {
		for cmd := range cmds {
			switch cmd.ty {
			case GetStatsCommand:
				l.workWaitGroup.Add(1)
				total := len(l.requestTimes)
				avg := 0.0
				if total > 0 {
					sum := int64(0)
					for _, num := range l.requestTimes {
						sum += num
					}
					avg = float64(sum / int64(total))
				}
				cmd.replyChan <- StatCommandData{payload: stats{Total: total, Average: avg}, ok: true}
				l.workWaitGroup.Done()
			case CollectStatCommand:
				l.workWaitGroup.Add(1)
				//quick, dirty
				// if its the /stats path, skip, dont want to time the request asking for the timing
				if cmd.payload.path != "/stats" {
					l.requestTimes = append(l.requestTimes, cmd.payload.reqTime)
				}
				l.workWaitGroup.Done()
			}
		}
	}()
	return cmds
}

func (l *Server) hash(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		_, _ = fmt.Fprintf(w, "ParseForm() err: %v", err)
		return
	}
	pw := req.PostForm.Get("password")
	log.Println(pw)
	replyChan := make(chan HashData)
	l.hashCmds <- HashCommand{ty: HashPasswordCommand, data: HashData{pw: pw}, replyChan: replyChan}
	reply := <-replyChan
	if reply.ok {
		_, _ = fmt.Fprintf(w, "%d", reply.index)
	} else {
		http.NotFound(w, req)
	}
}

func (l *Server) fetchHash(w http.ResponseWriter, req *http.Request) {
	log.Printf("fetchHash %s\n", req.URL.Path)
	//Assumes there is a 2nd int value, since this method is only matched, if the regex matches something like: '/hash/2020' and not '/hash/10220/11'
	id := strings.Split(req.URL.Path, "/")[2]
	i, err := strconv.Atoi(id)
	if err != nil {
		//invalid ID, maybe a negative number
		http.Error(w, "400 Bad Request", http.StatusBadRequest)
		return
	}
	replyChan := make(chan HashData)
	l.hashCmds <- HashCommand{ty: GetHashCommand, data: HashData{index: i}, replyChan: replyChan}
	reply := <-replyChan
	if reply.ok {
		_, _ = fmt.Fprintf(w, reply.pw)
	} else {
		http.NotFound(w, req)
	}
}

func (l *Server) stats(w http.ResponseWriter, req *http.Request) {
	replyChan := make(chan StatCommandData)
	l.statsCmds <- StatsCommand{ty: GetStatsCommand, replyChan: replyChan}
	reply := <-replyChan
	if reply.ok {
		statsJSON, err := json.MarshalIndent(reply.payload, "", "  ")
		if err != nil {
			log.Fatalf(err.Error())
		}
		_, _ = fmt.Fprintf(w, "%s", string(statsJSON))
	} else {
		http.Error(w, "500 Internal Error Collecting Stats", http.StatusInternalServerError)
	}
}

func (l *Server) shutdown(w http.ResponseWriter, req *http.Request) {
	l.interruptChannel <- os.Interrupt
	_, _ = fmt.Fprint(w, "shutting down")
}

func (l *Server) timingMiddleware(next func(w http.ResponseWriter, r *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//log.Println("timingmiddleware start")
		startTS := time.Now()
		next(w, r)
		//log.Println("timingMiddleware end")
		diff := time.Now().Sub(startTS)
		//Pipe this to the statsManager...., no need for a reply.
		l.statsCmds <- StatsCommand{ty: CollectStatCommand, payload: requestStats{reqTime: diff.Milliseconds(), path: r.URL.Path}}
	})
}

func methodValidationMiddleware(method string, next func(w http.ResponseWriter, r *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			http.Error(w, "405 Method Not allowed", http.StatusMethodNotAllowed)
			return
		}
		next(w, r)
	})
}

func (l *Server) init() {
	log.Println("init server...")

	rh := &RegexpHandler{}
	rh.Handler(regexp.MustCompile("^/hash?$"), methodValidationMiddleware("POST", l.hash))
	rh.Handler(regexp.MustCompile("^/hash/\\d*?$"), methodValidationMiddleware("GET", l.fetchHash))
	rh.Handler(regexp.MustCompile("^/stats?$"), methodValidationMiddleware("GET", l.stats))
	rh.Handler(regexp.MustCompile("^/shutdown?$"), methodValidationMiddleware("GET", l.shutdown))
	l.mux.Handle("/", l.timingMiddleware(rh.ServeHTTP)) //add global middleware here.

	signal.Notify(l.interruptChannel, os.Interrupt)

	l.statsCmds = l.statsManager() // pattern feels un-clean :|
	l.hashCmds = l.hashManager()

	l.srv = &http.Server{
		Addr:         ":9000",          //TODO: make configurable
		WriteTimeout: time.Second * 15, //TODO: make configurable
		ReadTimeout:  time.Second * 15, //TODO: make configurable
		IdleTimeout:  time.Second * 60, //TODO: make configurable
		Handler:      l.mux,
	}
}

func (l *Server) runTillInterrupted() {
	go func() {
		log.Println("Listen and Serve start")
		if err := l.srv.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()
	<-l.interruptChannel //wait till system interrupt or shutdown-api.
}

func waitFor(wg *sync.WaitGroup, timeout time.Duration) bool {
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()
	select {
	case <-c:
		return false
	case <-time.After(timeout):
		return true
	}
}
func (l *Server) cleanShutdown() {

	close(l.interruptChannel)
	close(l.computeChannel)
	close(l.hashCmds)
	close(l.statsCmds)

	var wait = time.Second * 15
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()

	log.Println("Waiting for Workgroup to finish")
	if waitFor(&l.workWaitGroup, time.Second*2) {
		log.Println("Timeout waiting, invalid data may exist")
	}

	log.Println("Shutting Down")
	err := l.srv.Shutdown(ctx)
	if err != nil {
		log.Fatal(err)
	}
}
func main() {
	server := Server{
		myhashes:         make(map[int]string),
		computeChannel:   make(chan *HashData),
		interruptChannel: make(chan os.Signal, 1),
		mux:              http.NewServeMux(),
	}
	server.init()
	server.runTillInterrupted()
	server.cleanShutdown()
	log.Println("ShutDown")
	os.Exit(0)
}

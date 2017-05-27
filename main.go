package main

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/immesys/bw2bind"
	murmur "github.com/zhangxinngang/murmur"
)

const NumEpochs = 3
const EpochInterval = 20 * time.Second

type Key struct {
	src  string
	hash uint32
}

type Forward struct {
	src string
	po  bw2bind.PayloadObject
}

var hmu sync.Mutex
var epochs []map[Key][]byte

type message struct {
	Srcmac  string `msgpack:"srcmac"`
	Srcip   string `msgpack:"srcip"`
	Popid   string `msgpack:"popid"`
	Poptime int64  `msgpack:"poptime"`
	Brtime  int64  `msgpack:"brtime"`
	Rssi    int    `msgpack:"rssi"`
	Lqi     int    `msgpack:"lqi"`
	Payload []byte `msgpack:"payload"`
}

//counters
var c_recv uint64
var c_dup uint64
var c_err uint64
var c_forwarded uint64

func main() {
	cl := bw2bind.ConnectOrExit("")
	cl.SetEntityFromEnvironOrExit()
	if len(os.Args) != 3 {
		fmt.Printf("Format: hkdedupd <prefix> <customer>:<brz>")
		os.Exit(1)
	}
	prefix := os.Args[1]
	customerbrz := strings.Split(os.Args[2], ":")
	customer := customerbrz[0]
	brz := customerbrz[1]
	brarr := strings.Split(brz, ",")
	epochs = make([]map[Key][]byte, NumEpochs)
	for i := 0; i < NumEpochs; i++ {
		epochs[i] = make(map[Key][]byte)
	}
	och := make(chan Forward, 1000)
	go AgeOut()
	go PrintStats()
	outputuri := path.Join(prefix, "dedup", customer)
	if !strings.HasSuffix(outputuri, "/") {
		outputuri += "/"
	}

	for _, b := range brarr {
		listenuri := path.Join(prefix, b)
		if !strings.HasSuffix(listenuri, "/") {
			listenuri += "/"
		}
		ch := cl.SubscribeOrExit(&bw2bind.SubscribeParams{
			AutoChain: true,
			URI:       listenuri + "*/s.hamilton/+/i.l7g/signal/raw",
		})
		go handleIncoming(ch, och)
	}
	go handleOutgoing(cl, outputuri, och)
	go handleOutgoing(cl, outputuri, och)
	go handleOutgoing(cl, outputuri, och)
	handleOutgoing(cl, outputuri, och)
}

func PrintStats() {
	for {
		time.Sleep(5 * time.Second)
		fmt.Printf("recv=%d  dup=%d  err=%d  forwarded=%d\n", c_recv, c_dup, c_err, c_forwarded)
	}
}
func AgeOut() {
	for {
		time.Sleep(EpochInterval)
		hmu.Lock()
		for i := len(epochs) - 1; i > 0; i-- {
			epochs[i] = epochs[i-1]
		}
		epochs[0] = make(map[Key][]byte)
		hmu.Unlock()
	}
}
func CheckInsertDup(k Key, body []byte) bool {
	hmu.Lock()
	defer hmu.Unlock()
	for _, e := range epochs {
		pay, ok := e[k]
		if ok {
			if bytes.Equal(pay, body) {
				return true
			}
		}
	}
	epochs[0][k] = body
	return false
}
func handleIncoming(ch chan *bw2bind.SimpleMessage, out chan Forward) {
	for m := range ch {
		po := m.GetOnePODF("2.0.10.1")
		if po == nil {
			fmt.Printf("po mismatch\n")
			continue
		}
		atomic.AddUint64(&c_recv, 1)
		im := message{}
		po.(bw2bind.MsgPackPayloadObject).ValueInto(&im)
		k := Key{src: im.Srcmac, hash: murmur.Murmur3(im.Payload)}

		if !CheckInsertDup(k, im.Payload) {
			select {
			case out <- Forward{po: po, src: im.Srcmac}:
			default:
				fmt.Println("Dropping, cannot keep up")
			}
		} else {
			atomic.AddUint64(&c_dup, 1)
		}
	}
}
func handleOutgoing(cl *bw2bind.BW2Client, outputuri string, out chan Forward) {
	for m := range out {
		err := cl.Publish(&bw2bind.PublishParams{
			URI:            fmt.Sprintf("%ss.hamilton/%s/i.l7g/signal/dedup", outputuri, m.src),
			PayloadObjects: []bw2bind.PayloadObject{m.po},
			AutoChain:      true,
		})
		if err != nil {
			fmt.Printf("failed to publish: %v\n", err)
			atomic.AddUint64(&c_err, 1)
		} else {
			atomic.AddUint64(&c_forwarded, 1)
		}
	}
}

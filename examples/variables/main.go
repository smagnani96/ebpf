// This program demonstrates interacting with global variables and constants defined
// in an eBPF program from the userspace. For the example, the program is attached
// to a network interface with XDP (eXpress Data Path).
// The program declares different types of variables:
//
//  1. __u64 pkt_count = 0: 								Initialized to zero -> .bss
//  2. __u32 another_pkt_count = 0: 						Initialized to zero -> .bss
//  3. __u32 random = 1:									Initialized to != 0 -> .data
//  4. char var_msg[] = "I can change :)":					Initialized to != 0	-> .data
//  5. const char const_msg[] = "I'm constant :)":			Constant variable 	-> .rodata
//  6. const char const_named_msg[] SEC(".rodata.named")
//     = "I'm constant and named :)"						Constant and Named -> .rodata.named
//  7. struct {...} map_pkt_count SEC(".maps")				Map PktCount
//
// The userspace program (Go code in this file) prints the contents of all the
// variables, while also changing the value of the `random` and `var_msg` variables.
// This example depends on bpf_link, available in Linux kernel version 5.7 or newer.
package main

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"text/tabwriter"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf xdp.c -- -I../headers
func main() {

	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	// Look up the network interface by name.
	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgFunc,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	// Mmap sections we want to directly access from userspace. Keep Rodata non mmap-ed for this example
	for _, v := range []*ebpf.Map{objs.Bss, objs.Rodata, objs.Data, objs.MapPktCount, objs.Rodatanamed} {
		if err := v.Mmap(0, 0); err != nil {
			log.Printf("Unable to mmap %s: %v", v.Name(), err)
		}
	}

	var (
		sb             strings.Builder
		bss            bpfBss
		data           bpfData
		rodata         bpfRodata
		rodataNamed    bpfRodatanamed
		mapPktCntValue uint64
		writer         = tabwriter.NewWriter(&sb, 1, 1, 1, ' ', 0)
	)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Load map_pkt_count variable (array map with 1 entry)
		if err = objs.MapPktCount.LoadAt(0, uint32(1), &mapPktCntValue); err != nil {
			log.Fatal(err)
		}
		fmt.Fprintf(writer, "MapPktCount:\t%20v\t", mapPktCntValue)

		// Load const_msg variable (from rodata section)
		if err = rodata.LoadConstMsg(objs.Rodata); err != nil {
			log.Fatal(err)
		}
		constMsgToSlice := rodata.ConstMsg[:]
		fmt.Fprintf(writer, "ConstMsg:\t%26s\t\n", *(*[]byte)(unsafe.Pointer(&constMsgToSlice)))

		// Load pkt_count variable (from bss section)
		if err = bss.LoadPktCount(objs.Bss); err != nil {
			log.Fatal(err)
		}
		fmt.Fprintf(writer, "PktCount:\t%20v\t", bss.PktCount)

		// Load var_msg variable (from data section)
		if err = data.LoadVarMsg(objs.Data); err != nil {
			log.Fatal(err)
		}
		varMsgToSlice := data.VarMsg[:]
		fmt.Fprintf(writer, "VarMsg:\t%26s\t\n", *(*[]byte)(unsafe.Pointer(&varMsgToSlice)))

		// Load random variable (from data section)
		if err = data.LoadRandom(objs.Data); err != nil {
			log.Fatal(err)
		}
		fmt.Fprintf(writer, "Random:\t%20v\t", data.Random)

		// Load const_named_msg variable (from rodata.named section)
		if err = rodataNamed.LoadConstNamedMsg(objs.Rodatanamed); err != nil {
			log.Fatal(err)
		}
		varNamedMsgToSlice := rodataNamed.ConstNamedMsg[:]
		fmt.Fprintf(writer, "VarNamedMsg:\t%26s\t\n", *(*[]byte)(unsafe.Pointer(&varNamedMsgToSlice)))

		// Update value of the random variable (data section)
		data.Random = rand.Uint32()
		if err = data.StoreRandom(objs.Data); err != nil {
			log.Fatal(err)
		}

		// Update last byte from var_msg variable (data section)
		data.VarMsg[len(data.VarMsg)-2] = (data.VarMsg[len(data.VarMsg)-2]+1)%2 + 40
		if err = data.StoreVarMsg(objs.Data); err != nil {
			log.Fatal(err)
		}

		writer.Flush()
		log.Printf("Variables Status:\n%s", sb.String())
		sb.Reset()
	}
}

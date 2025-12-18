package smb

import (
	"encoding/binary"
	"errors"
)

// Errors
var (
	ErrInvalidPacket = errors.New("invalid packet")
)

// SMB1 Commands
const (
	SMB_COM_NEGOTIATE          = 0x72
	SMB_COM_SESSION_SETUP_ANDX = 0x73
	SMB_COM_TREE_CONNECT_ANDX  = 0x75
	SMB_COM_ECHO               = 0x2B
)

// SMB1 Flags
const (
	SMB_FLAGS_CASE_INSENSITIVE = 0x08
	SMB_FLAGS_CANONICALIZED    = 0x10
	SMB_FLAGS_REPLY            = 0x80
)

// SMB1 Flags2
const (
	SMB_FLAGS2_LONG_NAMES        = 0x0001
	SMB_FLAGS2_EAS               = 0x0002
	SMB_FLAGS2_SECURITY_SIG      = 0x0004
	SMB_FLAGS2_IS_LONG_NAME      = 0x0040
	SMB_FLAGS2_EXTENDED_SECURITY = 0x0800
	SMB_FLAGS2_NT_STATUS         = 0x4000
	SMB_FLAGS2_UNICODE           = 0x8000
)

// SMB1 Capabilities
const (
	CAP_RAW_MODE           = 0x00000001
	CAP_MPX_MODE           = 0x00000002
	CAP_UNICODE            = 0x00000004
	CAP_LARGE_FILES        = 0x00000008
	CAP_NT_SMBS            = 0x00000010
	CAP_RPC_REMOTE_APIS    = 0x00000020
	CAP_STATUS32           = 0x00000040
	CAP_LEVEL_II_OPLOCKS   = 0x00000080
	CAP_LOCK_AND_READ      = 0x00000100
	CAP_NT_FIND            = 0x00000200
	CAP_DFS                = 0x00001000
	CAP_INFOLEVEL_PASSTHRU = 0x00002000
	CAP_LARGE_READX        = 0x00004000
	CAP_LARGE_WRITEX       = 0x00008000
	CAP_UNIX               = 0x00800000
	CAP_EXTENDED_SECURITY  = 0x80000000
)

// SMB1 Security Modes
const (
	SECURITY_MODE_USER_LEVEL                   = 0x01
	SECURITY_MODE_ENCRYPT_PASSWORDS            = 0x02
	SECURITY_MODE_SECURITY_SIGNATURES_ENABLED  = 0x04
	SECURITY_MODE_SECURITY_SIGNATURES_REQUIRED = 0x08
)

// SMB1Header represents an SMB1 protocol header
type SMB1Header struct {
	Protocol         [4]byte // 0xFF 'S' 'M' 'B'
	Command          uint8   // Command code
	Status           uint32  // NT Status code
	Flags            uint8   // Flags
	Flags2           uint16  // Flags2
	PIDHigh          uint16  // Process ID High
	SecurityFeatures [8]byte // Security features
	Reserved         uint16  // Reserved
	TID              uint16  // Tree ID
	PID              uint16  // Process ID
	UID              uint16  // User ID
	MID              uint16  // Multiplex ID
}

// ParseSMB1Header parses an SMB1 header from packet data
func ParseSMB1Header(data []byte) (*SMB1Header, error) {
	if len(data) < 32 {
		return nil, ErrInvalidPacket
	}

	header := &SMB1Header{}
	copy(header.Protocol[:], data[0:4])
	header.Command = data[4]
	header.Status = binary.LittleEndian.Uint32(data[5:9])
	header.Flags = data[9]
	header.Flags2 = binary.LittleEndian.Uint16(data[10:12])
	header.PIDHigh = binary.LittleEndian.Uint16(data[12:14])
	copy(header.SecurityFeatures[:], data[14:22])
	header.Reserved = binary.LittleEndian.Uint16(data[22:24])
	header.TID = binary.LittleEndian.Uint16(data[24:26])
	header.PID = binary.LittleEndian.Uint16(data[26:28])
	header.UID = binary.LittleEndian.Uint16(data[28:30])
	header.MID = binary.LittleEndian.Uint16(data[30:32])

	return header, nil
}

// BuildSMB1Header builds an SMB1 header as bytes
func BuildSMB1Header(header *SMB1Header) []byte {
	data := make([]byte, 32)

	copy(data[0:4], header.Protocol[:])
	data[4] = header.Command
	binary.LittleEndian.PutUint32(data[5:9], header.Status)
	data[9] = header.Flags
	binary.LittleEndian.PutUint16(data[10:12], header.Flags2)
	binary.LittleEndian.PutUint16(data[12:14], header.PIDHigh)
	copy(data[14:22], header.SecurityFeatures[:])
	binary.LittleEndian.PutUint16(data[22:24], header.Reserved)
	binary.LittleEndian.PutUint16(data[24:26], header.TID)
	binary.LittleEndian.PutUint16(data[26:28], header.PID)
	binary.LittleEndian.PutUint16(data[28:30], header.UID)
	binary.LittleEndian.PutUint16(data[30:32], header.MID)

	return data
}

package smb

import (
	"encoding/binary"
	"fmt"
)

// SMB2 Commands
const (
	SMB2_NEGOTIATE       = 0x0000
	SMB2_SESSION_SETUP   = 0x0001
	SMB2_LOGOFF          = 0x0002
	SMB2_TREE_CONNECT    = 0x0003
	SMB2_TREE_DISCONNECT = 0x0004
	SMB2_CREATE          = 0x0005
	SMB2_CLOSE           = 0x0006
	SMB2_FLUSH           = 0x0007
	SMB2_READ            = 0x0008
	SMB2_WRITE           = 0x0009
	SMB2_LOCK            = 0x000A
	SMB2_IOCTL           = 0x000B
	SMB2_CANCEL          = 0x000C
	SMB2_ECHO            = 0x000D
	SMB2_QUERY_DIRECTORY = 0x000E
	SMB2_CHANGE_NOTIFY   = 0x000F
	SMB2_QUERY_INFO      = 0x0010
	SMB2_SET_INFO        = 0x0011
	SMB2_OPLOCK_BREAK    = 0x0012
)

// SMB2 Dialects
const (
	SMB2_DIALECT_202 = 0x0202
	SMB2_DIALECT_210 = 0x0210
	SMB2_DIALECT_300 = 0x0300
	SMB2_DIALECT_302 = 0x0302
	SMB2_DIALECT_311 = 0x0311
)

// SMB2 Security Modes
const (
	SMB2_NEGOTIATE_SIGNING_ENABLED  = 0x0001
	SMB2_NEGOTIATE_SIGNING_REQUIRED = 0x0002
)

// SMB2 Capabilities
const (
	SMB2_GLOBAL_CAP_DFS                = 0x00000001
	SMB2_GLOBAL_CAP_LEASING            = 0x00000002
	SMB2_GLOBAL_CAP_LARGE_MTU          = 0x00000004
	SMB2_GLOBAL_CAP_MULTI_CHANNEL      = 0x00000008
	SMB2_GLOBAL_CAP_PERSISTENT_HANDLES = 0x00000010
	SMB2_GLOBAL_CAP_DIRECTORY_LEASING  = 0x00000020
	SMB2_GLOBAL_CAP_ENCRYPTION         = 0x00000040
)

// SMB2Header structure
type SMB2Header struct {
	ProtocolID    [4]byte
	StructureSize uint16
	CreditCharge  uint16
	Status        uint32
	Command       uint16
	CreditReqResp uint16
	Flags         uint32
	NextCommand   uint32
	MessageID     uint64
	Reserved      uint32
	TreeID        uint32
	SessionID     uint64
	Signature     [16]byte
}

// buildNegotiateResponse builds an SMB2 NEGOTIATE response
func buildNegotiateResponse(req *SMB2Header) []byte {
	// SPNEGO NegTokenInit with NTLMSSP OID to advertise NTLM support
	spnegoBlob := []byte{
		0x60, 0x48, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 0xa0, 0x3e,
		0x30, 0x3c, 0xa0, 0x0e, 0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
		0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, 0xa3, 0x2a, 0x30, 0x28, 0xa0, 0x26,
		0x1b, 0x24, 0x6e, 0x6f, 0x74, 0x5f, 0x64, 0x65, 0x66, 0x69, 0x6e, 0x65,
		0x64, 0x5f, 0x69, 0x6e, 0x5f, 0x52, 0x46, 0x43, 0x34, 0x31, 0x37, 0x38,
		0x40, 0x70, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x5f, 0x69, 0x67, 0x6e, 0x6f,
		0x72, 0x65,
	}

	response := make([]byte, 128+len(spnegoBlob))
	offset := 0

	// SMB2 Header
	copy(response[offset:offset+4], []byte{0xFE, 'S', 'M', 'B'})
	offset += 4
	binary.LittleEndian.PutUint16(response[offset:offset+2], 64)
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], 1)
	offset += 2
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0)
	offset += 4
	binary.LittleEndian.PutUint16(response[offset:offset+2], SMB2_NEGOTIATE)
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], 1)
	offset += 2
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0x00000001)
	offset += 4
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0)
	offset += 4
	binary.LittleEndian.PutUint64(response[offset:offset+8], req.MessageID)
	offset += 8
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0)
	offset += 4
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0)
	offset += 4
	binary.LittleEndian.PutUint64(response[offset:offset+8], 0)
	offset += 8
	offset += 16

	// SMB2 NEGOTIATE Response body
	binary.LittleEndian.PutUint16(response[offset:offset+2], 65)
	offset += 2
	// Security Mode - require signing to force NTLM authentication
	binary.LittleEndian.PutUint16(response[offset:offset+2], SMB2_NEGOTIATE_SIGNING_ENABLED|SMB2_NEGOTIATE_SIGNING_REQUIRED)
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], SMB2_DIALECT_210)
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], 0)
	offset += 2
	copy(response[offset:offset+16], make([]byte, 16))
	offset += 16
	binary.LittleEndian.PutUint32(response[offset:offset+4], SMB2_GLOBAL_CAP_DFS)
	offset += 4
	binary.LittleEndian.PutUint32(response[offset:offset+4], 65536)
	offset += 4
	binary.LittleEndian.PutUint32(response[offset:offset+4], 65536)
	offset += 4
	binary.LittleEndian.PutUint32(response[offset:offset+4], 65536)
	offset += 4
	binary.LittleEndian.PutUint64(response[offset:offset+8], 0)
	offset += 8
	binary.LittleEndian.PutUint64(response[offset:offset+8], 0)
	offset += 8
	// Security buffer offset and length
	binary.LittleEndian.PutUint16(response[offset:offset+2], 128) // offset to security blob
	offset += 2
	binary.LittleEndian.PutUint16(response[offset:offset+2], uint16(len(spnegoBlob)))
	offset += 2
	binary.LittleEndian.PutUint32(response[offset:offset+4], 0)

	// Append SPNEGO blob
	copy(response[128:], spnegoBlob)

	return response[0 : 128+len(spnegoBlob)]
}

// parseNegotiateRequest parses an SMB2 NEGOTIATE request
func parseNegotiateRequest(data []byte) (*SMB2Header, error) {
	if len(data) < 64 {
		return nil, fmt.Errorf("packet too short for SMB2 header")
	}

	header := &SMB2Header{}
	offset := 0

	copy(header.ProtocolID[:], data[offset:offset+4])
	offset += 4
	header.StructureSize = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2
	header.CreditCharge = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2
	header.Status = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4
	header.Command = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2
	header.CreditReqResp = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2
	header.Flags = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4
	header.NextCommand = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4
	header.MessageID = binary.LittleEndian.Uint64(data[offset : offset+8])
	offset += 8
	header.Reserved = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4
	header.TreeID = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4
	header.SessionID = binary.LittleEndian.Uint64(data[offset : offset+8])
	offset += 8
	copy(header.Signature[:], data[offset:offset+16])

	return header, nil
}

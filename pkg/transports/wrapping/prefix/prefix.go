package prefix

import (
	"bytes"
	"errors"
	"fmt"
	"net"

	"github.com/refraction-networking/conjure/pkg/core"
	"github.com/refraction-networking/conjure/pkg/transports"
	pb "github.com/refraction-networking/conjure/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	// Earliest client library version ID that supports destination port randomization
	randomizeDstPortMinVersion uint = 3

	// port range boundaries for prefix transport when randomizing
	portRangeMin = 1024
	portRangeMax = 65535
)

const minTagLength = 64

// const minTagLengthBase64 = 88

// prefix provides the elements required for independent prefixes to be usable as part of the
// transport used by the server specifically.
type prefix struct {
	// // Regular expression to match
	// *regexp.Regexp

	// // Function allowing decode / transformation of obfuscated ID bytes before attempting to
	// // de-obfuscate them. Example - base64 decode.
	// // [FUTURE WORK]
	// tagDecode func([]byte) ([]byte, int, error)

	// // Function allowing decode / transformation stream bytes before attempting to forward them.
	// // Example - base64 decode.
	// // [FUTURE WORK]
	// streamDecode func([]byte) ([]byte, int, error)

	// Static string to match to rule out protocols without using a regex.
	StaticMatch []byte

	// Offset in a byte array where we expect the identifier to start.
	Offset int

	// Minimum length to guarantee we have received the whole identifier
	// (i.e. return ErrTryAgain)
	MinLen int

	// Maximum length after which we can rule out prefix if we have not found a known identifier
	// (i.e. return ErrNotTransport)
	MaxLen int

	// Minimum client library version that supports this prefix
	MinVer uint

	// Default DST Port for this prefix. We are not bound by client_lib_version (yet) so we can set the
	// default destination port for each prefix individually
	DefaultDstPort uint16

	// Flush Indicates whether the client is expected to flush the write buffer after the prefix
	// before writing the tag. This would allow the whole first packet to be a prefix (with no tag).
	Flush int32
}

// PrefixID provide an integer Identifier for each individual prefixes allowing clients to indicate
// to the station the prefix they intend to connect with.
type PrefixID int

const (
	Rand PrefixID = -1 + iota
	Min
	GetLong
	PostLong
	HTTPResp
	TLSClientHello
	TLSServerHello
	TLSAlertWarning
	TLSAlertFatal
	DNSOverTCP
	OpenSSH2
	NewTLSClientHello
	FFTLSClientHello
	SMSNGClientHello

	// GetShortBase64
)

var (
	// ErrUnknownPrefix indicates that the provided Prefix ID is unknown to the transport object.
	ErrUnknownPrefix = errors.New("unknown / unsupported prefix")

	// ErrBadParams indicates that the parameters provided to a call on the server side do not make
	// sense in the context that they are provided and the registration will be ignored.
	ErrBadParams = errors.New("bad parameters provided")

	// ErrIncorrectPrefix indicates that tryFindRegistration found a valid registration based on
	// the obfuscated tag, however the prefix that it matched was not the prefix indicated in the
	// registration.
	ErrIncorrectPrefix = errors.New("found connection for unexpected prefix")

	// ErrIncorrectTransport indicates that tryFindRegistration found a valid registration based on
	// the obfuscated tag, however the prefix that it matched was not the prefix indicated in the
	// registration.
	ErrIncorrectTransport = errors.New("found registration w/ incorrect transport type")
)

// Name returns the human-friendly name of the prefix.
func (id PrefixID) Name() string {
	switch id {
	case Min:
		return "Min"
	case GetLong:
		return "GetLong"
	case PostLong:
		return "PostLong"
	case HTTPResp:
		return "HTTPResp"
	case TLSClientHello:
		return "TLSClientHello"
	case TLSServerHello:
		return "TLSServerHello"
	case TLSAlertWarning:
		return "TLSAlertWarning"
	case TLSAlertFatal:
		return "TLSAlertFatal"
	case DNSOverTCP:
		return "DNSOverTCP"
	case OpenSSH2:
		return "OpenSSH2"
	case NewTLSClientHello:
		return "NewTLSClientHello"
	case FFTLSClientHello:
		return "FFTLSClientHello"
	case SMSNGClientHello:
		return "SMSNGClientHello"

	// case GetShort:
	// 	return "GetShort"
	default:
		return "other"
	}
}

// defaultPrefixes provides the prefixes supported by default for use when
// initializing the prefix transport.
var defaultPrefixes = map[PrefixID]prefix{
	//Min - Empty prefix
	Min: {[]byte{}, 0, minTagLength, minTagLength, randomizeDstPortMinVersion, 443, NoAddedFlush},
	// HTTP GET
	GetLong: {[]byte("GET / HTTP/1.1\r\n"), 16, 16 + minTagLength, 16 + minTagLength, randomizeDstPortMinVersion, 80, FlushAfterPrefix},
	// HTTP POST
	PostLong: {[]byte("POST / HTTP/1.1\r\n"), 17, 17 + minTagLength, 17 + minTagLength, randomizeDstPortMinVersion, 80, NoAddedFlush},
	// HTTP Response
	HTTPResp: {[]byte("HTTP/1.1 200\r\n"), 14, 14 + minTagLength, 14 + minTagLength, randomizeDstPortMinVersion, 80, NoAddedFlush},
	// TLS Client Hello
	TLSClientHello: {[]byte("\x16\x03\x03\x40\x00\x01"), 6, 6 + minTagLength, 6 + minTagLength, randomizeDstPortMinVersion, 443, NoAddedFlush},
	// TLS Server Hello
	TLSServerHello: {[]byte("\x16\x03\x03\x40\x00\x02\r\n"), 8, 8 + minTagLength, 8 + minTagLength, randomizeDstPortMinVersion, 443, NoAddedFlush},
	// TLS Alert Warning
	TLSAlertWarning: {[]byte("\x15\x03\x01\x00\x02"), 5, 5 + minTagLength, 5 + minTagLength, randomizeDstPortMinVersion, 443, NoAddedFlush},
	// TLS Alert Fatal
	TLSAlertFatal: {[]byte("\x15\x03\x02\x00\x02"), 5, 5 + minTagLength, 5 + minTagLength, randomizeDstPortMinVersion, 443, NoAddedFlush},
	// DNS over TCP
	DNSOverTCP: {[]byte("\x05\xDC\x5F\xE0\x01\x20"), 6, 6 + minTagLength, 6 + minTagLength, randomizeDstPortMinVersion, 53, NoAddedFlush},
	// SSH-2.0-OpenSSH_8.9p1
	OpenSSH2: {[]byte("SSH-2.0-OpenSSH_8.9p1"), 21, 21 + minTagLength, 21 + minTagLength, randomizeDstPortMinVersion, 22, NoAddedFlush},
	// New TLS Client Hello
	NewTLSClientHello: {[]byte("\x16\x03\x00\x00\x97\x01\x00\x00\x93\x03\x03\x66\x8f\x07\xd4\x1c\xbf\x82\x79\x9d\x2c\x87\x08\xf5\x9d\x83\xfa\xab\x0a\xff\x33\x4e\x0c\x35\x6d\x40\x80\xe1\x9f\x4c\xc3\x83\x44\x00\x00\x24\x13\x01\x13\x03\x13\x02\xc0\x2b\xc0\x2f\xcc\xa9\xcc\xa8\xc0\x2c\xc0\x30\xc0\x0a\xc0\x09\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35\x00\x0a\x02\x01\x00\x00\x45\x00\x00\x00\x13\x00\x11\x00\x00\x0e\x64\x75\x63\x6b\x64\x75\x63\x6b\x67\x6f\x2e\x63\x6f\x6d\x00\x0d\x00\x18\x00\x16\x04\x03\x05\x03\x06\x03\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x02\x03\x02\x01\x00\x0a\x00\x0e\x00\x0c\x00\x1d\x00\x17\x00\x18\x00\x19\x01\x00\x01\x01"), 156, 156 + minTagLength, 156 + minTagLength, randomizeDstPortMinVersion, 443, FlushAfterPrefix},
	FFTLSClientHello: {[]byte("\x16\x03\x01\x02\x91\x01\x00\x02\x8d\x03\x03\x95\x91\x9a\xaa\x09\xc1\xee\xc6\xa6\x78\x1a\x41\xf6\xd2\x31\xa5\xb0\xed\x66\x00\x80\x5c\x40\x21\x3d\x4f\xe2\x69\x1e\x1b\x51\x72\x20\xef\x80\x1a\xc4\xcd\x8e\x7c\x42\xe8\x60\x7a\xbb\xb1\x83\xb4\x59\x09\xf6\x5c\x5c\xdc\x38\x78\x99\xd6\x25\x07\x70\x8e\xa9\xfa\x6c\x00\x22\x13\x01\x13\x03\x13\x02\xc0\x2b\xc0\x2f\xcc\xa9\xcc\xa8\xc0\x2c\xc0\x30\xc0\x0a\xc0\x09\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35\x01\x00\x02\x22\x00\x00\x00\x13\x00\x11\x00\x00\x0e\x64\x75\x63\x6b\x64\x75\x63\x6b\x67\x6f\x2e\x63\x6f\x6d\x00\x17\x00\x00\xff\x01\x00\x01\x00\x00\x0a\x00\x0e\x00\x0c\x00\x1d\x00\x17\x00\x18\x00\x19\x01\x00\x01\x01\x00\x0b\x00\x02\x01\x00\x00\x23\x00\x00\x00\x10\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\x22\x00\x0a\x00\x08\x04\x03\x05\x03\x06\x03\x02\x03\x00\x33\x00\x6b\x00\x69\x00\x1d\x00\x20\xeb\x9f\x93\x31\x51\xab\x3b\xf7\xab\x37\xe0\x90\xdc\xf1\x9d\x77\x90\xf8\x9e\x8e\x3f\x15\xcb\xe4\xa0\xf2\xf1\x47\x5f\x52\x0c\x16\x00\x17\x00\x41\x04\xe9\xc9\x06\x46\xc6\xd8\x62\xa0\x7e\x50\xfd\x66\x2e\x01\x1d\x81\xcd\x9e\x61\x64\x3b\x92\x21\xf0\xbc\xd0\x7a\xa0\x49\x28\x6e\x40\xcc\xb4\x70\x69\x46\x02\x1b\x00\x58\xfe\x4a\x62\x3b\x4c\x48\xb5\xee\xf5\x7c\xc9\x76\xbe\x42\x5a\x43\x38\x88\x8f\xc1\x2d\x14\x8e\x00\x2b\x00\x05\x04\x03\x04\x03\x03\x00\x0d\x00\x18\x00\x16\x04\x03\x05\x03\x06\x03\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x02\x03\x02\x01\x00\x2d\x00\x02\x01\x01\x00\x1c\x00\x02\x40\x01\xfe\x0d\x01\x19\x00\x00\x01\x00\x01\x13\x00\x20\xba\xe1\x22\xe0\xb7\x18\x9b\xf6\xeb\x1b\xb2\x33\xb1\x40\x1b\xb0\xd6\xfd\x06\xc3\xea\xb6\x77\xb9\xc4\xe8\xb0\x07\xf2\x78\x0c\x87\x00\xef\x9c\x9c\x09\xc1\xc5\x59\x6e\x83\xfa\xbb\x4e\x02\x94\x5d\xfd\x8d\x78\xfb\x1e\xfe\x2e\xc1\xc7\xee\x02\x26\xdd\x89\x9b\xc0\xc3\x44\x5a\x3e\x46\x77\x65\xbc\x93\x62\xd6\x43\x40\x82\x88\x05\x0e\xdb\xa5\xcb\x56\xfc\x42\x62\x39\xd1\xb6\x68\x4c\xfe\x18\xb2\x41\x19\x9b\xc5\x60\x2e\xb4\x21\xbd\xe6\x7e\xa1\x5a\xec\x32\x30\x0b\x6a\x82\xc2\x36\x0f\x6e\xcf\x0f\x9d\x4e\xd4\xd0\x87\x39\x4d\x74\x8e\x8b\x52\x32\xf8\x31\xe8\x5c\xfe\x07\x84\xb7\x56\x93\x44\xb7\x82\xff\xac\xad\xef\x0d\x2a\xaf\x0b\xd6\xb2\x43\x43\xba\x9d\x2f\x54\x90\xf0\xf1\x33\x3d\x5b\x42\x1b\x65\x0c\xc8\xb8\x12\xc1\x5d\x7e\x75\x27\x24\xbb\x82\xd8\xf2\x96\x52\xfb\xfd\x78\xa4\x3e\x82\x9e\x42\xb1\x91\x15\xd7\x2f\x14\xcf\x8d\xd4\xc9\x21\x53\xd6\xb7\x75\x45\xf8\x01\x1d\x29\x47\xd1\xb6\x5e\x36\x1c\x62\xbf\x8b\x87\x46\x8a\x87\xc2\x22\xa2\x79\x5d\x6a\x5f\x15\x5d\xf2\x25\xf4\x45\xb3\xc9\x16\x23\xf6\xaa\x1e\xff\x31\x57\x35\xc9\xe4\x7d\x4a\x96\xb8\x31\xae\x32\x3d\xee\xbf\x94\x2a\x11\x64\x1b\x4c\x3c\xb8\xb8"), 662, 662 + minTagLength, 662 + minTagLength, randomizeDstPortMinVersion, 443, FlushAfterPrefix},
	SMSNGClientHello: {[]byte("\x16\x03\x01\x02\x31\x01\x00\x02\x2d\x03\x03\x1d\x10\xa5\xfb\xd3\x31\xed\xf1\x1c\x63\xd9\xdc\x99\x29\xcd\x8a\x88\x60\xe5\x06\x0c\x1c\xca\xca\xf0\x1c\x00\xb2\x1a\x87\xcc\x81\x20\x38\x00\x83\x45\xe0\x44\xe7\x34\x27\x9d\x5f\x46\xbd\x47\x8a\x23\x6b\xfe\x3f\xc7\xc3\x5e\x9c\xff\x98\xf1\x4a\xbb\x2c\x3f\x7f\xdb\x00\x20\x9a\x9a\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30\xcc\xa9\xcc\xa8\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35\x01\x00\x01\xc4\xca\xca\x00\x00\x00\x0b\x00\x02\x01\x00\x00\x33\x00\x2b\x00\x29\x5a\x5a\x00\x01\x00\x00\x1d\x00\x20\x47\x67\x6f\x31\xc6\x1d\x8d\x13\xc8\x67\xa6\xa5\x7b\xcb\xb0\xac\x9c\xee\xbd\x2a\x7a\xb3\xe6\xa8\xc0\xdb\x04\x59\x3f\x43\x21\x48\x00\x0d\x00\x12\x00\x10\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x00\x10\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31\xff\x01\x00\x01\x00\x00\x12\x00\x00\x00\x17\x00\x00\x00\x0a\x00\x0a\x00\x08\x5a\x5a\x00\x1d\x00\x17\x00\x18\x00\x2d\x00\x02\x01\x01\x00\x00\x00\x13\x00\x11\x00\x00\x0e\x64\x75\x63\x6b\x64\x75\x63\x6b\x67\x6f\x2e\x63\x6f\x6d\x44\x69\x00\x05\x00\x03\x02\x68\x32\x00\x1b\x00\x03\x02\x00\x02\x00\x2b\x00\x07\x06\x3a\x3a\x03\x04\x03\x03\x00\x23\x00\x00\xfe\x0d\x00\xfa\x00\x00\x01\x00\x01\xda\x00\x20\x60\xbf\x64\xe7\x01\x71\xba\xe4\xac\x6e\x96\xc3\xca\x35\x2b\x76\x12\x38\xad\x40\x9c\x97\xc3\x20\x1d\xba\x9e\xb5\x56\xa2\xd3\x00\x00\xd0\xc5\xe4\x7f\xcc\x52\x65\xef\x44\x79\xc9\xd8\x64\xf2\x69\xfe\x94\x8d\x45\x88\x45\x36\xf4\xa6\x42\x07\xbc\xbe\x39\x92\x93\xee\x0c\x1f\x6b\x32\x75\x94\x83\x6b\xb3\x2f\xd0\xa6\x9e\xe2\xb4\x41\xc2\x03\x86\x12\x88\x9b\xe7\x26\xac\x45\x3e\x06\x9e\x99\x3c\x12\x02\x51\xbe\x4d\xb0\xbf\x3f\x2f\x34\x0c\xeb\xe8\x40\x76\x6e\x13\xfb\xe4\x23\xb8\x72\x74\x1c\x38\xd3\x52\x8b\x02\x9d\xfd\xbf\x69\x3c\xa2\x15\x7d\xf4\xd2\xd8\xca\x25\xae\x4a\x41\x6e\x10\xfb\xe5\xb7\x53\x3a\x47\x65\x19\xc3\xd6\x80\x9c\xf5\x41\x03\x34\xb6\x2a\xc9\x74\x09\x72\x84\x1f\x4e\x4c\xf6\x74\xe4\x28\x0c\x9b\x20\x06\xab\xb1\xf9\x5b\xd2\x11\xc1\x64\x8d\x96\xbd\xde\x4b\xfc\x0c\x5a\x9d\x3d\x29\x62\xbb\x5b\x12\xe5\x25\x0b\x63\x59\xab\x24\xe5\xe6\x3f\x06\x76\xf4\xc2\x3d\x0e\x6d\x13\xb0\x51\xae\x78\xee\xd5\x90\xfa\x14\x8b\x12\x3c\xe6\x89\xc4\xf1\xc9\xa5\xaf\x67\xfb\x37\x88\x95\x00\x05\x00\x05\x01\x00\x00\x00\x00\x0a\x0a\x00\x01\x00"), 566, 566 + minTagLength, 566 + minTagLength, randomizeDstPortMinVersion, 443, FlushAfterPrefix},

	// // HTTP GET base64 in url min tag length 88 because 64 bytes base64 encoded should be length 88
	// GetShort: {base64TagDecode, []byte("GET /"), 5, 5 + 88, 5 + 88, randomizeDstPortMinVersion},
}

// Transport provides a struct implementing the Transport, WrappingTransport,
// PortRandomizingTransport, and FixedPortTransport interfaces.
type Transport struct {
	SupportedPrefixes map[PrefixID]prefix
	TagObfuscator     transports.Obfuscator
	Privkey           [32]byte
}

// Name returns the human-friendly name of the transport, implementing the
// Transport interface..
func (Transport) Name() string { return "PrefixTransport" }

// LogPrefix returns the prefix used when including this transport in logs,
// implementing the Transport interface.
func (Transport) LogPrefix() string { return "PREF" }

// GetIdentifier takes in a registration and returns an identifier for it. This
// identifier should be unique for each registration on a given phantom;
// registrations on different phantoms can have the same identifier.
func (Transport) GetIdentifier(d transports.Registration) string {
	return string(core.ConjureHMAC(d.SharedSecret(), "PrefixTransportHMACString"))
}

// GetProto returns the next layer protocol that the transport uses. Implements
// the Transport interface.
func (Transport) GetProto() pb.IPProto {
	return pb.IPProto_Tcp
}

// ParseParams gives the specific transport an option to parse a generic object into parameters
// provided by the client during registration. This Transport was written after RandomizeDstPort was
// added, so it should not be usable by clients who don't support destination port randomization.
func (t Transport) ParseParams(libVersion uint, data *anypb.Any) (any, error) {
	if data == nil {
		return nil, nil
	}

	if libVersion < randomizeDstPortMinVersion {
		return nil, fmt.Errorf("client couldn't support this transport")
	}

	var m = &pb.PrefixTransportParams{}
	err := transports.UnmarshalAnypbTo(data, m)

	// Check if this is a prefix that we know how to parse, if not, drop the registration because
	// we will be unable to pick up.
	if _, ok := t.SupportedPrefixes[PrefixID(m.GetPrefixId())]; !ok {
		return nil, fmt.Errorf("%w: %d", ErrUnknownPrefix, m.GetPrefixId())
	}

	return m, err
}

// ParamStrings returns an array of tag string that will be added to tunStats when a proxy session
// is closed.
func (t Transport) ParamStrings(p any) []string {
	params, ok := p.(*pb.PrefixTransportParams)
	if !ok {
		return nil
	}

	out := []string{PrefixID(params.GetPrefixId()).Name()}

	return out
}

// GetDstPort Given the library version, a seed, and a generic object
// containing parameters the transport should be able to return the
// destination port that a clients phantom connection will attempt to reach
func (t Transport) GetDstPort(libVersion uint, seed []byte, params any) (uint16, error) {

	if libVersion < randomizeDstPortMinVersion {
		return 0, fmt.Errorf("client couldn't support this transport")
	}
	parameters, ok := params.(*pb.PrefixTransportParams)
	if !ok {
		return 0, fmt.Errorf("%w: incorrect type", ErrBadParams)
	}

	if parameters == nil {
		return 0, fmt.Errorf("%w: nil params", ErrBadParams)
	}

	prefix := parameters.GetPrefixId()
	p, ok := t.SupportedPrefixes[PrefixID(prefix)]
	if !ok {
		return 0, ErrUnknownPrefix
	}

	if parameters.GetRandomizeDstPort() {
		return transports.PortSelectorRange(portRangeMin, portRangeMax, seed)
	}

	return p.DefaultDstPort, nil
}

// WrapConnection attempts to wrap the given connection in the transport. It
// takes the information gathered so far on the connection in data, attempts to
// identify itself, and if it positively identifies itself wraps the connection
// in the transport, returning a connection that's ready to be used by others.
//
// If the returned error is nil or non-nil and non-{ transports.ErrTryAgain,
// transports.ErrNotTransport }, the caller may no longer use data or conn.
func (t Transport) WrapConnection(data *bytes.Buffer, c net.Conn, originalDst net.IP, regManager transports.RegManager) (transports.Registration, net.Conn, error) {
	if data.Len() < minTagLength {
		return nil, nil, transports.ErrTryAgain
	}

	reg, err := t.tryFindReg(data, originalDst, regManager)
	if err != nil {
		return nil, nil, err
	}

	return reg, transports.PrependToConn(c, data), nil
}

func (t Transport) tryFindReg(data *bytes.Buffer, originalDst net.IP, regManager transports.RegManager) (transports.Registration, error) {
	if data.Len() == 0 {
		return nil, transports.ErrTryAgain
	}

	var eWrongPrefix error = nil
	err := transports.ErrNotTransport
	for id, prefix := range t.SupportedPrefixes {
		if len(prefix.StaticMatch) > 0 {
			matchLen := min(len(prefix.StaticMatch), data.Len())
			if !bytes.Equal(prefix.StaticMatch[:matchLen], data.Bytes()[:matchLen]) {
				continue
			}
		}

		if data.Len() < prefix.MinLen {
			// the data we have received matched at least one static prefix, but was not long
			// enough to extract the tag - go back and read more, continue checking if any
			// of the other prefixes match. If not we want to indicate to read more, not
			// give up because we may receive the rest of the match.
			err = transports.ErrTryAgain
			continue
		}

		if data.Len() < prefix.Offset+minTagLength && data.Len() < prefix.MaxLen {
			err = transports.ErrTryAgain
			continue
		} else if data.Len() < prefix.MaxLen {
			continue
		}

		var obfuscatedID []byte
		var forwardBy = minTagLength
		// var errN error
		// if prefix.fn != nil {
		// 	obfuscatedID, forwardBy, errN = prefix.tagDecode(data.Bytes()[prefix.Offset:])
		// 	if errN != nil || len(obfuscatedID) != minTagLength {
		// 		continue
		// 	}
		// } else {
		obfuscatedID = data.Bytes()[prefix.Offset : prefix.Offset+minTagLength]
		// }

		hmacID, err := t.TagObfuscator.TryReveal(obfuscatedID, t.Privkey)
		if err != nil || hmacID == nil {
			continue
		}

		reg, ok := regManager.GetRegistrations(originalDst)[string(hmacID)]
		if !ok {
			continue
		}

		if reg.TransportType() != pb.TransportType_Prefix {
			return nil, ErrIncorrectTransport
		} else if params, ok := reg.TransportParams().(*pb.PrefixTransportParams); ok {
			if params == nil || params.GetPrefixId() != int32(id) {
				// If the registration we found has no params specified (invalid and shouldn't have
				// been ingested) or if the prefix ID does not match the expected prefix, set the
				// err to return if we can't match any other prefixes.
				eWrongPrefix = fmt.Errorf("%w: e %d != %d", ErrIncorrectPrefix, params.GetPrefixId(), id)
				continue
			}
		}

		// We don't want to forward the prefix or Tag bytes, but if any message
		// remains we do want to forward it.
		data.Next(prefix.Offset + forwardBy)

		return reg, nil
	}

	if errors.Is(err, transports.ErrNotTransport) && errors.Is(eWrongPrefix, ErrIncorrectPrefix) {
		// If we found a match and it was the only one that matched (i.e. none of the other prefixes
		// could possibly match even if we read more bytes). Then something went wrong and the
		// client is attempting to connect with the wrong prefix.
		return nil, ErrIncorrectPrefix
	}

	return nil, err
}

// New Given a private key this builds the server side transport with an EMPTY set of supported
// prefixes. The optional filepath specifies a file from which to read extra prefixes. If provided
// only the first variadic string will be used to attempt to parse prefixes. There can be no
// colliding PrefixIDs - within the file first defined takes precedence.
func New(privkey [32]byte, filepath ...string) (*Transport, error) {
	var prefixes map[PrefixID]prefix = make(map[PrefixID]prefix)
	var err error
	if len(filepath) > 0 && filepath[0] != "" {
		prefixes, err = tryParsePrefixes(filepath[0])
		if err != nil {
			return nil, err
		}
	}
	return &Transport{
		Privkey:           privkey,
		SupportedPrefixes: prefixes,
		TagObfuscator:     transports.CTRObfuscator{},
	}, nil
}

// Default Given a private key this builds the server side transport with the DEFAULT set of supported
// prefixes. The optional filepath specifies a file from which to read extra prefixes.
// If provided only the first variadic string will be used to attempt to parse prefixes. There can
// be no colliding PrefixIDs - file defined prefixes take precedent over defaults, and within the
// file first defined takes precedence.
func Default(privkey [32]byte, filepath ...string) (*Transport, error) {
	t, err := New(privkey, filepath...)
	if err != nil {
		return nil, err
	}

	for k, v := range defaultPrefixes {
		if _, ok := t.SupportedPrefixes[k]; !ok {
			t.SupportedPrefixes[k] = v
		}
	}
	return t, nil
}

// DefaultSet builds a hollow version of the transport with the DEFAULT set of supported
// prefixes. This is useful in instances where we just need to check whether the prefix ID is known,
// not actually handle any major operations (tryFindReg / WrapConn)
func DefaultSet() *Transport {
	var prefixes map[PrefixID]prefix = make(map[PrefixID]prefix)
	for k, v := range defaultPrefixes {
		if _, ok := prefixes[k]; !ok {
			prefixes[k] = v
		}
	}
	return &Transport{
		SupportedPrefixes: prefixes,
	}
}

func tryParsePrefixes(filepath string) (map[PrefixID]prefix, error) {
	return nil, nil
}

func applyDefaultPrefixes() {
	// if at any point we need to do init on the prefixes (i.e compiling regular expressions) it
	// should happen here.
	for ID, p := range defaultPrefixes {
		DefaultPrefixes[ID] = &clientPrefix{p.StaticMatch, ID, p.DefaultDstPort, p.Flush}
	}
}

func init() {
	applyDefaultPrefixes()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// func base64TagDecode(encoded []byte) ([]byte, int, error) {
// 	if len(encoded) < minTagLengthBase64 {
// 		return nil, 0, fmt.Errorf("not enough to decode")
// 	}
// 	buf := make([]byte, minTagLengthBase64)
// 	n, err := base64.StdEncoding.Decode(buf, encoded[:minTagLengthBase64])
// 	if err != nil {
// 		return nil, 0, err
// 	}

// 	return buf[:n], minTagLengthBase64, nil
// }

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
	FFTLSClientHello: {[]byte("\x16\x03\x01\x02\x92\x01\x00\x02\x8e\x03\x03\xf7\x83\x54\xee\x99\x18\x93\xfe\x7d\x85\x73\x0e\xfd\xf4\xfa\xfb\x37\x20\x27\xa2\xdf\x0a\x2e\x3a\xb4\xb1\xfa\x53\x9d\xc6\x39\x41\x20\x51\xd4\x28\x16\xaf\xc7\x5a\x58\xd5\x5a\xcd\xdb\xd8\xcc\xc6\xc1\xf8\x18\x3f\xe1\xc0\xca\xf8\x32\xe6\x97\x91\xe4\x81\x47\x80\xc1\x00\x22\x13\x01\x13\x03\x13\x02\xc0\x2b\xc0\x2f\xcc\xa9\xcc\xa8\xc0\x2c\xc0\x30\xc0\x0a\xc0\x09\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35\x01\x00\x02\x23\x00\x00\x00\x14\x00\x12\x00\x00\x0f\x77\x77\x77\x2e\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d\x00\x17\x00\x00\xff\x01\x00\x01\x00\x00\x0a\x00\x0e\x00\x0c\x00\x1d\x00\x17\x00\x18\x00\x19\x01\x00\x01\x01\x00\x0b\x00\x02\x01\x00\x00\x23\x00\x00\x00\x10\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\x22\x00\x0a\x00\x08\x04\x03\x05\x03\x06\x03\x02\x03\x00\x33\x00\x6b\x00\x69\x00\x1d\x00\x20\xd1\x06\x46\xd1\x79\xb6\xb0\x34\x5b\xa2\x36\xc1\xd5\x42\xeb\x2d\x12\x02\xc7\x12\x5c\x5f\x39\x0f\xd8\x57\xec\xb5\x96\x8d\xe2\x20\x00\x17\x00\x41\x04\xfc\xd1\xa9\x84\x4a\x5d\x82\x9e\x8d\x4e\xdb\xd2\xc6\xdc\x7b\xc0\x2a\x95\x92\xb7\xed\x05\x1a\xea\xb5\xd3\x65\x79\x77\x81\xd8\xc0\x50\x9c\x0b\x9a\x84\x91\x2f\xdd\x8b\xaf\xe7\x3e\xe9\xdb\xb5\xb4\xd1\x93\xc0\x1d\x94\xa1\xff\x06\x8e\x7d\x7b\x9c\x84\xb9\x8c\xd3\x00\x2b\x00\x05\x04\x03\x04\x03\x03\x00\x0d\x00\x18\x00\x16\x04\x03\x05\x03\x06\x03\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x02\x03\x02\x01\x00\x2d\x00\x02\x01\x01\x00\x1c\x00\x02\x40\x01\xfe\x0d\x01\x19\x00\x00\x01\x00\x03\xc4\x00\x20\x1b\x12\x3a\xde\x4c\xce\x5c\x5f\x82\x63\x7d\x36\xf1\xb4\x88\x5f\x69\xe4\x4e\x01\x4d\x78\xff\xae\x6f\xaa\x77\x0e\x6e\x3d\x8a\xd8\x00\xef\xab\x4e\xc0\xa5\x11\xcc\xb9\x27\x46\xcd\x4f\x41\x18\x7a\xdf\x0c\x6b\x7b\xed\xfb\x10\x89\xde\x8d\xf7\x9d\xb3\x3b\xbd\xf9\xa3\xb0\x19\xb9\xc7\x89\x5c\x69\x81\x6e\xa3\x7c\x81\x8b\x54\xca\x57\xb0\x90\xa1\x41\x8b\xef\xc3\xc1\x5e\xba\x21\xec\x69\xe8\x32\x54\x2b\x65\x85\xaa\xe1\x95\x4b\xaa\x7d\xda\xaa\x08\x50\xd5\xc3\x9e\xe8\x68\x10\x40\x6a\xb4\x88\x14\x70\xa5\xb7\x5a\x44\x4d\xf8\x43\x63\x2a\xdb\x29\x60\xfd\x76\x07\x85\x94\x85\x84\x2d\x74\xdf\x4a\x44\x69\xc6\x04\x85\x09\xf5\x33\x52\x16\x5f\xd7\x34\x06\x84\x71\x85\x41\xc8\xec\x1d\x9c\x49\xca\x2a\x0d\xab\x49\xfc\x73\xde\x16\x3f\xf9\x3f\x7b\xa6\xb3\xb1\x14\x49\xa8\xd2\xa2\x7e\x3c\xbd\x4b\xa4\x1d\x97\x5f\x78\x66\x52\x9f\xf5\x1d\xee\x17\x61\xb1\x2d\xe2\x96\x0d\x6e\x6a\xa0\x8c\xf3\x22\xb0\x61\x8a\x52\x98\xb6\x84\xa8\x5f\x19\x71\xf5\x75\xb6\xb2\xa1\x96\xa1\x51\x62\x48\xfd\x83\x28\xfd\x80\x31\xfa\x5e\x0c\x7f\xce\x03\x94\x0a\xa0\x5a\xc5\x06\x47\xd4\x6f\x70\xba\x76\x7f\xc2\x82\xb7\x57\x1e\xa0\x56\x27\x3d\xc4"), 663, 663 + minTagLength, 663 + minTagLength, randomizeDstPortMinVersion, 443, FlushAfterPrefix},

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

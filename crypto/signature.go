package crypto

import (
	"errors"
	"math/big"

	"github.com/xtaci/hppk"
	"github.com/xtaci/qsh/protocol"
)

// SignatureToProto converts an HPPK signature into its protobuf equivalent.
func SignatureToProto(sig *hppk.Signature) *protocol.Signature {
	if sig == nil {
		return nil
	}
	msg := &protocol.Signature{
		Beta:     bigIntToBytes(sig.Beta),
		F:        bigIntToBytes(sig.F),
		H:        bigIntToBytes(sig.H),
		S1Verify: bigIntToBytes(sig.S1Verify),
		S2Verify: bigIntToBytes(sig.S2Verify),
		K:        uint32(sig.K),
	}
	if len(sig.U) > 0 {
		msg.U = make([][]byte, len(sig.U))
		for i, v := range sig.U {
			msg.U[i] = bigIntToBytes(v)
		}
	}
	if len(sig.V) > 0 {
		msg.V = make([][]byte, len(sig.V))
		for i, v := range sig.V {
			msg.V[i] = bigIntToBytes(v)
		}
	}
	return msg
}

// SignatureFromProto rebuilds an HPPK signature from protobuf bytes.
func SignatureFromProto(msg *protocol.Signature) (*hppk.Signature, error) {
	if msg == nil {
		return nil, errors.New("missing signature payload")
	}
	sig := &hppk.Signature{
		Beta:     bytesToBigInt(msg.Beta),
		F:        bytesToBigInt(msg.F),
		H:        bytesToBigInt(msg.H),
		S1Verify: bytesToBigInt(msg.S1Verify),
		S2Verify: bytesToBigInt(msg.S2Verify),
		K:        int(msg.K),
	}
	if len(msg.U) != len(msg.V) {
		return nil, errors.New("signature: mismatched vector lengths")
	}
	if len(msg.U) > 0 {
		sig.U = make([]*big.Int, len(msg.U))
		sig.V = make([]*big.Int, len(msg.V))
		for i := range msg.U {
			sig.U[i] = bytesToBigInt(msg.U[i])
			sig.V[i] = bytesToBigInt(msg.V[i])
		}
	}
	return sig, nil
}

// bigIntToBytes safely serializes a big integer.
func bigIntToBytes(v *big.Int) []byte {
	if v == nil {
		return nil
	}
	return v.Bytes()
}

// bytesToBigInt produces a big.Int even for nil/empty inputs.
func bytesToBigInt(data []byte) *big.Int {
	if len(data) == 0 {
		return big.NewInt(0)
	}
	return new(big.Int).SetBytes(data)
}

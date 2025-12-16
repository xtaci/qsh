package protocol

import "github.com/golang/protobuf/proto"

// Envelope is the outer message exchanged between client and server.
type Envelope struct {
	ClientHello   *ClientHello   `protobuf:"bytes,1,opt,name=client_hello,json=clientHello,proto3" json:"client_hello,omitempty"`
	AuthChallenge *AuthChallenge `protobuf:"bytes,2,opt,name=auth_challenge,json=authChallenge,proto3" json:"auth_challenge,omitempty"`
	AuthResponse  *AuthResponse  `protobuf:"bytes,3,opt,name=auth_response,json=authResponse,proto3" json:"auth_response,omitempty"`
	AuthResult    *AuthResult    `protobuf:"bytes,4,opt,name=auth_result,json=authResult,proto3" json:"auth_result,omitempty"`
	SecureData    *SecureData    `protobuf:"bytes,5,opt,name=secure_data,json=secureData,proto3" json:"secure_data,omitempty"`
}

func (m *Envelope) Reset()         { *m = Envelope{} }
func (m *Envelope) String() string { return proto.CompactTextString(m) }
func (*Envelope) ProtoMessage()    {}

// ClientHello identifies the connecting client.
type ClientHello struct {
	ClientId string     `protobuf:"bytes,1,opt,name=client_id,json=clientId,proto3" json:"client_id,omitempty"`
	Mode     ClientMode `protobuf:"varint,2,opt,name=mode,proto3,enum=qsh.protocol.ClientMode" json:"mode,omitempty"`
}

func (m *ClientHello) Reset()         { *m = ClientHello{} }
func (m *ClientHello) String() string { return proto.CompactTextString(m) }
func (*ClientHello) ProtoMessage()    {}

type ClientMode int32

const (
	ClientMode_CLIENT_MODE_SHELL ClientMode = 0
	ClientMode_CLIENT_MODE_COPY  ClientMode = 1
)

// AuthChallenge carries the random challenge and encrypted session key.
type AuthChallenge struct {
	Challenge      []byte `protobuf:"bytes,1,opt,name=challenge,proto3" json:"challenge,omitempty"`
	KemP           []byte `protobuf:"bytes,2,opt,name=kem_p,json=kemP,proto3" json:"kem_p,omitempty"`
	KemQ           []byte `protobuf:"bytes,3,opt,name=kem_q,json=kemQ,proto3" json:"kem_q,omitempty"`
	Pads           uint32 `protobuf:"varint,4,opt,name=pads,proto3" json:"pads,omitempty"`
	SessionKeySize uint32 `protobuf:"varint,5,opt,name=session_key_size,json=sessionKeySize,proto3" json:"session_key_size,omitempty"`
}

func (m *AuthChallenge) Reset()         { *m = AuthChallenge{} }
func (m *AuthChallenge) String() string { return proto.CompactTextString(m) }
func (*AuthChallenge) ProtoMessage()    {}

// Signature is the serialized HPPK signature payload.
type Signature struct {
	Beta     []byte   `protobuf:"bytes,1,opt,name=beta,proto3" json:"beta,omitempty"`
	F        []byte   `protobuf:"bytes,2,opt,name=f,proto3" json:"f,omitempty"`
	H        []byte   `protobuf:"bytes,3,opt,name=h,proto3" json:"h,omitempty"`
	S1Verify []byte   `protobuf:"bytes,4,opt,name=s1_verify,json=s1Verify,proto3" json:"s1_verify,omitempty"`
	S2Verify []byte   `protobuf:"bytes,5,opt,name=s2_verify,json=s2Verify,proto3" json:"s2_verify,omitempty"`
	U        [][]byte `protobuf:"bytes,6,rep,name=u,proto3" json:"u,omitempty"`
	V        [][]byte `protobuf:"bytes,7,rep,name=v,proto3" json:"v,omitempty"`
	K        uint32   `protobuf:"varint,8,opt,name=k,proto3" json:"k,omitempty"`
}

func (m *Signature) Reset()         { *m = Signature{} }
func (m *Signature) String() string { return proto.CompactTextString(m) }
func (*Signature) ProtoMessage()    {}

// AuthResponse conveys the response signature.
type AuthResponse struct {
	ClientId  string     `protobuf:"bytes,1,opt,name=client_id,json=clientId,proto3" json:"client_id,omitempty"`
	Signature *Signature `protobuf:"bytes,2,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (m *AuthResponse) Reset()         { *m = AuthResponse{} }
func (m *AuthResponse) String() string { return proto.CompactTextString(m) }
func (*AuthResponse) ProtoMessage()    {}

// AuthResult confirms authentication outcome.
type AuthResult struct {
	Success bool   `protobuf:"varint,1,opt,name=success,proto3" json:"success,omitempty"`
	Message string `protobuf:"bytes,2,opt,name=message,proto3" json:"message,omitempty"`
}

func (m *AuthResult) Reset()         { *m = AuthResult{} }
func (m *AuthResult) String() string { return proto.CompactTextString(m) }
func (*AuthResult) ProtoMessage()    {}

// SecureData contains encrypted payload bytes.
type SecureData struct {
	Ciphertext []byte `protobuf:"bytes,1,opt,name=ciphertext,proto3" json:"ciphertext,omitempty"`
}

func (m *SecureData) Reset()         { *m = SecureData{} }
func (m *SecureData) String() string { return proto.CompactTextString(m) }
func (*SecureData) ProtoMessage()    {}

// PlainPayload represents plaintext terminal data or control signals.
type PlainPayload struct {
	Stream      []byte               `protobuf:"bytes,1,opt,name=stream,proto3" json:"stream,omitempty"`
	Resize      *Resize              `protobuf:"bytes,2,opt,name=resize,proto3" json:"resize,omitempty"`
	FileRequest *FileTransferRequest `protobuf:"bytes,3,opt,name=file_request,json=fileRequest,proto3" json:"file_request,omitempty"`
	FileChunk   *FileTransferChunk   `protobuf:"bytes,4,opt,name=file_chunk,json=fileChunk,proto3" json:"file_chunk,omitempty"`
	FileResult  *FileTransferResult  `protobuf:"bytes,5,opt,name=file_result,json=fileResult,proto3" json:"file_result,omitempty"`
}

func (m *PlainPayload) Reset()         { *m = PlainPayload{} }
func (m *PlainPayload) String() string { return proto.CompactTextString(m) }
func (*PlainPayload) ProtoMessage()    {}

// Resize carries terminal dimension updates.
type Resize struct {
	Rows uint32 `protobuf:"varint,1,opt,name=rows,proto3" json:"rows,omitempty"`
	Cols uint32 `protobuf:"varint,2,opt,name=cols,proto3" json:"cols,omitempty"`
}

func (m *Resize) Reset()         { *m = Resize{} }
func (m *Resize) String() string { return proto.CompactTextString(m) }
func (*Resize) ProtoMessage()    {}

type FileDirection int32

const (
	FileDirection_FILE_DIRECTION_UPLOAD   FileDirection = 0
	FileDirection_FILE_DIRECTION_DOWNLOAD FileDirection = 1
)

type FileTransferRequest struct {
	Direction FileDirection `protobuf:"varint,1,opt,name=direction,proto3,enum=qsh.protocol.FileDirection" json:"direction,omitempty"`
	Path      string        `protobuf:"bytes,2,opt,name=path,proto3" json:"path,omitempty"`
	Size      uint64        `protobuf:"varint,3,opt,name=size,proto3" json:"size,omitempty"`
	Perm      uint32        `protobuf:"varint,4,opt,name=perm,proto3" json:"perm,omitempty"`
}

func (m *FileTransferRequest) Reset()         { *m = FileTransferRequest{} }
func (m *FileTransferRequest) String() string { return proto.CompactTextString(m) }
func (*FileTransferRequest) ProtoMessage()    {}

type FileTransferChunk struct {
	Data   []byte `protobuf:"bytes,1,opt,name=data,proto3" json:"data,omitempty"`
	Offset uint64 `protobuf:"varint,2,opt,name=offset,proto3" json:"offset,omitempty"`
	Eof    bool   `protobuf:"varint,3,opt,name=eof,proto3" json:"eof,omitempty"`
}

func (m *FileTransferChunk) Reset()         { *m = FileTransferChunk{} }
func (m *FileTransferChunk) String() string { return proto.CompactTextString(m) }
func (*FileTransferChunk) ProtoMessage()    {}

type FileTransferResult struct {
	Success bool   `protobuf:"varint,1,opt,name=success,proto3" json:"success,omitempty"`
	Message string `protobuf:"bytes,2,opt,name=message,proto3" json:"message,omitempty"`
	Size    uint64 `protobuf:"varint,3,opt,name=size,proto3" json:"size,omitempty"`
	Done    bool   `protobuf:"varint,4,opt,name=done,proto3" json:"done,omitempty"`
	Perm    uint32 `protobuf:"varint,5,opt,name=perm,proto3" json:"perm,omitempty"`
}

func (m *FileTransferResult) Reset()         { *m = FileTransferResult{} }
func (m *FileTransferResult) String() string { return proto.CompactTextString(m) }
func (*FileTransferResult) ProtoMessage()    {}

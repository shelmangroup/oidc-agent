// Code generated by protoc-gen-go. DO NOT EDIT.
// source: api.proto

package api

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type GetRequest struct {
	Name                 string   `protobuf:"bytes,1,opt,name=name" json:"name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GetRequest) Reset()         { *m = GetRequest{} }
func (m *GetRequest) String() string { return proto.CompactTextString(m) }
func (*GetRequest) ProtoMessage()    {}
func (*GetRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_api_dc398aed313e1a52, []int{0}
}
func (m *GetRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetRequest.Unmarshal(m, b)
}
func (m *GetRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetRequest.Marshal(b, m, deterministic)
}
func (dst *GetRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetRequest.Merge(dst, src)
}
func (m *GetRequest) XXX_Size() int {
	return xxx_messageInfo_GetRequest.Size(m)
}
func (m *GetRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_GetRequest.DiscardUnknown(m)
}

var xxx_messageInfo_GetRequest proto.InternalMessageInfo

func (m *GetRequest) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

type GetResponse struct {
	IdToken              string   `protobuf:"bytes,1,opt,name=id_token,json=idToken" json:"id_token,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GetResponse) Reset()         { *m = GetResponse{} }
func (m *GetResponse) String() string { return proto.CompactTextString(m) }
func (*GetResponse) ProtoMessage()    {}
func (*GetResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_api_dc398aed313e1a52, []int{1}
}
func (m *GetResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetResponse.Unmarshal(m, b)
}
func (m *GetResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetResponse.Marshal(b, m, deterministic)
}
func (dst *GetResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetResponse.Merge(dst, src)
}
func (m *GetResponse) XXX_Size() int {
	return xxx_messageInfo_GetResponse.Size(m)
}
func (m *GetResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_GetResponse.DiscardUnknown(m)
}

var xxx_messageInfo_GetResponse proto.InternalMessageInfo

func (m *GetResponse) GetIdToken() string {
	if m != nil {
		return m.IdToken
	}
	return ""
}

func init() {
	proto.RegisterType((*GetRequest)(nil), "api.GetRequest")
	proto.RegisterType((*GetResponse)(nil), "api.GetResponse")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// OIDCAgentClient is the client API for OIDCAgent service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type OIDCAgentClient interface {
	Get(ctx context.Context, in *GetRequest, opts ...grpc.CallOption) (*GetResponse, error)
}

type oIDCAgentClient struct {
	cc *grpc.ClientConn
}

func NewOIDCAgentClient(cc *grpc.ClientConn) OIDCAgentClient {
	return &oIDCAgentClient{cc}
}

func (c *oIDCAgentClient) Get(ctx context.Context, in *GetRequest, opts ...grpc.CallOption) (*GetResponse, error) {
	out := new(GetResponse)
	err := c.cc.Invoke(ctx, "/api.OIDCAgent/Get", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// OIDCAgentServer is the server API for OIDCAgent service.
type OIDCAgentServer interface {
	Get(context.Context, *GetRequest) (*GetResponse, error)
}

func RegisterOIDCAgentServer(s *grpc.Server, srv OIDCAgentServer) {
	s.RegisterService(&_OIDCAgent_serviceDesc, srv)
}

func _OIDCAgent_Get_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OIDCAgentServer).Get(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.OIDCAgent/Get",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OIDCAgentServer).Get(ctx, req.(*GetRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _OIDCAgent_serviceDesc = grpc.ServiceDesc{
	ServiceName: "api.OIDCAgent",
	HandlerType: (*OIDCAgentServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Get",
			Handler:    _OIDCAgent_Get_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "api.proto",
}

func init() { proto.RegisterFile("api.proto", fileDescriptor_api_dc398aed313e1a52) }

var fileDescriptor_api_dc398aed313e1a52 = []byte{
	// 143 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xe2, 0x4c, 0x2c, 0xc8, 0xd4,
	0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0x62, 0x4e, 0x2c, 0xc8, 0x54, 0x52, 0xe0, 0xe2, 0x72, 0x4f,
	0x2d, 0x09, 0x4a, 0x2d, 0x2c, 0x4d, 0x2d, 0x2e, 0x11, 0x12, 0xe2, 0x62, 0xc9, 0x4b, 0xcc, 0x4d,
	0x95, 0x60, 0x54, 0x60, 0xd4, 0xe0, 0x0c, 0x02, 0xb3, 0x95, 0x34, 0xb8, 0xb8, 0xc1, 0x2a, 0x8a,
	0x0b, 0xf2, 0xf3, 0x8a, 0x53, 0x85, 0x24, 0xb9, 0x38, 0x32, 0x53, 0xe2, 0x4b, 0xf2, 0xb3, 0x53,
	0xf3, 0xa0, 0xca, 0xd8, 0x33, 0x53, 0x42, 0x40, 0x5c, 0x23, 0x73, 0x2e, 0x4e, 0x7f, 0x4f, 0x17,
	0x67, 0xc7, 0xf4, 0xd4, 0xbc, 0x12, 0x21, 0x2d, 0x2e, 0x66, 0xf7, 0xd4, 0x12, 0x21, 0x7e, 0x3d,
	0x90, 0x85, 0x08, 0x2b, 0xa4, 0x04, 0x10, 0x02, 0x10, 0x13, 0x95, 0x18, 0x92, 0xd8, 0xc0, 0x0e,
	0x32, 0x06, 0x04, 0x00, 0x00, 0xff, 0xff, 0xa1, 0x8c, 0xa9, 0xa9, 0x9d, 0x00, 0x00, 0x00,
}

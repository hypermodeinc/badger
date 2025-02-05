/*
 * SPDX-FileCopyrightText: © Hypermode Inc. <hello@hypermode.com>
 * SPDX-License-Identifier: Apache-2.0
 */

// Use protos/gen.sh to generate .pb.go files.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v3.21.12
// source: badgerpb4.proto

package pb

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type EncryptionAlgo int32

const (
	EncryptionAlgo_aes EncryptionAlgo = 0
)

// Enum value maps for EncryptionAlgo.
var (
	EncryptionAlgo_name = map[int32]string{
		0: "aes",
	}
	EncryptionAlgo_value = map[string]int32{
		"aes": 0,
	}
)

func (x EncryptionAlgo) Enum() *EncryptionAlgo {
	p := new(EncryptionAlgo)
	*p = x
	return p
}

func (x EncryptionAlgo) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (EncryptionAlgo) Descriptor() protoreflect.EnumDescriptor {
	return file_badgerpb4_proto_enumTypes[0].Descriptor()
}

func (EncryptionAlgo) Type() protoreflect.EnumType {
	return &file_badgerpb4_proto_enumTypes[0]
}

func (x EncryptionAlgo) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use EncryptionAlgo.Descriptor instead.
func (EncryptionAlgo) EnumDescriptor() ([]byte, []int) {
	return file_badgerpb4_proto_rawDescGZIP(), []int{0}
}

type ManifestChange_Operation int32

const (
	ManifestChange_CREATE ManifestChange_Operation = 0
	ManifestChange_DELETE ManifestChange_Operation = 1
)

// Enum value maps for ManifestChange_Operation.
var (
	ManifestChange_Operation_name = map[int32]string{
		0: "CREATE",
		1: "DELETE",
	}
	ManifestChange_Operation_value = map[string]int32{
		"CREATE": 0,
		"DELETE": 1,
	}
)

func (x ManifestChange_Operation) Enum() *ManifestChange_Operation {
	p := new(ManifestChange_Operation)
	*p = x
	return p
}

func (x ManifestChange_Operation) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ManifestChange_Operation) Descriptor() protoreflect.EnumDescriptor {
	return file_badgerpb4_proto_enumTypes[1].Descriptor()
}

func (ManifestChange_Operation) Type() protoreflect.EnumType {
	return &file_badgerpb4_proto_enumTypes[1]
}

func (x ManifestChange_Operation) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ManifestChange_Operation.Descriptor instead.
func (ManifestChange_Operation) EnumDescriptor() ([]byte, []int) {
	return file_badgerpb4_proto_rawDescGZIP(), []int{3, 0}
}

type Checksum_Algorithm int32

const (
	Checksum_CRC32C   Checksum_Algorithm = 0
	Checksum_XXHash64 Checksum_Algorithm = 1
)

// Enum value maps for Checksum_Algorithm.
var (
	Checksum_Algorithm_name = map[int32]string{
		0: "CRC32C",
		1: "XXHash64",
	}
	Checksum_Algorithm_value = map[string]int32{
		"CRC32C":   0,
		"XXHash64": 1,
	}
)

func (x Checksum_Algorithm) Enum() *Checksum_Algorithm {
	p := new(Checksum_Algorithm)
	*p = x
	return p
}

func (x Checksum_Algorithm) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Checksum_Algorithm) Descriptor() protoreflect.EnumDescriptor {
	return file_badgerpb4_proto_enumTypes[2].Descriptor()
}

func (Checksum_Algorithm) Type() protoreflect.EnumType {
	return &file_badgerpb4_proto_enumTypes[2]
}

func (x Checksum_Algorithm) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Checksum_Algorithm.Descriptor instead.
func (Checksum_Algorithm) EnumDescriptor() ([]byte, []int) {
	return file_badgerpb4_proto_rawDescGZIP(), []int{4, 0}
}

type KV struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Key       []byte `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	Value     []byte `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
	UserMeta  []byte `protobuf:"bytes,3,opt,name=user_meta,json=userMeta,proto3" json:"user_meta,omitempty"`
	Version   uint64 `protobuf:"varint,4,opt,name=version,proto3" json:"version,omitempty"`
	ExpiresAt uint64 `protobuf:"varint,5,opt,name=expires_at,json=expiresAt,proto3" json:"expires_at,omitempty"`
	Meta      []byte `protobuf:"bytes,6,opt,name=meta,proto3" json:"meta,omitempty"`
	// Stream id is used to identify which stream the KV came from.
	StreamId uint32 `protobuf:"varint,10,opt,name=stream_id,json=streamId,proto3" json:"stream_id,omitempty"`
	// Stream done is used to indicate end of stream.
	StreamDone bool `protobuf:"varint,11,opt,name=stream_done,json=streamDone,proto3" json:"stream_done,omitempty"`
}

func (x *KV) Reset() {
	*x = KV{}
	if protoimpl.UnsafeEnabled {
		mi := &file_badgerpb4_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KV) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KV) ProtoMessage() {}

func (x *KV) ProtoReflect() protoreflect.Message {
	mi := &file_badgerpb4_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KV.ProtoReflect.Descriptor instead.
func (*KV) Descriptor() ([]byte, []int) {
	return file_badgerpb4_proto_rawDescGZIP(), []int{0}
}

func (x *KV) GetKey() []byte {
	if x != nil {
		return x.Key
	}
	return nil
}

func (x *KV) GetValue() []byte {
	if x != nil {
		return x.Value
	}
	return nil
}

func (x *KV) GetUserMeta() []byte {
	if x != nil {
		return x.UserMeta
	}
	return nil
}

func (x *KV) GetVersion() uint64 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *KV) GetExpiresAt() uint64 {
	if x != nil {
		return x.ExpiresAt
	}
	return 0
}

func (x *KV) GetMeta() []byte {
	if x != nil {
		return x.Meta
	}
	return nil
}

func (x *KV) GetStreamId() uint32 {
	if x != nil {
		return x.StreamId
	}
	return 0
}

func (x *KV) GetStreamDone() bool {
	if x != nil {
		return x.StreamDone
	}
	return false
}

type KVList struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Kv []*KV `protobuf:"bytes,1,rep,name=kv,proto3" json:"kv,omitempty"`
	// alloc_ref used internally for memory management.
	AllocRef uint64 `protobuf:"varint,10,opt,name=alloc_ref,json=allocRef,proto3" json:"alloc_ref,omitempty"`
}

func (x *KVList) Reset() {
	*x = KVList{}
	if protoimpl.UnsafeEnabled {
		mi := &file_badgerpb4_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KVList) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KVList) ProtoMessage() {}

func (x *KVList) ProtoReflect() protoreflect.Message {
	mi := &file_badgerpb4_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KVList.ProtoReflect.Descriptor instead.
func (*KVList) Descriptor() ([]byte, []int) {
	return file_badgerpb4_proto_rawDescGZIP(), []int{1}
}

func (x *KVList) GetKv() []*KV {
	if x != nil {
		return x.Kv
	}
	return nil
}

func (x *KVList) GetAllocRef() uint64 {
	if x != nil {
		return x.AllocRef
	}
	return 0
}

type ManifestChangeSet struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// A set of changes that are applied atomically.
	Changes []*ManifestChange `protobuf:"bytes,1,rep,name=changes,proto3" json:"changes,omitempty"`
}

func (x *ManifestChangeSet) Reset() {
	*x = ManifestChangeSet{}
	if protoimpl.UnsafeEnabled {
		mi := &file_badgerpb4_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ManifestChangeSet) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ManifestChangeSet) ProtoMessage() {}

func (x *ManifestChangeSet) ProtoReflect() protoreflect.Message {
	mi := &file_badgerpb4_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ManifestChangeSet.ProtoReflect.Descriptor instead.
func (*ManifestChangeSet) Descriptor() ([]byte, []int) {
	return file_badgerpb4_proto_rawDescGZIP(), []int{2}
}

func (x *ManifestChangeSet) GetChanges() []*ManifestChange {
	if x != nil {
		return x.Changes
	}
	return nil
}

type ManifestChange struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id             uint64                   `protobuf:"varint,1,opt,name=Id,proto3" json:"Id,omitempty"` // Table ID.
	Op             ManifestChange_Operation `protobuf:"varint,2,opt,name=Op,proto3,enum=badgerpb4.ManifestChange_Operation" json:"Op,omitempty"`
	Level          uint32                   `protobuf:"varint,3,opt,name=Level,proto3" json:"Level,omitempty"` // Only used for CREATE.
	KeyId          uint64                   `protobuf:"varint,4,opt,name=key_id,json=keyId,proto3" json:"key_id,omitempty"`
	EncryptionAlgo EncryptionAlgo           `protobuf:"varint,5,opt,name=encryption_algo,json=encryptionAlgo,proto3,enum=badgerpb4.EncryptionAlgo" json:"encryption_algo,omitempty"`
	Compression    uint32                   `protobuf:"varint,6,opt,name=compression,proto3" json:"compression,omitempty"` // Only used for CREATE Op.
}

func (x *ManifestChange) Reset() {
	*x = ManifestChange{}
	if protoimpl.UnsafeEnabled {
		mi := &file_badgerpb4_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ManifestChange) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ManifestChange) ProtoMessage() {}

func (x *ManifestChange) ProtoReflect() protoreflect.Message {
	mi := &file_badgerpb4_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ManifestChange.ProtoReflect.Descriptor instead.
func (*ManifestChange) Descriptor() ([]byte, []int) {
	return file_badgerpb4_proto_rawDescGZIP(), []int{3}
}

func (x *ManifestChange) GetId() uint64 {
	if x != nil {
		return x.Id
	}
	return 0
}

func (x *ManifestChange) GetOp() ManifestChange_Operation {
	if x != nil {
		return x.Op
	}
	return ManifestChange_CREATE
}

func (x *ManifestChange) GetLevel() uint32 {
	if x != nil {
		return x.Level
	}
	return 0
}

func (x *ManifestChange) GetKeyId() uint64 {
	if x != nil {
		return x.KeyId
	}
	return 0
}

func (x *ManifestChange) GetEncryptionAlgo() EncryptionAlgo {
	if x != nil {
		return x.EncryptionAlgo
	}
	return EncryptionAlgo_aes
}

func (x *ManifestChange) GetCompression() uint32 {
	if x != nil {
		return x.Compression
	}
	return 0
}

type Checksum struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Algo Checksum_Algorithm `protobuf:"varint,1,opt,name=algo,proto3,enum=badgerpb4.Checksum_Algorithm" json:"algo,omitempty"` // For storing type of Checksum algorithm used
	Sum  uint64             `protobuf:"varint,2,opt,name=sum,proto3" json:"sum,omitempty"`
}

func (x *Checksum) Reset() {
	*x = Checksum{}
	if protoimpl.UnsafeEnabled {
		mi := &file_badgerpb4_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Checksum) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Checksum) ProtoMessage() {}

func (x *Checksum) ProtoReflect() protoreflect.Message {
	mi := &file_badgerpb4_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Checksum.ProtoReflect.Descriptor instead.
func (*Checksum) Descriptor() ([]byte, []int) {
	return file_badgerpb4_proto_rawDescGZIP(), []int{4}
}

func (x *Checksum) GetAlgo() Checksum_Algorithm {
	if x != nil {
		return x.Algo
	}
	return Checksum_CRC32C
}

func (x *Checksum) GetSum() uint64 {
	if x != nil {
		return x.Sum
	}
	return 0
}

type DataKey struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	KeyId     uint64 `protobuf:"varint,1,opt,name=key_id,json=keyId,proto3" json:"key_id,omitempty"`
	Data      []byte `protobuf:"bytes,2,opt,name=data,proto3" json:"data,omitempty"`
	Iv        []byte `protobuf:"bytes,3,opt,name=iv,proto3" json:"iv,omitempty"`
	CreatedAt int64  `protobuf:"varint,4,opt,name=created_at,json=createdAt,proto3" json:"created_at,omitempty"`
}

func (x *DataKey) Reset() {
	*x = DataKey{}
	if protoimpl.UnsafeEnabled {
		mi := &file_badgerpb4_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DataKey) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DataKey) ProtoMessage() {}

func (x *DataKey) ProtoReflect() protoreflect.Message {
	mi := &file_badgerpb4_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DataKey.ProtoReflect.Descriptor instead.
func (*DataKey) Descriptor() ([]byte, []int) {
	return file_badgerpb4_proto_rawDescGZIP(), []int{5}
}

func (x *DataKey) GetKeyId() uint64 {
	if x != nil {
		return x.KeyId
	}
	return 0
}

func (x *DataKey) GetData() []byte {
	if x != nil {
		return x.Data
	}
	return nil
}

func (x *DataKey) GetIv() []byte {
	if x != nil {
		return x.Iv
	}
	return nil
}

func (x *DataKey) GetCreatedAt() int64 {
	if x != nil {
		return x.CreatedAt
	}
	return 0
}

type Match struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Prefix      []byte `protobuf:"bytes,1,opt,name=prefix,proto3" json:"prefix,omitempty"`
	IgnoreBytes string `protobuf:"bytes,2,opt,name=ignore_bytes,json=ignoreBytes,proto3" json:"ignore_bytes,omitempty"` // Comma separated with dash to represent ranges "1, 2-3, 4-7, 9"
}

func (x *Match) Reset() {
	*x = Match{}
	if protoimpl.UnsafeEnabled {
		mi := &file_badgerpb4_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Match) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Match) ProtoMessage() {}

func (x *Match) ProtoReflect() protoreflect.Message {
	mi := &file_badgerpb4_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Match.ProtoReflect.Descriptor instead.
func (*Match) Descriptor() ([]byte, []int) {
	return file_badgerpb4_proto_rawDescGZIP(), []int{6}
}

func (x *Match) GetPrefix() []byte {
	if x != nil {
		return x.Prefix
	}
	return nil
}

func (x *Match) GetIgnoreBytes() string {
	if x != nil {
		return x.IgnoreBytes
	}
	return ""
}

var File_badgerpb4_proto protoreflect.FileDescriptor

var file_badgerpb4_proto_rawDesc = []byte{
	0x0a, 0x0f, 0x62, 0x61, 0x64, 0x67, 0x65, 0x72, 0x70, 0x62, 0x34, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x09, 0x62, 0x61, 0x64, 0x67, 0x65, 0x72, 0x70, 0x62, 0x34, 0x22, 0xd4, 0x01, 0x0a,
	0x02, 0x4b, 0x56, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x12, 0x1b, 0x0a, 0x09, 0x75,
	0x73, 0x65, 0x72, 0x5f, 0x6d, 0x65, 0x74, 0x61, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x08,
	0x75, 0x73, 0x65, 0x72, 0x4d, 0x65, 0x74, 0x61, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73,
	0x69, 0x6f, 0x6e, 0x18, 0x04, 0x20, 0x01, 0x28, 0x04, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69,
	0x6f, 0x6e, 0x12, 0x1d, 0x0a, 0x0a, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x73, 0x5f, 0x61, 0x74,
	0x18, 0x05, 0x20, 0x01, 0x28, 0x04, 0x52, 0x09, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x73, 0x41,
	0x74, 0x12, 0x12, 0x0a, 0x04, 0x6d, 0x65, 0x74, 0x61, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x04, 0x6d, 0x65, 0x74, 0x61, 0x12, 0x1b, 0x0a, 0x09, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x5f,
	0x69, 0x64, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x08, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d,
	0x49, 0x64, 0x12, 0x1f, 0x0a, 0x0b, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x5f, 0x64, 0x6f, 0x6e,
	0x65, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0a, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x44,
	0x6f, 0x6e, 0x65, 0x22, 0x44, 0x0a, 0x06, 0x4b, 0x56, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x1d, 0x0a,
	0x02, 0x6b, 0x76, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0d, 0x2e, 0x62, 0x61, 0x64, 0x67,
	0x65, 0x72, 0x70, 0x62, 0x34, 0x2e, 0x4b, 0x56, 0x52, 0x02, 0x6b, 0x76, 0x12, 0x1b, 0x0a, 0x09,
	0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x5f, 0x72, 0x65, 0x66, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x04, 0x52,
	0x08, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x52, 0x65, 0x66, 0x22, 0x48, 0x0a, 0x11, 0x4d, 0x61, 0x6e,
	0x69, 0x66, 0x65, 0x73, 0x74, 0x43, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x53, 0x65, 0x74, 0x12, 0x33,
	0x0a, 0x07, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x19, 0x2e, 0x62, 0x61, 0x64, 0x67, 0x65, 0x72, 0x70, 0x62, 0x34, 0x2e, 0x4d, 0x61, 0x6e, 0x69,
	0x66, 0x65, 0x73, 0x74, 0x43, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x52, 0x07, 0x63, 0x68, 0x61, 0x6e,
	0x67, 0x65, 0x73, 0x22, 0x8d, 0x02, 0x0a, 0x0e, 0x4d, 0x61, 0x6e, 0x69, 0x66, 0x65, 0x73, 0x74,
	0x43, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x12, 0x0e, 0x0a, 0x02, 0x49, 0x64, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x04, 0x52, 0x02, 0x49, 0x64, 0x12, 0x33, 0x0a, 0x02, 0x4f, 0x70, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0e, 0x32, 0x23, 0x2e, 0x62, 0x61, 0x64, 0x67, 0x65, 0x72, 0x70, 0x62, 0x34, 0x2e, 0x4d,
	0x61, 0x6e, 0x69, 0x66, 0x65, 0x73, 0x74, 0x43, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x2e, 0x4f, 0x70,
	0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x02, 0x4f, 0x70, 0x12, 0x14, 0x0a, 0x05, 0x4c,
	0x65, 0x76, 0x65, 0x6c, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x4c, 0x65, 0x76, 0x65,
	0x6c, 0x12, 0x15, 0x0a, 0x06, 0x6b, 0x65, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x04, 0x52, 0x05, 0x6b, 0x65, 0x79, 0x49, 0x64, 0x12, 0x42, 0x0a, 0x0f, 0x65, 0x6e, 0x63, 0x72,
	0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x61, 0x6c, 0x67, 0x6f, 0x18, 0x05, 0x20, 0x01, 0x28,
	0x0e, 0x32, 0x19, 0x2e, 0x62, 0x61, 0x64, 0x67, 0x65, 0x72, 0x70, 0x62, 0x34, 0x2e, 0x45, 0x6e,
	0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x41, 0x6c, 0x67, 0x6f, 0x52, 0x0e, 0x65, 0x6e,
	0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x41, 0x6c, 0x67, 0x6f, 0x12, 0x20, 0x0a, 0x0b,
	0x63, 0x6f, 0x6d, 0x70, 0x72, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x06, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x0b, 0x63, 0x6f, 0x6d, 0x70, 0x72, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x22, 0x23,
	0x0a, 0x09, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x0a, 0x0a, 0x06, 0x43,
	0x52, 0x45, 0x41, 0x54, 0x45, 0x10, 0x00, 0x12, 0x0a, 0x0a, 0x06, 0x44, 0x45, 0x4c, 0x45, 0x54,
	0x45, 0x10, 0x01, 0x22, 0x76, 0x0a, 0x08, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x73, 0x75, 0x6d, 0x12,
	0x31, 0x0a, 0x04, 0x61, 0x6c, 0x67, 0x6f, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x1d, 0x2e,
	0x62, 0x61, 0x64, 0x67, 0x65, 0x72, 0x70, 0x62, 0x34, 0x2e, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x73,
	0x75, 0x6d, 0x2e, 0x41, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x52, 0x04, 0x61, 0x6c,
	0x67, 0x6f, 0x12, 0x10, 0x0a, 0x03, 0x73, 0x75, 0x6d, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x52,
	0x03, 0x73, 0x75, 0x6d, 0x22, 0x25, 0x0a, 0x09, 0x41, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68,
	0x6d, 0x12, 0x0a, 0x0a, 0x06, 0x43, 0x52, 0x43, 0x33, 0x32, 0x43, 0x10, 0x00, 0x12, 0x0c, 0x0a,
	0x08, 0x58, 0x58, 0x48, 0x61, 0x73, 0x68, 0x36, 0x34, 0x10, 0x01, 0x22, 0x63, 0x0a, 0x07, 0x44,
	0x61, 0x74, 0x61, 0x4b, 0x65, 0x79, 0x12, 0x15, 0x0a, 0x06, 0x6b, 0x65, 0x79, 0x5f, 0x69, 0x64,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x05, 0x6b, 0x65, 0x79, 0x49, 0x64, 0x12, 0x12, 0x0a,
	0x04, 0x64, 0x61, 0x74, 0x61, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x64, 0x61, 0x74,
	0x61, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x76, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x69,
	0x76, 0x12, 0x1d, 0x0a, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x03, 0x52, 0x09, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74,
	0x22, 0x42, 0x0a, 0x05, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x12, 0x16, 0x0a, 0x06, 0x70, 0x72, 0x65,
	0x66, 0x69, 0x78, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x70, 0x72, 0x65, 0x66, 0x69,
	0x78, 0x12, 0x21, 0x0a, 0x0c, 0x69, 0x67, 0x6e, 0x6f, 0x72, 0x65, 0x5f, 0x62, 0x79, 0x74, 0x65,
	0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x69, 0x67, 0x6e, 0x6f, 0x72, 0x65, 0x42,
	0x79, 0x74, 0x65, 0x73, 0x2a, 0x19, 0x0a, 0x0e, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69,
	0x6f, 0x6e, 0x41, 0x6c, 0x67, 0x6f, 0x12, 0x07, 0x0a, 0x03, 0x61, 0x65, 0x73, 0x10, 0x00, 0x42,
	0x23, 0x5a, 0x21, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x64, 0x67,
	0x72, 0x61, 0x70, 0x68, 0x2d, 0x69, 0x6f, 0x2f, 0x62, 0x61, 0x64, 0x67, 0x65, 0x72, 0x2f, 0x76,
	0x34, 0x2f, 0x70, 0x62, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_badgerpb4_proto_rawDescOnce sync.Once
	file_badgerpb4_proto_rawDescData = file_badgerpb4_proto_rawDesc
)

func file_badgerpb4_proto_rawDescGZIP() []byte {
	file_badgerpb4_proto_rawDescOnce.Do(func() {
		file_badgerpb4_proto_rawDescData = protoimpl.X.CompressGZIP(file_badgerpb4_proto_rawDescData)
	})
	return file_badgerpb4_proto_rawDescData
}

var file_badgerpb4_proto_enumTypes = make([]protoimpl.EnumInfo, 3)
var file_badgerpb4_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_badgerpb4_proto_goTypes = []interface{}{
	(EncryptionAlgo)(0),           // 0: badgerpb4.EncryptionAlgo
	(ManifestChange_Operation)(0), // 1: badgerpb4.ManifestChange.Operation
	(Checksum_Algorithm)(0),       // 2: badgerpb4.Checksum.Algorithm
	(*KV)(nil),                    // 3: badgerpb4.KV
	(*KVList)(nil),                // 4: badgerpb4.KVList
	(*ManifestChangeSet)(nil),     // 5: badgerpb4.ManifestChangeSet
	(*ManifestChange)(nil),        // 6: badgerpb4.ManifestChange
	(*Checksum)(nil),              // 7: badgerpb4.Checksum
	(*DataKey)(nil),               // 8: badgerpb4.DataKey
	(*Match)(nil),                 // 9: badgerpb4.Match
}
var file_badgerpb4_proto_depIdxs = []int32{
	3, // 0: badgerpb4.KVList.kv:type_name -> badgerpb4.KV
	6, // 1: badgerpb4.ManifestChangeSet.changes:type_name -> badgerpb4.ManifestChange
	1, // 2: badgerpb4.ManifestChange.Op:type_name -> badgerpb4.ManifestChange.Operation
	0, // 3: badgerpb4.ManifestChange.encryption_algo:type_name -> badgerpb4.EncryptionAlgo
	2, // 4: badgerpb4.Checksum.algo:type_name -> badgerpb4.Checksum.Algorithm
	5, // [5:5] is the sub-list for method output_type
	5, // [5:5] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_badgerpb4_proto_init() }
func file_badgerpb4_proto_init() {
	if File_badgerpb4_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_badgerpb4_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KV); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_badgerpb4_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KVList); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_badgerpb4_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ManifestChangeSet); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_badgerpb4_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ManifestChange); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_badgerpb4_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Checksum); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_badgerpb4_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DataKey); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_badgerpb4_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Match); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_badgerpb4_proto_rawDesc,
			NumEnums:      3,
			NumMessages:   7,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_badgerpb4_proto_goTypes,
		DependencyIndexes: file_badgerpb4_proto_depIdxs,
		EnumInfos:         file_badgerpb4_proto_enumTypes,
		MessageInfos:      file_badgerpb4_proto_msgTypes,
	}.Build()
	File_badgerpb4_proto = out.File
	file_badgerpb4_proto_rawDesc = nil
	file_badgerpb4_proto_goTypes = nil
	file_badgerpb4_proto_depIdxs = nil
}

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.2
// 	protoc        v3.21.12
// source: context.proto

package conformance

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

// A set of feature flags.
type FeatureSet struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Every item in this list marks an enabled feature.  The value of
	// each item is the first 8 bytes of the feature ID as a little-
	// endian integer.
	Features []uint64 `protobuf:"fixed64,1,rep,packed,name=features,proto3" json:"features,omitempty"`
}

func (x *FeatureSet) Reset() {
	*x = FeatureSet{}
	if protoimpl.UnsafeEnabled {
		mi := &file_context_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FeatureSet) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FeatureSet) ProtoMessage() {}

func (x *FeatureSet) ProtoReflect() protoreflect.Message {
	mi := &file_context_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FeatureSet.ProtoReflect.Descriptor instead.
func (*FeatureSet) Descriptor() ([]byte, []int) {
	return file_context_proto_rawDescGZIP(), []int{0}
}

func (x *FeatureSet) GetFeatures() []uint64 {
	if x != nil {
		return x.Features
	}
	return nil
}

// A seed address.  This is not a PDA.
type SeedAddress struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The seed address base.  (32 bytes)
	Base []byte `protobuf:"bytes,1,opt,name=base,proto3" json:"base,omitempty"`
	// The seed path  (<= 32 bytes)
	Seed []byte `protobuf:"bytes,2,opt,name=seed,proto3" json:"seed,omitempty"`
	// The seed address owner.  (32 bytes)
	Owner []byte `protobuf:"bytes,3,opt,name=owner,proto3" json:"owner,omitempty"`
}

func (x *SeedAddress) Reset() {
	*x = SeedAddress{}
	if protoimpl.UnsafeEnabled {
		mi := &file_context_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SeedAddress) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SeedAddress) ProtoMessage() {}

func (x *SeedAddress) ProtoReflect() protoreflect.Message {
	mi := &file_context_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SeedAddress.ProtoReflect.Descriptor instead.
func (*SeedAddress) Descriptor() ([]byte, []int) {
	return file_context_proto_rawDescGZIP(), []int{1}
}

func (x *SeedAddress) GetBase() []byte {
	if x != nil {
		return x.Base
	}
	return nil
}

func (x *SeedAddress) GetSeed() []byte {
	if x != nil {
		return x.Seed
	}
	return nil
}

func (x *SeedAddress) GetOwner() []byte {
	if x != nil {
		return x.Owner
	}
	return nil
}

// The complete state of an account excluding its public key.
type AcctState struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The account address.  (32 bytes)
	Address  []byte `protobuf:"bytes,1,opt,name=address,proto3" json:"address,omitempty"`
	Lamports uint64 `protobuf:"varint,2,opt,name=lamports,proto3" json:"lamports,omitempty"`
	// Account data is limited to 10 MiB on Solana mainnet as of 2024-Feb.
	Data       []byte `protobuf:"bytes,3,opt,name=data,proto3" json:"data,omitempty"`
	Executable bool   `protobuf:"varint,4,opt,name=executable,proto3" json:"executable,omitempty"`
	// The rent epoch is deprecated on Solana mainnet as of 2024-Feb.
	// If ommitted, implies a value of UINT64_MAX.
	RentEpoch uint64 `protobuf:"varint,5,opt,name=rent_epoch,json=rentEpoch,proto3" json:"rent_epoch,omitempty"`
	// Address of the program that owns this account.  (32 bytes)
	Owner []byte `protobuf:"bytes,6,opt,name=owner,proto3" json:"owner,omitempty"`
	// The account address, but derived as a seed address.  Overrides
	// `address` if present.
	// TODO: This is a solfuzz specific extension and is not compliant
	// with the org.solana.sealevel.v1 API.
	SeedAddr *SeedAddress `protobuf:"bytes,7,opt,name=seed_addr,json=seedAddr,proto3" json:"seed_addr,omitempty"`
}

func (x *AcctState) Reset() {
	*x = AcctState{}
	if protoimpl.UnsafeEnabled {
		mi := &file_context_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AcctState) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AcctState) ProtoMessage() {}

func (x *AcctState) ProtoReflect() protoreflect.Message {
	mi := &file_context_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AcctState.ProtoReflect.Descriptor instead.
func (*AcctState) Descriptor() ([]byte, []int) {
	return file_context_proto_rawDescGZIP(), []int{2}
}

func (x *AcctState) GetAddress() []byte {
	if x != nil {
		return x.Address
	}
	return nil
}

func (x *AcctState) GetLamports() uint64 {
	if x != nil {
		return x.Lamports
	}
	return 0
}

func (x *AcctState) GetData() []byte {
	if x != nil {
		return x.Data
	}
	return nil
}

func (x *AcctState) GetExecutable() bool {
	if x != nil {
		return x.Executable
	}
	return false
}

func (x *AcctState) GetRentEpoch() uint64 {
	if x != nil {
		return x.RentEpoch
	}
	return 0
}

func (x *AcctState) GetOwner() []byte {
	if x != nil {
		return x.Owner
	}
	return nil
}

func (x *AcctState) GetSeedAddr() *SeedAddress {
	if x != nil {
		return x.SeedAddr
	}
	return nil
}

// EpochContext includes context scoped to an epoch.
// On "real" ledgers, it is created during the epoch boundary.
type EpochContext struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Features *FeatureSet `protobuf:"bytes,1,opt,name=features,proto3" json:"features,omitempty"`
}

func (x *EpochContext) Reset() {
	*x = EpochContext{}
	if protoimpl.UnsafeEnabled {
		mi := &file_context_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EpochContext) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EpochContext) ProtoMessage() {}

func (x *EpochContext) ProtoReflect() protoreflect.Message {
	mi := &file_context_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EpochContext.ProtoReflect.Descriptor instead.
func (*EpochContext) Descriptor() ([]byte, []int) {
	return file_context_proto_rawDescGZIP(), []int{3}
}

func (x *EpochContext) GetFeatures() *FeatureSet {
	if x != nil {
		return x.Features
	}
	return nil
}

// SlotContext includes context scoped to a block.
// On "real" ledgers, it is created during the slot boundary.
type SlotContext struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Slot number
	Slot uint64 `protobuf:"fixed64,1,opt,name=slot,proto3" json:"slot,omitempty"`
}

func (x *SlotContext) Reset() {
	*x = SlotContext{}
	if protoimpl.UnsafeEnabled {
		mi := &file_context_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SlotContext) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SlotContext) ProtoMessage() {}

func (x *SlotContext) ProtoReflect() protoreflect.Message {
	mi := &file_context_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SlotContext.ProtoReflect.Descriptor instead.
func (*SlotContext) Descriptor() ([]byte, []int) {
	return file_context_proto_rawDescGZIP(), []int{4}
}

func (x *SlotContext) GetSlot() uint64 {
	if x != nil {
		return x.Slot
	}
	return 0
}

var File_context_proto protoreflect.FileDescriptor

var file_context_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x16, 0x6f, 0x72, 0x67, 0x2e, 0x73, 0x6f, 0x6c, 0x61, 0x6e, 0x61, 0x2e, 0x73, 0x65, 0x61, 0x6c,
	0x65, 0x76, 0x65, 0x6c, 0x2e, 0x76, 0x31, 0x22, 0x28, 0x0a, 0x0a, 0x46, 0x65, 0x61, 0x74, 0x75,
	0x72, 0x65, 0x53, 0x65, 0x74, 0x12, 0x1a, 0x0a, 0x08, 0x66, 0x65, 0x61, 0x74, 0x75, 0x72, 0x65,
	0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x06, 0x52, 0x08, 0x66, 0x65, 0x61, 0x74, 0x75, 0x72, 0x65,
	0x73, 0x22, 0x4b, 0x0a, 0x0b, 0x53, 0x65, 0x65, 0x64, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73,
	0x12, 0x12, 0x0a, 0x04, 0x62, 0x61, 0x73, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04,
	0x62, 0x61, 0x73, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x73, 0x65, 0x65, 0x64, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x04, 0x73, 0x65, 0x65, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x6f, 0x77, 0x6e, 0x65,
	0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x6f, 0x77, 0x6e, 0x65, 0x72, 0x22, 0xec,
	0x01, 0x0a, 0x09, 0x41, 0x63, 0x63, 0x74, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x18, 0x0a, 0x07,
	0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x61,
	0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x1a, 0x0a, 0x08, 0x6c, 0x61, 0x6d, 0x70, 0x6f, 0x72,
	0x74, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x52, 0x08, 0x6c, 0x61, 0x6d, 0x70, 0x6f, 0x72,
	0x74, 0x73, 0x12, 0x12, 0x0a, 0x04, 0x64, 0x61, 0x74, 0x61, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x04, 0x64, 0x61, 0x74, 0x61, 0x12, 0x1e, 0x0a, 0x0a, 0x65, 0x78, 0x65, 0x63, 0x75, 0x74,
	0x61, 0x62, 0x6c, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0a, 0x65, 0x78, 0x65, 0x63,
	0x75, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x72, 0x65, 0x6e, 0x74, 0x5f, 0x65,
	0x70, 0x6f, 0x63, 0x68, 0x18, 0x05, 0x20, 0x01, 0x28, 0x04, 0x52, 0x09, 0x72, 0x65, 0x6e, 0x74,
	0x45, 0x70, 0x6f, 0x63, 0x68, 0x12, 0x14, 0x0a, 0x05, 0x6f, 0x77, 0x6e, 0x65, 0x72, 0x18, 0x06,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x6f, 0x77, 0x6e, 0x65, 0x72, 0x12, 0x40, 0x0a, 0x09, 0x73,
	0x65, 0x65, 0x64, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x23,
	0x2e, 0x6f, 0x72, 0x67, 0x2e, 0x73, 0x6f, 0x6c, 0x61, 0x6e, 0x61, 0x2e, 0x73, 0x65, 0x61, 0x6c,
	0x65, 0x76, 0x65, 0x6c, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x65, 0x65, 0x64, 0x41, 0x64, 0x64, 0x72,
	0x65, 0x73, 0x73, 0x52, 0x08, 0x73, 0x65, 0x65, 0x64, 0x41, 0x64, 0x64, 0x72, 0x22, 0x4e, 0x0a,
	0x0c, 0x45, 0x70, 0x6f, 0x63, 0x68, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x12, 0x3e, 0x0a,
	0x08, 0x66, 0x65, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x22, 0x2e, 0x6f, 0x72, 0x67, 0x2e, 0x73, 0x6f, 0x6c, 0x61, 0x6e, 0x61, 0x2e, 0x73, 0x65, 0x61,
	0x6c, 0x65, 0x76, 0x65, 0x6c, 0x2e, 0x76, 0x31, 0x2e, 0x46, 0x65, 0x61, 0x74, 0x75, 0x72, 0x65,
	0x53, 0x65, 0x74, 0x52, 0x08, 0x66, 0x65, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x22, 0x21, 0x0a,
	0x0b, 0x53, 0x6c, 0x6f, 0x74, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x12, 0x12, 0x0a, 0x04,
	0x73, 0x6c, 0x6f, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x06, 0x52, 0x04, 0x73, 0x6c, 0x6f, 0x74,
	0x42, 0x0f, 0x5a, 0x0d, 0x2e, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x6e, 0x63,
	0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_context_proto_rawDescOnce sync.Once
	file_context_proto_rawDescData = file_context_proto_rawDesc
)

func file_context_proto_rawDescGZIP() []byte {
	file_context_proto_rawDescOnce.Do(func() {
		file_context_proto_rawDescData = protoimpl.X.CompressGZIP(file_context_proto_rawDescData)
	})
	return file_context_proto_rawDescData
}

var file_context_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_context_proto_goTypes = []any{
	(*FeatureSet)(nil),   // 0: org.solana.sealevel.v1.FeatureSet
	(*SeedAddress)(nil),  // 1: org.solana.sealevel.v1.SeedAddress
	(*AcctState)(nil),    // 2: org.solana.sealevel.v1.AcctState
	(*EpochContext)(nil), // 3: org.solana.sealevel.v1.EpochContext
	(*SlotContext)(nil),  // 4: org.solana.sealevel.v1.SlotContext
}
var file_context_proto_depIdxs = []int32{
	1, // 0: org.solana.sealevel.v1.AcctState.seed_addr:type_name -> org.solana.sealevel.v1.SeedAddress
	0, // 1: org.solana.sealevel.v1.EpochContext.features:type_name -> org.solana.sealevel.v1.FeatureSet
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_context_proto_init() }
func file_context_proto_init() {
	if File_context_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_context_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*FeatureSet); i {
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
		file_context_proto_msgTypes[1].Exporter = func(v any, i int) any {
			switch v := v.(*SeedAddress); i {
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
		file_context_proto_msgTypes[2].Exporter = func(v any, i int) any {
			switch v := v.(*AcctState); i {
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
		file_context_proto_msgTypes[3].Exporter = func(v any, i int) any {
			switch v := v.(*EpochContext); i {
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
		file_context_proto_msgTypes[4].Exporter = func(v any, i int) any {
			switch v := v.(*SlotContext); i {
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
			RawDescriptor: file_context_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_context_proto_goTypes,
		DependencyIndexes: file_context_proto_depIdxs,
		MessageInfos:      file_context_proto_msgTypes,
	}.Build()
	File_context_proto = out.File
	file_context_proto_rawDesc = nil
	file_context_proto_goTypes = nil
	file_context_proto_depIdxs = nil
}

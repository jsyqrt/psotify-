# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: playlist4ops.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import playlist4meta_pb2 as playlist4meta__pb2
import playlist4content_pb2 as playlist4content__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='playlist4ops.proto',
  package='',
  syntax='proto2',
  serialized_pb=_b('\n\x12playlist4ops.proto\x1a\x13playlist4meta.proto\x1a\x16playlist4content.proto\"w\n\x03\x41\x64\x64\x12\x11\n\tfromIndex\x18\x01 \x01(\x05\x12\x14\n\x05items\x18\x02 \x03(\x0b\x32\x05.Item\x12$\n\rlist_checksum\x18\x03 \x01(\x0b\x32\r.ListChecksum\x12\x0f\n\x07\x61\x64\x64Last\x18\x04 \x01(\x08\x12\x10\n\x08\x61\x64\x64\x46irst\x18\x05 \x01(\x08\"\xc5\x01\n\x03Rem\x12\x11\n\tfromIndex\x18\x01 \x01(\x05\x12\x0e\n\x06length\x18\x02 \x01(\x05\x12\x14\n\x05items\x18\x03 \x03(\x0b\x32\x05.Item\x12$\n\rlist_checksum\x18\x04 \x01(\x0b\x32\r.ListChecksum\x12%\n\x0eitems_checksum\x18\x05 \x01(\x0b\x32\r.ListChecksum\x12$\n\ruris_checksum\x18\x06 \x01(\x0b\x32\r.ListChecksum\x12\x12\n\nitemsAsKey\x18\x07 \x01(\x08\"\xac\x01\n\x03Mov\x12\x11\n\tfromIndex\x18\x01 \x01(\x05\x12\x0e\n\x06length\x18\x02 \x01(\x05\x12\x0f\n\x07toIndex\x18\x03 \x01(\x05\x12$\n\rlist_checksum\x18\x04 \x01(\x0b\x32\r.ListChecksum\x12%\n\x0eitems_checksum\x18\x05 \x01(\x0b\x32\r.ListChecksum\x12$\n\ruris_checksum\x18\x06 \x01(\x0b\x32\r.ListChecksum\"\xfa\x02\n\x1aItemAttributesPartialState\x12\x1f\n\x06values\x18\x01 \x01(\x0b\x32\x0f.ItemAttributes\x12?\n\x08no_value\x18\x02 \x03(\x0e\x32-.ItemAttributesPartialState.ItemAttributeKind\"\xf9\x01\n\x11ItemAttributeKind\x12\x10\n\x0cITEM_UNKNOWN\x10\x00\x12\x11\n\rITEM_ADDED_BY\x10\x01\x12\x12\n\x0eITEM_TIMESTAMP\x10\x02\x12\x10\n\x0cITEM_MESSAGE\x10\x03\x12\r\n\tITEM_SEEN\x10\x04\x12\x17\n\x13ITEM_DOWNLOAD_COUNT\x10\x05\x12\x18\n\x14ITEM_DOWNLOAD_FORMAT\x10\x06\x12\x18\n\x14ITEM_SEVENDIGITAL_ID\x10\x07\x12\x1a\n\x16ITEM_SEVENDIGITAL_LEFT\x10\x08\x12\x10\n\x0cITEM_SEEN_AT\x10\t\x12\x0f\n\x0bITEM_PUBLIC\x10\n\"\xc9\x02\n\x1aListAttributesPartialState\x12\x1f\n\x06values\x18\x01 \x01(\x0b\x32\x0f.ListAttributes\x12?\n\x08no_value\x18\x02 \x03(\x0e\x32-.ListAttributesPartialState.ListAttributeKind\"\xc8\x01\n\x11ListAttributeKind\x12\x10\n\x0cLIST_UNKNOWN\x10\x00\x12\r\n\tLIST_NAME\x10\x01\x12\x14\n\x10LIST_DESCRIPTION\x10\x02\x12\x10\n\x0cLIST_PICTURE\x10\x03\x12\x16\n\x12LIST_COLLABORATIVE\x10\x04\x12\x14\n\x10LIST_PL3_VERSION\x10\x05\x12\x19\n\x15LIST_DELETED_BY_OWNER\x10\x06\x12!\n\x1dLIST_RESTRICTED_COLLABORATIVE\x10\x07\"\xe5\x01\n\x14UpdateItemAttributes\x12\r\n\x05index\x18\x01 \x01(\x05\x12\x33\n\x0enew_attributes\x18\x02 \x01(\x0b\x32\x1b.ItemAttributesPartialState\x12\x33\n\x0eold_attributes\x18\x03 \x01(\x0b\x32\x1b.ItemAttributesPartialState\x12$\n\rlist_checksum\x18\x04 \x01(\x0b\x32\r.ListChecksum\x12.\n\x17old_attributes_checksum\x18\x05 \x01(\x0b\x32\r.ListChecksum\"\xd6\x01\n\x14UpdateListAttributes\x12\x33\n\x0enew_attributes\x18\x01 \x01(\x0b\x32\x1b.ListAttributesPartialState\x12\x33\n\x0eold_attributes\x18\x02 \x01(\x0b\x32\x1b.ListAttributesPartialState\x12$\n\rlist_checksum\x18\x03 \x01(\x0b\x32\r.ListChecksum\x12.\n\x17old_attributes_checksum\x18\x04 \x01(\x0b\x32\r.ListChecksum\"\xb0\x02\n\x02Op\x12\x16\n\x04kind\x18\x01 \x01(\x0e\x32\x08.Op.Kind\x12\x11\n\x03\x61\x64\x64\x18\x02 \x01(\x0b\x32\x04.Add\x12\x11\n\x03rem\x18\x03 \x01(\x0b\x32\x04.Rem\x12\x11\n\x03mov\x18\x04 \x01(\x0b\x32\x04.Mov\x12\x35\n\x16update_item_attributes\x18\x05 \x01(\x0b\x32\x15.UpdateItemAttributes\x12\x35\n\x16update_list_attributes\x18\x06 \x01(\x0b\x32\x15.UpdateListAttributes\"k\n\x04Kind\x12\x10\n\x0cKIND_UNKNOWN\x10\x00\x12\x07\n\x03\x41\x44\x44\x10\x02\x12\x07\n\x03REM\x10\x03\x12\x07\n\x03MOV\x10\x04\x12\x1a\n\x16UPDATE_ITEM_ATTRIBUTES\x10\x05\x12\x1a\n\x16UPDATE_LIST_ATTRIBUTES\x10\x06\"\x1a\n\x06OpList\x12\x10\n\x03ops\x18\x01 \x03(\x0b\x32\x03.Op')
  ,
  dependencies=[playlist4meta__pb2.DESCRIPTOR,playlist4content__pb2.DESCRIPTOR,])



_ITEMATTRIBUTESPARTIALSTATE_ITEMATTRIBUTEKIND = _descriptor.EnumDescriptor(
  name='ItemAttributeKind',
  full_name='ItemAttributesPartialState.ItemAttributeKind',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='ITEM_UNKNOWN', index=0, number=0,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ITEM_ADDED_BY', index=1, number=1,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ITEM_TIMESTAMP', index=2, number=2,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ITEM_MESSAGE', index=3, number=3,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ITEM_SEEN', index=4, number=4,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ITEM_DOWNLOAD_COUNT', index=5, number=5,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ITEM_DOWNLOAD_FORMAT', index=6, number=6,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ITEM_SEVENDIGITAL_ID', index=7, number=7,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ITEM_SEVENDIGITAL_LEFT', index=8, number=8,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ITEM_SEEN_AT', index=9, number=9,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ITEM_PUBLIC', index=10, number=10,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=693,
  serialized_end=942,
)
_sym_db.RegisterEnumDescriptor(_ITEMATTRIBUTESPARTIALSTATE_ITEMATTRIBUTEKIND)

_LISTATTRIBUTESPARTIALSTATE_LISTATTRIBUTEKIND = _descriptor.EnumDescriptor(
  name='ListAttributeKind',
  full_name='ListAttributesPartialState.ListAttributeKind',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='LIST_UNKNOWN', index=0, number=0,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='LIST_NAME', index=1, number=1,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='LIST_DESCRIPTION', index=2, number=2,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='LIST_PICTURE', index=3, number=3,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='LIST_COLLABORATIVE', index=4, number=4,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='LIST_PL3_VERSION', index=5, number=5,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='LIST_DELETED_BY_OWNER', index=6, number=6,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='LIST_RESTRICTED_COLLABORATIVE', index=7, number=7,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=1074,
  serialized_end=1274,
)
_sym_db.RegisterEnumDescriptor(_LISTATTRIBUTESPARTIALSTATE_LISTATTRIBUTEKIND)

_OP_KIND = _descriptor.EnumDescriptor(
  name='Kind',
  full_name='Op.Kind',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='KIND_UNKNOWN', index=0, number=0,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ADD', index=1, number=2,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='REM', index=2, number=3,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='MOV', index=3, number=4,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='UPDATE_ITEM_ATTRIBUTES', index=4, number=5,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='UPDATE_LIST_ATTRIBUTES', index=5, number=6,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=1923,
  serialized_end=2030,
)
_sym_db.RegisterEnumDescriptor(_OP_KIND)


_ADD = _descriptor.Descriptor(
  name='Add',
  full_name='Add',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='fromIndex', full_name='Add.fromIndex', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='items', full_name='Add.items', index=1,
      number=2, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='list_checksum', full_name='Add.list_checksum', index=2,
      number=3, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='addLast', full_name='Add.addLast', index=3,
      number=4, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='addFirst', full_name='Add.addFirst', index=4,
      number=5, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=67,
  serialized_end=186,
)


_REM = _descriptor.Descriptor(
  name='Rem',
  full_name='Rem',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='fromIndex', full_name='Rem.fromIndex', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='length', full_name='Rem.length', index=1,
      number=2, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='items', full_name='Rem.items', index=2,
      number=3, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='list_checksum', full_name='Rem.list_checksum', index=3,
      number=4, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='items_checksum', full_name='Rem.items_checksum', index=4,
      number=5, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='uris_checksum', full_name='Rem.uris_checksum', index=5,
      number=6, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='itemsAsKey', full_name='Rem.itemsAsKey', index=6,
      number=7, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=189,
  serialized_end=386,
)


_MOV = _descriptor.Descriptor(
  name='Mov',
  full_name='Mov',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='fromIndex', full_name='Mov.fromIndex', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='length', full_name='Mov.length', index=1,
      number=2, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='toIndex', full_name='Mov.toIndex', index=2,
      number=3, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='list_checksum', full_name='Mov.list_checksum', index=3,
      number=4, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='items_checksum', full_name='Mov.items_checksum', index=4,
      number=5, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='uris_checksum', full_name='Mov.uris_checksum', index=5,
      number=6, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=389,
  serialized_end=561,
)


_ITEMATTRIBUTESPARTIALSTATE = _descriptor.Descriptor(
  name='ItemAttributesPartialState',
  full_name='ItemAttributesPartialState',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='values', full_name='ItemAttributesPartialState.values', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='no_value', full_name='ItemAttributesPartialState.no_value', index=1,
      number=2, type=14, cpp_type=8, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _ITEMATTRIBUTESPARTIALSTATE_ITEMATTRIBUTEKIND,
  ],
  options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=564,
  serialized_end=942,
)


_LISTATTRIBUTESPARTIALSTATE = _descriptor.Descriptor(
  name='ListAttributesPartialState',
  full_name='ListAttributesPartialState',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='values', full_name='ListAttributesPartialState.values', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='no_value', full_name='ListAttributesPartialState.no_value', index=1,
      number=2, type=14, cpp_type=8, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _LISTATTRIBUTESPARTIALSTATE_LISTATTRIBUTEKIND,
  ],
  options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=945,
  serialized_end=1274,
)


_UPDATEITEMATTRIBUTES = _descriptor.Descriptor(
  name='UpdateItemAttributes',
  full_name='UpdateItemAttributes',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='index', full_name='UpdateItemAttributes.index', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='new_attributes', full_name='UpdateItemAttributes.new_attributes', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='old_attributes', full_name='UpdateItemAttributes.old_attributes', index=2,
      number=3, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='list_checksum', full_name='UpdateItemAttributes.list_checksum', index=3,
      number=4, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='old_attributes_checksum', full_name='UpdateItemAttributes.old_attributes_checksum', index=4,
      number=5, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=1277,
  serialized_end=1506,
)


_UPDATELISTATTRIBUTES = _descriptor.Descriptor(
  name='UpdateListAttributes',
  full_name='UpdateListAttributes',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='new_attributes', full_name='UpdateListAttributes.new_attributes', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='old_attributes', full_name='UpdateListAttributes.old_attributes', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='list_checksum', full_name='UpdateListAttributes.list_checksum', index=2,
      number=3, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='old_attributes_checksum', full_name='UpdateListAttributes.old_attributes_checksum', index=3,
      number=4, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=1509,
  serialized_end=1723,
)


_OP = _descriptor.Descriptor(
  name='Op',
  full_name='Op',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='kind', full_name='Op.kind', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='add', full_name='Op.add', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='rem', full_name='Op.rem', index=2,
      number=3, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='mov', full_name='Op.mov', index=3,
      number=4, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='update_item_attributes', full_name='Op.update_item_attributes', index=4,
      number=5, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='update_list_attributes', full_name='Op.update_list_attributes', index=5,
      number=6, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _OP_KIND,
  ],
  options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=1726,
  serialized_end=2030,
)


_OPLIST = _descriptor.Descriptor(
  name='OpList',
  full_name='OpList',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='ops', full_name='OpList.ops', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=2032,
  serialized_end=2058,
)

_ADD.fields_by_name['items'].message_type = playlist4content__pb2._ITEM
_ADD.fields_by_name['list_checksum'].message_type = playlist4meta__pb2._LISTCHECKSUM
_REM.fields_by_name['items'].message_type = playlist4content__pb2._ITEM
_REM.fields_by_name['list_checksum'].message_type = playlist4meta__pb2._LISTCHECKSUM
_REM.fields_by_name['items_checksum'].message_type = playlist4meta__pb2._LISTCHECKSUM
_REM.fields_by_name['uris_checksum'].message_type = playlist4meta__pb2._LISTCHECKSUM
_MOV.fields_by_name['list_checksum'].message_type = playlist4meta__pb2._LISTCHECKSUM
_MOV.fields_by_name['items_checksum'].message_type = playlist4meta__pb2._LISTCHECKSUM
_MOV.fields_by_name['uris_checksum'].message_type = playlist4meta__pb2._LISTCHECKSUM
_ITEMATTRIBUTESPARTIALSTATE.fields_by_name['values'].message_type = playlist4meta__pb2._ITEMATTRIBUTES
_ITEMATTRIBUTESPARTIALSTATE.fields_by_name['no_value'].enum_type = _ITEMATTRIBUTESPARTIALSTATE_ITEMATTRIBUTEKIND
_ITEMATTRIBUTESPARTIALSTATE_ITEMATTRIBUTEKIND.containing_type = _ITEMATTRIBUTESPARTIALSTATE
_LISTATTRIBUTESPARTIALSTATE.fields_by_name['values'].message_type = playlist4meta__pb2._LISTATTRIBUTES
_LISTATTRIBUTESPARTIALSTATE.fields_by_name['no_value'].enum_type = _LISTATTRIBUTESPARTIALSTATE_LISTATTRIBUTEKIND
_LISTATTRIBUTESPARTIALSTATE_LISTATTRIBUTEKIND.containing_type = _LISTATTRIBUTESPARTIALSTATE
_UPDATEITEMATTRIBUTES.fields_by_name['new_attributes'].message_type = _ITEMATTRIBUTESPARTIALSTATE
_UPDATEITEMATTRIBUTES.fields_by_name['old_attributes'].message_type = _ITEMATTRIBUTESPARTIALSTATE
_UPDATEITEMATTRIBUTES.fields_by_name['list_checksum'].message_type = playlist4meta__pb2._LISTCHECKSUM
_UPDATEITEMATTRIBUTES.fields_by_name['old_attributes_checksum'].message_type = playlist4meta__pb2._LISTCHECKSUM
_UPDATELISTATTRIBUTES.fields_by_name['new_attributes'].message_type = _LISTATTRIBUTESPARTIALSTATE
_UPDATELISTATTRIBUTES.fields_by_name['old_attributes'].message_type = _LISTATTRIBUTESPARTIALSTATE
_UPDATELISTATTRIBUTES.fields_by_name['list_checksum'].message_type = playlist4meta__pb2._LISTCHECKSUM
_UPDATELISTATTRIBUTES.fields_by_name['old_attributes_checksum'].message_type = playlist4meta__pb2._LISTCHECKSUM
_OP.fields_by_name['kind'].enum_type = _OP_KIND
_OP.fields_by_name['add'].message_type = _ADD
_OP.fields_by_name['rem'].message_type = _REM
_OP.fields_by_name['mov'].message_type = _MOV
_OP.fields_by_name['update_item_attributes'].message_type = _UPDATEITEMATTRIBUTES
_OP.fields_by_name['update_list_attributes'].message_type = _UPDATELISTATTRIBUTES
_OP_KIND.containing_type = _OP
_OPLIST.fields_by_name['ops'].message_type = _OP
DESCRIPTOR.message_types_by_name['Add'] = _ADD
DESCRIPTOR.message_types_by_name['Rem'] = _REM
DESCRIPTOR.message_types_by_name['Mov'] = _MOV
DESCRIPTOR.message_types_by_name['ItemAttributesPartialState'] = _ITEMATTRIBUTESPARTIALSTATE
DESCRIPTOR.message_types_by_name['ListAttributesPartialState'] = _LISTATTRIBUTESPARTIALSTATE
DESCRIPTOR.message_types_by_name['UpdateItemAttributes'] = _UPDATEITEMATTRIBUTES
DESCRIPTOR.message_types_by_name['UpdateListAttributes'] = _UPDATELISTATTRIBUTES
DESCRIPTOR.message_types_by_name['Op'] = _OP
DESCRIPTOR.message_types_by_name['OpList'] = _OPLIST
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

Add = _reflection.GeneratedProtocolMessageType('Add', (_message.Message,), dict(
  DESCRIPTOR = _ADD,
  __module__ = 'playlist4ops_pb2'
  # @@protoc_insertion_point(class_scope:Add)
  ))
_sym_db.RegisterMessage(Add)

Rem = _reflection.GeneratedProtocolMessageType('Rem', (_message.Message,), dict(
  DESCRIPTOR = _REM,
  __module__ = 'playlist4ops_pb2'
  # @@protoc_insertion_point(class_scope:Rem)
  ))
_sym_db.RegisterMessage(Rem)

Mov = _reflection.GeneratedProtocolMessageType('Mov', (_message.Message,), dict(
  DESCRIPTOR = _MOV,
  __module__ = 'playlist4ops_pb2'
  # @@protoc_insertion_point(class_scope:Mov)
  ))
_sym_db.RegisterMessage(Mov)

ItemAttributesPartialState = _reflection.GeneratedProtocolMessageType('ItemAttributesPartialState', (_message.Message,), dict(
  DESCRIPTOR = _ITEMATTRIBUTESPARTIALSTATE,
  __module__ = 'playlist4ops_pb2'
  # @@protoc_insertion_point(class_scope:ItemAttributesPartialState)
  ))
_sym_db.RegisterMessage(ItemAttributesPartialState)

ListAttributesPartialState = _reflection.GeneratedProtocolMessageType('ListAttributesPartialState', (_message.Message,), dict(
  DESCRIPTOR = _LISTATTRIBUTESPARTIALSTATE,
  __module__ = 'playlist4ops_pb2'
  # @@protoc_insertion_point(class_scope:ListAttributesPartialState)
  ))
_sym_db.RegisterMessage(ListAttributesPartialState)

UpdateItemAttributes = _reflection.GeneratedProtocolMessageType('UpdateItemAttributes', (_message.Message,), dict(
  DESCRIPTOR = _UPDATEITEMATTRIBUTES,
  __module__ = 'playlist4ops_pb2'
  # @@protoc_insertion_point(class_scope:UpdateItemAttributes)
  ))
_sym_db.RegisterMessage(UpdateItemAttributes)

UpdateListAttributes = _reflection.GeneratedProtocolMessageType('UpdateListAttributes', (_message.Message,), dict(
  DESCRIPTOR = _UPDATELISTATTRIBUTES,
  __module__ = 'playlist4ops_pb2'
  # @@protoc_insertion_point(class_scope:UpdateListAttributes)
  ))
_sym_db.RegisterMessage(UpdateListAttributes)

Op = _reflection.GeneratedProtocolMessageType('Op', (_message.Message,), dict(
  DESCRIPTOR = _OP,
  __module__ = 'playlist4ops_pb2'
  # @@protoc_insertion_point(class_scope:Op)
  ))
_sym_db.RegisterMessage(Op)

OpList = _reflection.GeneratedProtocolMessageType('OpList', (_message.Message,), dict(
  DESCRIPTOR = _OPLIST,
  __module__ = 'playlist4ops_pb2'
  # @@protoc_insertion_point(class_scope:OpList)
  ))
_sym_db.RegisterMessage(OpList)


# @@protoc_insertion_point(module_scope)

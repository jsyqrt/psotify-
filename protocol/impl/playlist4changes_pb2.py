# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: playlist4changes.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import playlist4ops_pb2 as playlist4ops__pb2
import playlist4meta_pb2 as playlist4meta__pb2
import playlist4content_pb2 as playlist4content__pb2
import playlist4issues_pb2 as playlist4issues__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='playlist4changes.proto',
  package='',
  syntax='proto2',
  serialized_pb=_b('\n\x16playlist4changes.proto\x1a\x12playlist4ops.proto\x1a\x13playlist4meta.proto\x1a\x16playlist4content.proto\x1a\x15playlist4issues.proto\"\x8e\x01\n\nChangeInfo\x12\x0c\n\x04user\x18\x01 \x01(\t\x12\x11\n\ttimestamp\x18\x02 \x01(\x05\x12\r\n\x05\x61\x64min\x18\x03 \x01(\x08\x12\x0c\n\x04undo\x18\x04 \x01(\x08\x12\x0c\n\x04redo\x18\x05 \x01(\x08\x12\r\n\x05merge\x18\x06 \x01(\x08\x12\x12\n\ncompressed\x18\x07 \x01(\x08\x12\x11\n\tmigration\x18\x08 \x01(\x08\"J\n\x05\x44\x65lta\x12\x14\n\x0c\x62\x61se_version\x18\x01 \x01(\x0c\x12\x10\n\x03ops\x18\x02 \x03(\x0b\x32\x03.Op\x12\x19\n\x04info\x18\x04 \x01(\x0b\x32\x0b.ChangeInfo\"O\n\x05Merge\x12\x14\n\x0c\x62\x61se_version\x18\x01 \x01(\x0c\x12\x15\n\rmerge_version\x18\x02 \x01(\x0c\x12\x19\n\x04info\x18\x04 \x01(\x0b\x32\x0b.ChangeInfo\"\x88\x01\n\tChangeSet\x12\x1d\n\x04kind\x18\x01 \x01(\x0e\x32\x0f.ChangeSet.Kind\x12\x15\n\x05\x64\x65lta\x18\x02 \x01(\x0b\x32\x06.Delta\x12\x15\n\x05merge\x18\x03 \x01(\x0b\x32\x06.Merge\".\n\x04Kind\x12\x10\n\x0cKIND_UNKNOWN\x10\x00\x12\t\n\x05\x44\x45LTA\x10\x02\x12\t\n\x05MERGE\x10\x03\"K\n\x17RevisionTaggedChangeSet\x12\x10\n\x08revision\x18\x01 \x01(\x0c\x12\x1e\n\nchange_set\x18\x02 \x01(\x0b\x32\n.ChangeSet\"D\n\x04\x44iff\x12\x15\n\rfrom_revision\x18\x01 \x01(\x0c\x12\x10\n\x03ops\x18\x02 \x03(\x0b\x32\x03.Op\x12\x13\n\x0bto_revision\x18\x03 \x01(\x0c\"\xb5\x01\n\x08ListDump\x12\x16\n\x0elatestRevision\x18\x01 \x01(\x0c\x12\x0e\n\x06length\x18\x02 \x01(\x05\x12#\n\nattributes\x18\x03 \x01(\x0b\x32\x0f.ListAttributes\x12\x1f\n\x08\x63hecksum\x18\x04 \x01(\x0b\x32\r.ListChecksum\x12\x1c\n\x08\x63ontents\x18\x05 \x01(\x0b\x32\n.ListItems\x12\x1d\n\rpendingDeltas\x18\x07 \x03(\x0b\x32\x06.Delta\"\x9c\x01\n\x0bListChanges\x12\x14\n\x0c\x62\x61seRevision\x18\x01 \x01(\x0c\x12\x16\n\x06\x64\x65ltas\x18\x02 \x03(\x0b\x32\x06.Delta\x12\x1e\n\x16wantResultingRevisions\x18\x03 \x01(\x08\x12\x16\n\x0ewantSyncResult\x18\x04 \x01(\x08\x12\x17\n\x04\x64ump\x18\x05 \x01(\x0b\x32\t.ListDump\x12\x0e\n\x06nonces\x18\x06 \x03(\x05\"\xeb\x02\n\x13SelectedListContent\x12\x10\n\x08revision\x18\x01 \x01(\x0c\x12\x0e\n\x06length\x18\x02 \x01(\x05\x12#\n\nattributes\x18\x03 \x01(\x0b\x32\x0f.ListAttributes\x12\x1f\n\x08\x63hecksum\x18\x04 \x01(\x0b\x32\r.ListChecksum\x12\x1c\n\x08\x63ontents\x18\x05 \x01(\x0b\x32\n.ListItems\x12\x13\n\x04\x64iff\x18\x06 \x01(\x0b\x32\x05.Diff\x12\x19\n\nsyncResult\x18\x07 \x01(\x0b\x32\x05.Diff\x12\x1a\n\x12resultingRevisions\x18\x08 \x03(\x0c\x12\x15\n\rmultipleHeads\x18\t \x01(\x08\x12\x10\n\x08upToDate\x18\n \x01(\x08\x12+\n\rresolveAction\x18\x0c \x03(\x0b\x32\x14.ClientResolveAction\x12\x1c\n\x06issues\x18\r \x03(\x0b\x32\x0c.ClientIssue\x12\x0e\n\x06nonces\x18\x0e \x03(\x05')
  ,
  dependencies=[playlist4ops__pb2.DESCRIPTOR,playlist4meta__pb2.DESCRIPTOR,playlist4content__pb2.DESCRIPTOR,playlist4issues__pb2.DESCRIPTOR,])



_CHANGESET_KIND = _descriptor.EnumDescriptor(
  name='Kind',
  full_name='ChangeSet.Kind',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='KIND_UNKNOWN', index=0, number=0,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='DELTA', index=1, number=2,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='MERGE', index=2, number=3,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=507,
  serialized_end=553,
)
_sym_db.RegisterEnumDescriptor(_CHANGESET_KIND)


_CHANGEINFO = _descriptor.Descriptor(
  name='ChangeInfo',
  full_name='ChangeInfo',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='user', full_name='ChangeInfo.user', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='timestamp', full_name='ChangeInfo.timestamp', index=1,
      number=2, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='admin', full_name='ChangeInfo.admin', index=2,
      number=3, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='undo', full_name='ChangeInfo.undo', index=3,
      number=4, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='redo', full_name='ChangeInfo.redo', index=4,
      number=5, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='merge', full_name='ChangeInfo.merge', index=5,
      number=6, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='compressed', full_name='ChangeInfo.compressed', index=6,
      number=7, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='migration', full_name='ChangeInfo.migration', index=7,
      number=8, type=8, cpp_type=7, label=1,
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
  serialized_start=115,
  serialized_end=257,
)


_DELTA = _descriptor.Descriptor(
  name='Delta',
  full_name='Delta',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='base_version', full_name='Delta.base_version', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='ops', full_name='Delta.ops', index=1,
      number=2, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='info', full_name='Delta.info', index=2,
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
  serialized_start=259,
  serialized_end=333,
)


_MERGE = _descriptor.Descriptor(
  name='Merge',
  full_name='Merge',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='base_version', full_name='Merge.base_version', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='merge_version', full_name='Merge.merge_version', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='info', full_name='Merge.info', index=2,
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
  serialized_start=335,
  serialized_end=414,
)


_CHANGESET = _descriptor.Descriptor(
  name='ChangeSet',
  full_name='ChangeSet',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='kind', full_name='ChangeSet.kind', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='delta', full_name='ChangeSet.delta', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='merge', full_name='ChangeSet.merge', index=2,
      number=3, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _CHANGESET_KIND,
  ],
  options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=417,
  serialized_end=553,
)


_REVISIONTAGGEDCHANGESET = _descriptor.Descriptor(
  name='RevisionTaggedChangeSet',
  full_name='RevisionTaggedChangeSet',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='revision', full_name='RevisionTaggedChangeSet.revision', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='change_set', full_name='RevisionTaggedChangeSet.change_set', index=1,
      number=2, type=11, cpp_type=10, label=1,
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
  serialized_start=555,
  serialized_end=630,
)


_DIFF = _descriptor.Descriptor(
  name='Diff',
  full_name='Diff',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='from_revision', full_name='Diff.from_revision', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='ops', full_name='Diff.ops', index=1,
      number=2, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='to_revision', full_name='Diff.to_revision', index=2,
      number=3, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
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
  serialized_start=632,
  serialized_end=700,
)


_LISTDUMP = _descriptor.Descriptor(
  name='ListDump',
  full_name='ListDump',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='latestRevision', full_name='ListDump.latestRevision', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='length', full_name='ListDump.length', index=1,
      number=2, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='attributes', full_name='ListDump.attributes', index=2,
      number=3, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='checksum', full_name='ListDump.checksum', index=3,
      number=4, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='contents', full_name='ListDump.contents', index=4,
      number=5, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='pendingDeltas', full_name='ListDump.pendingDeltas', index=5,
      number=7, type=11, cpp_type=10, label=3,
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
  serialized_start=703,
  serialized_end=884,
)


_LISTCHANGES = _descriptor.Descriptor(
  name='ListChanges',
  full_name='ListChanges',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='baseRevision', full_name='ListChanges.baseRevision', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='deltas', full_name='ListChanges.deltas', index=1,
      number=2, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='wantResultingRevisions', full_name='ListChanges.wantResultingRevisions', index=2,
      number=3, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='wantSyncResult', full_name='ListChanges.wantSyncResult', index=3,
      number=4, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='dump', full_name='ListChanges.dump', index=4,
      number=5, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='nonces', full_name='ListChanges.nonces', index=5,
      number=6, type=5, cpp_type=1, label=3,
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
  serialized_start=887,
  serialized_end=1043,
)


_SELECTEDLISTCONTENT = _descriptor.Descriptor(
  name='SelectedListContent',
  full_name='SelectedListContent',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='revision', full_name='SelectedListContent.revision', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='length', full_name='SelectedListContent.length', index=1,
      number=2, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='attributes', full_name='SelectedListContent.attributes', index=2,
      number=3, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='checksum', full_name='SelectedListContent.checksum', index=3,
      number=4, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='contents', full_name='SelectedListContent.contents', index=4,
      number=5, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='diff', full_name='SelectedListContent.diff', index=5,
      number=6, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='syncResult', full_name='SelectedListContent.syncResult', index=6,
      number=7, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='resultingRevisions', full_name='SelectedListContent.resultingRevisions', index=7,
      number=8, type=12, cpp_type=9, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='multipleHeads', full_name='SelectedListContent.multipleHeads', index=8,
      number=9, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='upToDate', full_name='SelectedListContent.upToDate', index=9,
      number=10, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='resolveAction', full_name='SelectedListContent.resolveAction', index=10,
      number=12, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='issues', full_name='SelectedListContent.issues', index=11,
      number=13, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='nonces', full_name='SelectedListContent.nonces', index=12,
      number=14, type=5, cpp_type=1, label=3,
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
  serialized_start=1046,
  serialized_end=1409,
)

_DELTA.fields_by_name['ops'].message_type = playlist4ops__pb2._OP
_DELTA.fields_by_name['info'].message_type = _CHANGEINFO
_MERGE.fields_by_name['info'].message_type = _CHANGEINFO
_CHANGESET.fields_by_name['kind'].enum_type = _CHANGESET_KIND
_CHANGESET.fields_by_name['delta'].message_type = _DELTA
_CHANGESET.fields_by_name['merge'].message_type = _MERGE
_CHANGESET_KIND.containing_type = _CHANGESET
_REVISIONTAGGEDCHANGESET.fields_by_name['change_set'].message_type = _CHANGESET
_DIFF.fields_by_name['ops'].message_type = playlist4ops__pb2._OP
_LISTDUMP.fields_by_name['attributes'].message_type = playlist4meta__pb2._LISTATTRIBUTES
_LISTDUMP.fields_by_name['checksum'].message_type = playlist4meta__pb2._LISTCHECKSUM
_LISTDUMP.fields_by_name['contents'].message_type = playlist4content__pb2._LISTITEMS
_LISTDUMP.fields_by_name['pendingDeltas'].message_type = _DELTA
_LISTCHANGES.fields_by_name['deltas'].message_type = _DELTA
_LISTCHANGES.fields_by_name['dump'].message_type = _LISTDUMP
_SELECTEDLISTCONTENT.fields_by_name['attributes'].message_type = playlist4meta__pb2._LISTATTRIBUTES
_SELECTEDLISTCONTENT.fields_by_name['checksum'].message_type = playlist4meta__pb2._LISTCHECKSUM
_SELECTEDLISTCONTENT.fields_by_name['contents'].message_type = playlist4content__pb2._LISTITEMS
_SELECTEDLISTCONTENT.fields_by_name['diff'].message_type = _DIFF
_SELECTEDLISTCONTENT.fields_by_name['syncResult'].message_type = _DIFF
_SELECTEDLISTCONTENT.fields_by_name['resolveAction'].message_type = playlist4issues__pb2._CLIENTRESOLVEACTION
_SELECTEDLISTCONTENT.fields_by_name['issues'].message_type = playlist4issues__pb2._CLIENTISSUE
DESCRIPTOR.message_types_by_name['ChangeInfo'] = _CHANGEINFO
DESCRIPTOR.message_types_by_name['Delta'] = _DELTA
DESCRIPTOR.message_types_by_name['Merge'] = _MERGE
DESCRIPTOR.message_types_by_name['ChangeSet'] = _CHANGESET
DESCRIPTOR.message_types_by_name['RevisionTaggedChangeSet'] = _REVISIONTAGGEDCHANGESET
DESCRIPTOR.message_types_by_name['Diff'] = _DIFF
DESCRIPTOR.message_types_by_name['ListDump'] = _LISTDUMP
DESCRIPTOR.message_types_by_name['ListChanges'] = _LISTCHANGES
DESCRIPTOR.message_types_by_name['SelectedListContent'] = _SELECTEDLISTCONTENT
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

ChangeInfo = _reflection.GeneratedProtocolMessageType('ChangeInfo', (_message.Message,), dict(
  DESCRIPTOR = _CHANGEINFO,
  __module__ = 'playlist4changes_pb2'
  # @@protoc_insertion_point(class_scope:ChangeInfo)
  ))
_sym_db.RegisterMessage(ChangeInfo)

Delta = _reflection.GeneratedProtocolMessageType('Delta', (_message.Message,), dict(
  DESCRIPTOR = _DELTA,
  __module__ = 'playlist4changes_pb2'
  # @@protoc_insertion_point(class_scope:Delta)
  ))
_sym_db.RegisterMessage(Delta)

Merge = _reflection.GeneratedProtocolMessageType('Merge', (_message.Message,), dict(
  DESCRIPTOR = _MERGE,
  __module__ = 'playlist4changes_pb2'
  # @@protoc_insertion_point(class_scope:Merge)
  ))
_sym_db.RegisterMessage(Merge)

ChangeSet = _reflection.GeneratedProtocolMessageType('ChangeSet', (_message.Message,), dict(
  DESCRIPTOR = _CHANGESET,
  __module__ = 'playlist4changes_pb2'
  # @@protoc_insertion_point(class_scope:ChangeSet)
  ))
_sym_db.RegisterMessage(ChangeSet)

RevisionTaggedChangeSet = _reflection.GeneratedProtocolMessageType('RevisionTaggedChangeSet', (_message.Message,), dict(
  DESCRIPTOR = _REVISIONTAGGEDCHANGESET,
  __module__ = 'playlist4changes_pb2'
  # @@protoc_insertion_point(class_scope:RevisionTaggedChangeSet)
  ))
_sym_db.RegisterMessage(RevisionTaggedChangeSet)

Diff = _reflection.GeneratedProtocolMessageType('Diff', (_message.Message,), dict(
  DESCRIPTOR = _DIFF,
  __module__ = 'playlist4changes_pb2'
  # @@protoc_insertion_point(class_scope:Diff)
  ))
_sym_db.RegisterMessage(Diff)

ListDump = _reflection.GeneratedProtocolMessageType('ListDump', (_message.Message,), dict(
  DESCRIPTOR = _LISTDUMP,
  __module__ = 'playlist4changes_pb2'
  # @@protoc_insertion_point(class_scope:ListDump)
  ))
_sym_db.RegisterMessage(ListDump)

ListChanges = _reflection.GeneratedProtocolMessageType('ListChanges', (_message.Message,), dict(
  DESCRIPTOR = _LISTCHANGES,
  __module__ = 'playlist4changes_pb2'
  # @@protoc_insertion_point(class_scope:ListChanges)
  ))
_sym_db.RegisterMessage(ListChanges)

SelectedListContent = _reflection.GeneratedProtocolMessageType('SelectedListContent', (_message.Message,), dict(
  DESCRIPTOR = _SELECTEDLISTCONTENT,
  __module__ = 'playlist4changes_pb2'
  # @@protoc_insertion_point(class_scope:SelectedListContent)
  ))
_sym_db.RegisterMessage(SelectedListContent)


# @@protoc_insertion_point(module_scope)

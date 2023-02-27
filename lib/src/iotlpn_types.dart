import 'dart:convert';
import 'dart:typed_data';

typedef DeviceID = Uint8List;

class IoTLPNException implements Exception {
  final String cause;
  const IoTLPNException(this.cause);

  @override
  String toString() => cause;
}

extension IoTLPNByteManipulation on Uint8List {
  /// Replace existing values with ones in [insert]
  void insertInto(int offset, Uint8List insert) {
    for (int i = 0; i < insert.length; i++) {
      this[i + offset] = insert[i];
    }
  }

  String toHexString([String separator = '']) =>
      map((e) => e.toRadixString(16).padLeft(2, '0').toUpperCase())
          .toList()
          .join(separator);

  String toAscii() => ascii.decode(this);
}

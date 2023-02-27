import 'dart:convert';
import 'dart:typed_data';

import 'package:iotlpn/src/iotlpn_security.dart';
import 'package:msgpack_dart/msgpack_dart.dart' as msgpack;

import './iotlpn_commands.dart';
import './iotlpn_types.dart';

const messageSizeBytes = 256;
const instructionSizeBytes = 32;
const contentSizeBytes = 192;
const bodySizeBytes = instructionSizeBytes + contentSizeBytes;

class InvalidBinarySizeException extends IoTLPNException {
  InvalidBinarySizeException(int size, int expected)
      : super("Expected <$expected> bytes of data, got <$size>");
}

class InvalidMessageSizeException extends IoTLPNException {
  InvalidMessageSizeException(int size)
      : super(
            'Invalid message size, must be <$messageSizeBytes> and got <$size>');
}

class InvalidJsonFormat extends IoTLPNException {
  const InvalidJsonFormat(String cause) : super("InvalidJsonFormat: $cause");
}

class Message {
  final Command command;
  final int options;
  final DeviceID origin;
  final DeviceID destination;
  final int transaction;

  int _contentSize = 0;
  Uint8List iv = Uint8List(16);
  final Uint8List _instruction = Uint8List(instructionSizeBytes);
  final Uint8List _content = Uint8List(contentSizeBytes);

  Message(
      {required this.command,
      this.options = 0,
      required this.origin,
      required this.destination,
      required this.transaction});

  static Future<Message> fromBytes(
      Uint8List data, SecurityHandler securityHandler) async {
    if (data.length != messageSizeBytes) {
      throw InvalidMessageSizeException(data.length);
    }

    final newMessage = Message(
        command: Command.fromCode(data[0]),
        options: data[1],
        origin: data.sublist(2, 8),
        destination: data.sublist(8, 14),
        transaction: data[14]);

    newMessage.iv = data.sublist(16, 32);
    final contentSize = data[15];
    final toDecrypt = data.sublist(32);

    final decrypted = await securityHandler.bytesDecryption(
        toDecrypt, newMessage.iv, bodySizeBytes);

    newMessage.addInstructionBinary(decrypted.sublist(0, 32));
    newMessage.addContentBinary(decrypted.sublist(32), contentSize);
    return newMessage;
  }

  Future<Uint8List> toBinary(SecurityHandler securityHandler) async {
    // Header
    final header = BytesBuilder();
    header.addByte(command.code);
    header.addByte(options);
    header.add(origin);
    header.add(destination);
    header.addByte(transaction);
    header.addByte(_contentSize);

    // IV
    iv = await securityHandler.randomIV();

    // Body
    final bodyUnencrypted = BytesBuilder();
    bodyUnencrypted.add(_instruction);
    bodyUnencrypted.add(_content);

    // Handle encryption
    final bodyEncrypted = Uint8List(bodySizeBytes);
    bodyEncrypted.insertInto(
        0,
        await securityHandler.bytesEncryption(
            bodyUnencrypted.toBytes(), iv, bodySizeBytes));

    // Return encrypted data
    final concatenate = BytesBuilder();
    concatenate.add(header.toBytes());
    concatenate.add(iv);
    concatenate.add(bodyEncrypted);

    if (concatenate.length != messageSizeBytes) {
      throw InvalidMessageSizeException(concatenate.length);
    }

    return concatenate.toBytes();
  }

  void addInstructionString(String instruction) =>
      _instruction.insertInto(0, ascii.encode(instruction));

  void addInstructionBinary(Uint8List data) {
    if (data.length != instructionSizeBytes) {
      throw InvalidBinarySizeException(data.length, instructionSizeBytes);
    }
    _instruction.insertInto(0, data);
  }

  void addContentJson(Map<String, dynamic> content) {
    final binary = msgpack.serialize(content);
    if (binary.length > contentSizeBytes) {
      throw InvalidJsonFormat(
          "Size cannot exceed <$contentSizeBytes>, got <${binary.length}>");
    }
    _contentSize = binary.length;
    _content.insertInto(0, binary);
  }

  void addContentBinary(Uint8List data, int size) {
    if (size > contentSizeBytes) {
      throw InvalidBinarySizeException(size, contentSizeBytes);
    }
    _contentSize = size;
    _content.insertInto(0, data);
  }

  String instructionAsString() =>
      ascii.decode(_instruction).replaceAll("\x00", "");

  Map<String, dynamic> contentAsJson() =>
      Map<String, dynamic>.from(msgpack.deserialize(_content));

  @override
  String toString() {
    // Return command
    return '''<IoTLPN Message>
  COMMAND: ${command.name.toUpperCase()}
  OPTIONS: $options
  NETWORK: ${origin.toHexString(':')} ${destination.toHexString(':')} ($transaction)
  IV: ${iv.toHexString()}
  INSTRUCTION: ${instructionAsString()}
  CONTENT ($_contentSize): ${contentAsJson()}
</IoTLPN Message>''';
  }
}

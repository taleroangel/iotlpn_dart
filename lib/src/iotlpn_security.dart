import 'dart:convert';
import 'dart:typed_data';
import 'dart:math';

import 'package:iotlpn/src/iotlpn_types.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/block/aes.dart';
import 'package:pointycastle/block/modes/cbc.dart';
import 'package:pointycastle/digests/md5.dart';

class EncryptionInvalidContentSize extends IoTLPNException {
  EncryptionInvalidContentSize(int size)
      : super(
            "Invalid encryption size, must be divisible by 16 and got <$size>");
}

abstract class SecurityHandler {
  Future<Uint8List> randomIV();
  Future<Uint8List> bytesDecryption(Uint8List decrypt, Uint8List iv, int size);
  Future<Uint8List> bytesEncryption(Uint8List encrypt, Uint8List iv, int size);
}

class Authentication implements SecurityHandler {
  static const maxRandomNumber = 0xFFFFFF;
  final md5 = MD5Digest();
  final secureRandom = Random.secure();
  final aes = CBCBlockCipher(AESEngine());
  late final Uint8List key;

  Authentication({required String network, required String password}) {
    key = md5.process(ascii.encode('$network $password'));
  }

  @override
  Future<Uint8List> randomIV() async =>
      md5.process(Uint8List.fromList([secureRandom.nextInt(maxRandomNumber)]));

  @override
  Future<Uint8List> bytesDecryption(
      Uint8List decrypt, Uint8List iv, int size) async {
    if (size % 16 != 0) {
      throw EncryptionInvalidContentSize(size);
    }
    aes.init(false, ParametersWithIV(KeyParameter(key), iv));

    final cipherText = Uint8List(size);

    var offset = 0;
    while (offset < size) {
      offset += aes.processBlock(decrypt, offset, cipherText, offset);
    }

    return cipherText;
  }

  @override
  Future<Uint8List> bytesEncryption(
      Uint8List encrypt, Uint8List iv, int size) async {
    if (size % 16 != 0) {
      throw EncryptionInvalidContentSize(size);
    }
    aes.init(true, ParametersWithIV(KeyParameter(key), iv));

    final cipherText = Uint8List(size);

    var offset = 0;
    while (offset < size) {
      offset += aes.processBlock(encrypt, offset, cipherText, offset);
    }

    return cipherText;
  }
}

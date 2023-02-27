import 'dart:typed_data';

import 'package:iotlpn/iotlpn.dart';

void main() async {
  try {
    final securityHandler =
        Authentication(network: "network_name", password: "password");
    print("Authentication key is: ${securityHandler.key.toHexString()}");

    var command = Message(
        command: Command.discovery,
        options: DiscoveryOptions.type.code | DiscoveryOptions.ping.code,
        origin: Uint8List.fromList([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
        destination: Uint8List.fromList([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        transaction: 0);

    command.addInstructionString("iotlpn:*");
    command.addContentJson({
      "id": [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
      "type": "iotlpn:debug",
      "vendor": "iotlpn"
    });

    final binary = (await command.toBinary(securityHandler));
    print("\nUnencrypted Command:\n$command");
    print("\nBinary format:\n${binary.toHexString(' ')}");

    final decrypted = await Message.fromBytes(binary, securityHandler);
    print("\nDecrypted Command:\n$decrypted");
  } on Exception catch (e) {
    print(e.toString());
  }
}

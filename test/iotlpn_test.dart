import 'dart:io';
import 'dart:typed_data';

import 'package:iotlpn/iotlpn.dart';
import 'package:test/test.dart';

void main() {
  final securityHandler =
      Authentication(network: "network_name", password: "password");

  test("Simple message decryption test", () async {
    final binary = await File('./test/discovery_encrypted.dat').readAsBytes();
    final message = await Message.fromBytes(binary, securityHandler);

    expect(message.command, Command.discovery);
    expect(message.options,
        DiscoveryOptions.type.code | DiscoveryOptions.ping.code);
    expect(message.origin,
        Uint8List.fromList([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]));
    expect(message.destination, Uint8List(6));
    expect(message.instructionAsString(), "iotlpn:*");
    expect(message.contentAsJson(), {
      "id": [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
      "type": "iotlpn:debug",
      "vendor": "iotlpn"
    });
  });
}

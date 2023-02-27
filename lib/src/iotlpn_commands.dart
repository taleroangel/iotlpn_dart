enum Command {
  discovery(0),
  resource(1),
  property(2),
  interact(3);

  final int code;
  const Command(this.code);

  static Command fromCode(int code) {
    return Command.values.where((element) => element.code == code).first;
  }
}

abstract class Options {}

enum DiscoveryOptions implements Options {
  // Base options
  any(0),
  id(1),
  type(2),
  vendor(3),
  // Mask arguments
  discover(0),
  ping(4);

  final int code;
  const DiscoveryOptions(this.code);
}

enum ResourceOptions implements Options {
  // Base options
  request(0),
  content(1),
  ack(2),
  // Mask arguments
  moref(12);

  final int code;
  const ResourceOptions(this.code);
}

enum PropertyInteractOptions implements Options {
  // Device options
  get(0),
  set(1),
  // Agent options
  success(2),
  error(3);

  final int code;
  const PropertyInteractOptions(this.code);
}

typedef PropertyOptions = PropertyInteractOptions;
typedef InteractOptions = PropertyInteractOptions;

class AndroidOptions {
  final bool authRequired;
  final String? tag;
  final bool oncePrompt;
  final int authValidityDuration;

  AndroidOptions({
    required this.authRequired,
    this.tag,
    this.oncePrompt = false,
    this.authValidityDuration = 10,
  });

  AndroidOptions copyWith({
    bool? authRequired,
    String? tag,
    bool? oncePrompt,
    int? authValidityDuration,
  }) {
    return AndroidOptions(
      authRequired: authRequired ?? this.authRequired,
      tag: tag ?? this.tag,
      oncePrompt: oncePrompt ?? this.oncePrompt,
      authValidityDuration: authValidityDuration ?? this.authValidityDuration,
    );
  }

  Map<String, dynamic> toMap() {
    return <String, dynamic>{
      'authRequired': authRequired,
      'tag': tag,
      'authValidityDuration': authValidityDuration,
      'oncePrompt': oncePrompt,
    };
  }
}

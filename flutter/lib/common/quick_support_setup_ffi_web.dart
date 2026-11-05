const String _unavailable =
    '{"state":"unavailable","detail":"Quick Support setup is unavailable on the web build","technician_id":null,"fingerprint":null}';

Future<String> quickSupportSetupStatus() async => _unavailable;

Future<String> quickSupportSetupSignIn() async => _unavailable;

Future<String> quickSupportSetupSignOut() async => _unavailable;

Future<String> quickSupportSetupEnroll(String requestId) async => _unavailable;

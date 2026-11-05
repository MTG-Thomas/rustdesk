import 'package:flutter_hbb/models/platform_model.dart';

Future<String> quickSupportSetupStatus() => bind.quickSupportSetupStatus();

Future<String> quickSupportSetupSignIn() => bind.quickSupportSetupSignIn();

Future<String> quickSupportSetupSignOut() => bind.quickSupportSetupSignOut();

Future<String> quickSupportSetupEnroll(String requestId) =>
    bind.quickSupportSetupEnroll(requestId: requestId);

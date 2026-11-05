import 'dart:convert';

import 'package:uuid/uuid.dart';

const String quickSupportUnavailableDetail =
    'Quick Support setup is unavailable until release configuration and the issuer are installed.';

const Set<String> _states = {
  'unavailable',
  'signed_out',
  'signing_in',
  'signed_in',
  'enrolled',
};

/// Parsed setup status. This is UI state only, never authorization: the native
/// host and the workflow remain the authority for login, enrollment and receipts.
class QuickSupportSetupStatus {
  final String state;
  final String detail;
  final String? technicianId;
  final String? fingerprint;

  const QuickSupportSetupStatus({
    required this.state,
    required this.detail,
    this.technicianId,
    this.fingerprint,
  });

  bool get isUnavailable => state == 'unavailable';
  bool get isSigningIn => state == 'signing_in';
  bool get isSignedOut => state == 'signed_out';
  bool get isSignedIn => state == 'signed_in' || state == 'enrolled';
  bool get canSignIn => isSignedOut;
  bool get canSignOut => isSignedIn;
  bool get canEnroll => state == 'signed_in';
  bool get isEnrolled => state == 'enrolled';

  static const QuickSupportSetupStatus unavailable = QuickSupportSetupStatus(
    state: 'unavailable',
    detail: quickSupportUnavailableDetail,
  );

  /// Accepts only the documented state names and never invents identity or a
  /// fingerprint. Anything unexpected degrades to unavailable.
  static QuickSupportSetupStatus fromJson(String raw) {
    try {
      final value = jsonDecode(raw);
      if (value is! Map<String, dynamic>) {
        return unavailable;
      }
      final state = value['state'];
      final detail = value['detail'];
      if (state is! String || !_states.contains(state)) {
        return unavailable;
      }
      if (detail is! String || detail.trim().isEmpty) {
        return unavailable;
      }
      var technicianId = _optionalText(value['technician_id']);
      var fingerprint = _optionalText(value['fingerprint']);
      if (state == 'signed_in' || state == 'enrolled') {
        if (technicianId == null) {
          return unavailable;
        }
      } else {
        technicianId = null;
      }
      if (state != 'enrolled') {
        fingerprint = null;
      }
      if (state == 'enrolled' && fingerprint == null) {
        return unavailable;
      }
      return QuickSupportSetupStatus(
        state: state,
        detail: detail,
        technicianId: technicianId,
        fingerprint: fingerprint,
      );
    } catch (_) {
      return unavailable;
    }
  }

  static String? _optionalText(dynamic value) {
    if (value is! String || value.isEmpty) {
      return null;
    }
    return value;
  }
}

/// The UI retains this request id before calling enrollment and must reconcile
/// an uncertain result instead of generating a replacement.
String newQuickSupportRequestId() => Uuid().v4();

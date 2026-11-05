import 'dart:convert';

import 'package:flutter_hbb/common/quick_support_setup.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('unavailable status has no identity or fingerprint', () {
    final status = QuickSupportSetupStatus.fromJson(jsonEncode({
      'state': 'unavailable',
      'detail': 'not installed',
      'technician_id': '33333333-3333-4333-8333-333333333333',
      'fingerprint': 'deadbeef',
    }));
    expect(status.isUnavailable, isTrue);
    expect(status.technicianId, isNull);
    expect(status.fingerprint, isNull);
    expect(status.canSignIn, isFalse);
    expect(status.canEnroll, isFalse);
  });

  test('signing in carries no identity and no fingerprint', () {
    final status = QuickSupportSetupStatus.fromJson(jsonEncode({
      'state': 'signing_in',
      'detail': 'waiting for browser sign-in',
      'technician_id': '33333333-3333-4333-8333-333333333333',
      'fingerprint': 'deadbeef',
    }));
    expect(status.isSigningIn, isTrue);
    expect(status.technicianId, isNull);
    expect(status.fingerprint, isNull);
    expect(status.canSignIn, isFalse);
    expect(status.canEnroll, isFalse);
  });

  test('signed in requires a technician and keeps no fingerprint', () {
    final status = QuickSupportSetupStatus.fromJson(jsonEncode({
      'state': 'signed_in',
      'detail': 'signed in',
      'technician_id': '33333333-3333-4333-8333-333333333333',
      'fingerprint': 'deadbeef',
    }));
    expect(status.isSignedIn, isTrue);
    expect(status.canSignOut, isTrue);
    expect(status.canEnroll, isTrue);
    expect(status.fingerprint, isNull);
  });

  test('signed in without a technician degrades to unavailable', () {
    final status = QuickSupportSetupStatus.fromJson(jsonEncode({
      'state': 'signed_in',
      'detail': 'signed in',
      'technician_id': null,
    }));
    expect(status.isUnavailable, isTrue);
  });

  test('enrolled keeps the fingerprint and requires it', () {
    final status = QuickSupportSetupStatus.fromJson(jsonEncode({
      'state': 'enrolled',
      'detail': 'enrolled',
      'technician_id': '33333333-3333-4333-8333-333333333333',
      'fingerprint': 'abc123',
    }));
    expect(status.isEnrolled, isTrue);
    expect(status.fingerprint, 'abc123');

    final missing = QuickSupportSetupStatus.fromJson(jsonEncode({
      'state': 'enrolled',
      'detail': 'enrolled',
      'technician_id': '33333333-3333-4333-8333-333333333333',
    }));
    expect(missing.isUnavailable, isTrue);
  });

  test('malformed or unknown status never becomes authority', () {
    for (final raw in [
      '',
      'not json',
      '[]',
      '{"state":"admin"}',
      '{"state":"signed_out"}',
      '{"state":"signed_out","detail":""}'
    ]) {
      final status = QuickSupportSetupStatus.fromJson(raw);
      expect(status.isUnavailable, isTrue, reason: raw);
      expect(status.technicianId, isNull);
      expect(status.fingerprint, isNull);
    }
  });

  test('request ids are retained UUIDs', () {
    final id = newQuickSupportRequestId();
    expect(
        id,
        matches(RegExp(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')));
  });
}

import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/desktop/pages/quick_support_setup_page.dart';
import 'package:flutter_test/flutter_test.dart';

String status(
  String state, {
  String detail = 'detail',
  String? technician,
  String? fingerprint,
}) =>
    jsonEncode({
      'state': state,
      'detail': detail,
      'technician_id': technician,
      'fingerprint': fingerprint,
    });

Widget page({
  required Future<String> Function() load,
  Future<String> Function()? signIn,
  Future<String> Function()? signOut,
  Future<String> Function(String requestId)? enroll,
}) =>
    MaterialApp(
      home: QuickSupportSetupPage(
        loadStatus: load,
        signIn: signIn,
        signOut: signOut,
        enroll: enroll,
        translateText: (name) => name,
      ),
    );

void main() {
  testWidgets('unavailable disables every authority-bearing action',
      (tester) async {
    await tester.pumpWidget(page(load: () async => status('unavailable')));
    await tester.pumpAndSettle();

    expect(find.text('Unavailable'), findsOneWidget);
    expect(
      tester
          .widget<FilledButton>(find.widgetWithText(FilledButton, 'Sign in'))
          .onPressed,
      isNull,
    );
    expect(
      tester
          .widget<FilledButton>(
              find.widgetWithText(FilledButton, 'Enroll this workstation'))
          .onPressed,
      isNull,
    );
    expect(find.textContaining('Technician:'), findsNothing);
    expect(find.textContaining('Workstation fingerprint:'), findsNothing);
  });

  testWidgets('failed sign-in remains fail-closed instead of showing success',
      (tester) async {
    await tester.pumpWidget(page(
      load: () async => status('signed_out', detail: 'signed out'),
      signIn: () async =>
          status('unavailable', detail: 'interactive sign-in is not wired'),
    ));
    await tester.pumpAndSettle();
    expect(find.text('Signed out'), findsOneWidget);

    await tester.tap(find.widgetWithText(FilledButton, 'Sign in'));
    await tester.pumpAndSettle();

    expect(find.text('Unavailable'), findsOneWidget);
    expect(find.textContaining('not wired'), findsOneWidget);
    expect(find.text('Signed in'), findsNothing);
  });

  testWidgets('uncertain enrollment keeps the request id for reconciliation',
      (tester) async {
    final ids = <String>[];
    Future<String> load() async => status(
          'signed_in',
          technician: '33333333-3333-4333-8333-333333333333',
        );
    await tester.pumpWidget(page(
      load: load,
      enroll: (id) async {
        ids.add(id);
        throw Exception('uncertain');
      },
    ));
    await tester.pumpAndSettle();

    await tester
        .tap(find.widgetWithText(FilledButton, 'Enroll this workstation'));
    await tester.pumpAndSettle();
    expect(find.text('Unavailable'), findsOneWidget);
    expect(ids, hasLength(1));

    await tester.tap(find.widgetWithText(TextButton, 'Refresh'));
    await tester.pumpAndSettle();
    await tester
        .tap(find.widgetWithText(FilledButton, 'Enroll this workstation'));
    await tester.pumpAndSettle();
    expect(ids, hasLength(2));
    expect(ids[0], ids[1]);
  });

  testWidgets('signed in shows identity and enables enrollment only then',
      (tester) async {
    await tester.pumpWidget(page(
      load: () async => status(
        'signed_in',
        technician: '33333333-3333-4333-8333-333333333333',
      ),
      enroll: (_) async => status('unavailable', detail: 'enrollment refused'),
    ));
    await tester.pumpAndSettle();

    expect(find.text('Signed in'), findsOneWidget);
    expect(find.textContaining('33333333-3333-4333-8333-333333333333'),
        findsOneWidget);
    expect(
      tester
          .widget<FilledButton>(
              find.widgetWithText(FilledButton, 'Enroll this workstation'))
          .onPressed,
      isNotNull,
    );

    await tester
        .tap(find.widgetWithText(FilledButton, 'Enroll this workstation'));
    await tester.pumpAndSettle();
    expect(find.text('Unavailable'), findsOneWidget);
    expect(find.textContaining('enrollment refused'), findsOneWidget);
  });
}

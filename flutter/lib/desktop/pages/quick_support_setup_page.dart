import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/common/quick_support_setup.dart';
import 'package:flutter_hbb/models/platform_model.dart';

class QuickSupportSetupPage extends StatefulWidget {
  const QuickSupportSetupPage({Key? key}) : super(key: key);

  @override
  State<QuickSupportSetupPage> createState() => _QuickSupportSetupPageState();
}

class _QuickSupportSetupPageState extends State<QuickSupportSetupPage> {
  QuickSupportSetupStatus _status = QuickSupportSetupStatus.unavailable;
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    _refresh();
  }

  Future<void> _refresh() => _run(() => bind.quickSupportSetupStatus());

  Future<void> _signIn() => _run(() => bind.quickSupportSetupSignIn());

  Future<void> _signOut() => _run(() => bind.quickSupportSetupSignOut());

  Future<void> _enroll() {
    // Retain the request id across the call; uncertain results must be
    // reconciled rather than retried under a new id.
    final requestId = newQuickSupportRequestId();
    return _run(() => bind.quickSupportSetupEnroll(requestId: requestId));
  }

  Future<void> _run(Future<String> Function() action) async {
    if (_busy) {
      return;
    }
    setState(() => _busy = true);
    QuickSupportSetupStatus next;
    try {
      next = QuickSupportSetupStatus.fromJson(await action());
    } catch (_) {
      next = QuickSupportSetupStatus.unavailable;
    }
    if (!mounted) {
      return;
    }
    setState(() {
      _status = next;
      _busy = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    final status = _status;
    return Scaffold(
      appBar: AppBar(title: Text(translate('Quick Support'))),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    translate(status.isUnavailable
                        ? 'Unavailable'
                        : status.isSignedOut
                            ? 'Signed out'
                            : 'Signed in'),
                    style: Theme.of(context).textTheme.titleMedium,
                  ),
                  const SizedBox(height: 8),
                  Text(status.detail),
                  if (status.technicianId != null) ...[
                    const SizedBox(height: 8),
                    SelectableText(
                        '${translate('Technician')}: ${status.technicianId}'),
                  ],
                  if (status.fingerprint != null) ...[
                    const SizedBox(height: 8),
                    SelectableText(
                        '${translate('Workstation fingerprint')}: ${status.fingerprint}'),
                  ],
                ],
              ),
            ),
          ),
          const SizedBox(height: 16),
          Wrap(
            spacing: 12,
            runSpacing: 8,
            children: [
              FilledButton(
                onPressed: _busy || !status.canSignIn ? null : () => _signIn(),
                child: Text(translate('Sign in')),
              ),
              OutlinedButton(
                onPressed:
                    _busy || !status.canSignOut ? null : () => _signOut(),
                child: Text(translate('Sign out')),
              ),
              FilledButton(
                onPressed: _busy || !status.canEnroll ? null : () => _enroll(),
                child: Text(translate('Enroll this workstation')),
              ),
              TextButton(
                onPressed: _busy ? null : _refresh,
                child: Text(translate('Refresh')),
              ),
            ],
          ),
          const SizedBox(height: 16),
          Text(
            translate(
                'Quick Support setup is unavailable until release configuration and the issuer are installed.'),
            style: Theme.of(context).textTheme.bodySmall,
          ),
        ],
      ),
    );
  }
}

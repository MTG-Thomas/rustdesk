import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/common/quick_support_setup.dart';
import 'package:flutter_hbb/models/platform_model.dart';

class QuickSupportSetupPage extends StatefulWidget {
  final Future<String> Function()? loadStatus;
  final Future<String> Function()? signIn;
  final Future<String> Function()? signOut;
  final Future<String> Function(String requestId)? enroll;
  final String Function(String name)? translateText;

  const QuickSupportSetupPage({
    Key? key,
    this.loadStatus,
    this.signIn,
    this.signOut,
    this.enroll,
    this.translateText,
  }) : super(key: key);

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

  Future<void> _refresh() =>
      _run(widget.loadStatus ?? () => bind.quickSupportSetupStatus());

  Future<void> _signIn() =>
      _run(widget.signIn ?? () => bind.quickSupportSetupSignIn());

  Future<void> _signOut() =>
      _run(widget.signOut ?? () => bind.quickSupportSetupSignOut());

  Future<void> _enroll() {
    // Retain the request id across the call; uncertain results must be
    // reconciled rather than retried under a new id.
    final requestId = newQuickSupportRequestId();
    final enroll =
        widget.enroll ?? (id) => bind.quickSupportSetupEnroll(requestId: id);
    return _run(() => enroll(requestId));
  }

  String _translate(String name) => (widget.translateText ?? translate)(name);

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
      appBar: AppBar(title: Text(_translate('Quick Support'))),
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
                    _translate(status.isUnavailable
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
                        '${_translate('Technician')}: ${status.technicianId}'),
                  ],
                  if (status.fingerprint != null) ...[
                    const SizedBox(height: 8),
                    SelectableText(
                        '${_translate('Workstation fingerprint')}: ${status.fingerprint}'),
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
                child: Text(_translate('Sign in')),
              ),
              OutlinedButton(
                onPressed:
                    _busy || !status.canSignOut ? null : () => _signOut(),
                child: Text(_translate('Sign out')),
              ),
              FilledButton(
                onPressed: _busy || !status.canEnroll ? null : () => _enroll(),
                child: Text(_translate('Enroll this workstation')),
              ),
              TextButton(
                onPressed: _busy ? null : _refresh,
                child: Text(_translate('Refresh')),
              ),
            ],
          ),
          const SizedBox(height: 16),
          Text(
            _translate(
                'Quick Support setup is unavailable until release configuration and the issuer are installed.'),
            style: Theme.of(context).textTheme.bodySmall,
          ),
        ],
      ),
    );
  }
}

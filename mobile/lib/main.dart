import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;

import 'package:crypto/crypto.dart';
import 'package:material_ui/material_ui.dart';
import 'package:local_auth/local_auth.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:flutter/services.dart';

void main() {
  runApp(const TapBridgeApp());
}

class TapBridgeApp extends StatelessWidget {
  const TapBridgeApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'TapBridge',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF123A5A),
          brightness: Brightness.light,
        ),
        scaffoldBackgroundColor: const Color(0xFFF5F8FA),
      ),
      home: const TapBridgeHome(),
    );
  }
}

enum ConnectionPhase { disconnected, connecting, connected, failed }

enum ConnectionRoute { wifi, usbTether }

extension ConnectionRouteLabel on ConnectionRoute {
  String get label => this == ConnectionRoute.wifi ? 'Wi-Fi' : 'USB tethering';
}

/// Keeps biometric data inside Android's system prompt. TapBridge receives only
/// a success/failure result and never receives or stores fingerprint/face data.
class BiometricGate extends ChangeNotifier {
  final LocalAuthentication _localAuth = LocalAuthentication();

  bool _isUnlocked = false;
  bool _isAuthenticating = false;
  String _message = 'TapBridge is locked.';

  bool get isUnlocked => _isUnlocked;
  bool get isAuthenticating => _isAuthenticating;
  String get message => _message;

  Future<bool> unlock({
    String reason = 'Unlock TapBridge before controlling your PC.',
  }) async {
    if (_isAuthenticating) {
      return false;
    }

    _isAuthenticating = true;
    _message = 'Waiting for fingerprint or face verification…';
    notifyListeners();

    try {
      final canCheckBiometrics = await _localAuth.canCheckBiometrics;
      if (!canCheckBiometrics) {
        _isUnlocked = false;
        _message = 'No enrolled biometric is available. Enrol a fingerprint or face in Android Settings.';
        return false;
      }

      final authenticated = await _localAuth.authenticate(
        localizedReason: reason,
        biometricOnly: true,
        persistAcrossBackgrounding: true,
      );

      _isUnlocked = authenticated;
      _message = authenticated
          ? 'TapBridge unlocked.'
          : 'Biometric verification was cancelled or not recognised.';
      return authenticated;
    } on LocalAuthException catch (error) {
      _isUnlocked = false;
      _message = 'Biometric verification is unavailable: ${error.code.name}.';
      return false;
    } catch (_) {
      _isUnlocked = false;
      _message = 'Biometric verification could not be completed.';
      return false;
    } finally {
      _isAuthenticating = false;
      notifyListeners();
    }
  }

  void lock([String reason = 'TapBridge locked.']) {
    _isUnlocked = false;
    _message = reason;
    notifyListeners();
  }
}

class HapticController extends ChangeNotifier {
  HapticController() {
    unawaited(_load());
  }

  static const _storageKey = 'tapbridge_haptics_enabled';
  bool _enabled = true;

  bool get enabled => _enabled;

  Future<void> _load() async {
    final preferences = await SharedPreferences.getInstance();
    _enabled = preferences.getBool(_storageKey) ?? true;
    notifyListeners();
  }

  void setEnabled(bool value) {
    if (_enabled == value) {
      return;
    }
    _enabled = value;
    notifyListeners();
    unawaited(_persist(value));
  }

  Future<void> _persist(bool value) async {
    final preferences = await SharedPreferences.getInstance();
    await preferences.setBool(_storageKey, value);
  }

  void selection() {
    if (_enabled) {
      unawaited(HapticFeedback.selectionClick());
    }
  }

  void impact() {
    if (_enabled) {
      unawaited(HapticFeedback.mediumImpact());
    }
  }
}

class TapBridgeConnection extends ChangeNotifier {
  TapBridgeConnection() : _channel = TapBridgeSecureChannel();

  final TapBridgeSecureChannel _channel;
  ConnectionPhase _phase = ConnectionPhase.disconnected;
  String _message = 'Pair with a PC before sending control commands.';

  ConnectionPhase get phase => _phase;
  String get message => _message;
  bool get isConnected => _phase == ConnectionPhase.connected;

  Future<void> connect({
    required String host,
    required int port,
    required String fingerprint,
    required String pairingCode,
    required String transportLabel,
  }) async {
    _phase = ConnectionPhase.connecting;
    _message = 'Verifying the PC certificate and one-time pairing code…';
    notifyListeners();

    try {
      await _channel.connect(
        host: host,
        port: port,
        fingerprint: fingerprint,
        pairingCode: pairingCode,
        onClosed: _handleRemoteClose,
      );
      _phase = ConnectionPhase.connected;
      _message = 'Securely connected over $transportLabel to $host:$port';
    } catch (error) {
      _phase = ConnectionPhase.failed;
      _message = 'Connection failed: $error';
      await _channel.disconnect();
    }

    notifyListeners();
  }

  void sendPointerMove(int dx, int dy) {
    if (!isConnected || (dx == 0 && dy == 0)) {
      return;
    }

    try {
      _channel.send('move $dx $dy');
    } catch (error) {
      _phase = ConnectionPhase.failed;
      _message = 'Pointer movement was not sent: $error';
      notifyListeners();
    }
  }

  void send(String command, String description) {
    if (!isConnected) {
      _message = 'Not connected. Open Pairing and connect to your PC first.';
      notifyListeners();
      return;
    }

    try {
      _channel.send(command);
      _message = description;
    } catch (error) {
      _phase = ConnectionPhase.failed;
      _message = 'Command was not sent: $error';
    }
    notifyListeners();
  }

  Future<void> disconnect() async {
    await _channel.disconnect();
    _phase = ConnectionPhase.disconnected;
    _message =
        'Disconnected. The one-time code is no longer active on this phone.';
    notifyListeners();
  }

  void _handleRemoteClose() {
    if (_phase == ConnectionPhase.connected ||
        _phase == ConnectionPhase.connecting) {
      _phase = ConnectionPhase.disconnected;
      _message = 'The PC closed the secure connection.';
      notifyListeners();
    }
  }

  @override
  void dispose() {
    unawaited(_channel.disconnect());
    super.dispose();
  }
}

/// TLS channel with strict SHA-256 certificate pinning.
///
/// The agent uses a self-signed certificate. Dart normally rejects such a
/// certificate; onBadCertificate permits it only when its exact SHA-256
/// fingerprint matches the value the user read from their own PC.
class TapBridgeSecureChannel {
  SecureSocket? _socket;
  StreamSubscription<String>? _lineSubscription;
  Timer? _heartbeat;
  bool _closeWasRequested = false;
  bool _isFlushing = false;
  bool _flushRequested = false;

  Future<void> connect({
    required String host,
    required int port,
    required String fingerprint,
    required String pairingCode,
    required VoidCallback onClosed,
  }) async {
    await disconnect();
    _closeWasRequested = false;

    final expectedFingerprint = _normaliseFingerprint(fingerprint);
    final safePairingCode = _normalisePairingCode(pairingCode);
    if (host.trim().isEmpty) {
      throw ArgumentError('Enter the Windows PC IPv4 address.');
    }
    if (expectedFingerprint.length != 64) {
      throw ArgumentError(
        'The certificate fingerprint must contain 64 hex characters.',
      );
    }
    final isStrongCode = RegExp(r'^[a-fA-F0-9]{48}$').hasMatch(safePairingCode);
    final isEasyDevelopmentCode = RegExp(r'^\d{10}$').hasMatch(safePairingCode);
    if (!isStrongCode && !isEasyDevelopmentCode) {
      throw ArgumentError(
        'Enter a 48-character code or a 10-digit easy development code.',
      );
    }

    final paired = Completer<void>();
    late final SecureSocket socket;

    try {
      socket = await SecureSocket.connect(
        host.trim(),
        port,
        timeout: const Duration(seconds: 10),
        onBadCertificate: (certificate) {
          final actualFingerprint = sha256
              .convert(certificate.der)
              .toString()
              .toUpperCase();
          return _sameFingerprint(actualFingerprint, expectedFingerprint);
        },
      );
    } catch (_) {
      rethrow;
    }

    _socket = socket;
    _lineSubscription = socket
        // SecureSocket emits Uint8List chunks. Cast them to List<int> so the
        // UTF-8 decoder receives exactly the stream type it expects.
        .cast<List<int>>()
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen(
          (line) {
            if (line == 'OK paired' && !paired.isCompleted) {
              paired.complete();
            } else if (line.startsWith('ERR') && !paired.isCompleted) {
              paired.completeError(StateError(line));
            }
          },
          onError: (Object error, StackTrace stackTrace) {
            if (!paired.isCompleted) {
              paired.completeError(error, stackTrace);
            }
          },
          onDone: () {
            _heartbeat?.cancel();
            _heartbeat = null;
            _socket = null;
            if (!paired.isCompleted) {
              paired.completeError(
                StateError('The PC closed the connection during pairing.'),
              );
            }
            if (!_closeWasRequested) {
              onClosed();
            }
          },
          cancelOnError: false,
        );

    try {
      socket.write('pair $safePairingCode\n');
      await socket.flush();
      await paired.future.timeout(const Duration(seconds: 10));
      _startHeartbeat();
    } catch (_) {
      await disconnect();
      rethrow;
    }
  }

  void _startHeartbeat() {
    _heartbeat?.cancel();
    _heartbeat = Timer.periodic(const Duration(seconds: 4), (_) {
      // Keep the foregrounded TLS session active through normal Wi-Fi/NAT
      // idle windows. The agent accepts ping without creating input or logs.
      if (_socket != null) {
        try {
          send('ping');
        } catch (_) {
          // onDone/onError will update UI state if the transport is gone.
        }
      }
    });
  }

  void send(String command) {
    if (command.contains('\n') || command.contains('\r')) {
      throw ArgumentError('A control command cannot contain a line break.');
    }
    final socket = _socket;
    if (socket == null) {
      throw StateError('No secure PC connection is active.');
    }
    socket.write('$command\n');
    _requestFlush(socket);
  }

  void _requestFlush(SecureSocket socket) {
    _flushRequested = true;
    if (!_isFlushing) {
      unawaited(_flushLoop(socket));
    }
  }

  Future<void> _flushLoop(SecureSocket socket) async {
    _isFlushing = true;
    try {
      // A new command that arrives while flush is awaiting I/O requests one
      // additional pass. This keeps real-time pointer packets moving without
      // creating an unbounded flush per raw touch event.
      while (_flushRequested && identical(_socket, socket)) {
        _flushRequested = false;
        await socket.flush();
      }
    } catch (_) {
      // The stream's onDone/onError listener updates connection state after a
      // transport failure. Do not crash the UI from a background flush.
    } finally {
      _isFlushing = false;
      if (_flushRequested && identical(_socket, socket)) {
        _requestFlush(socket);
      }
    }
  }

  Future<void> disconnect() async {
    _closeWasRequested = true;
    _heartbeat?.cancel();
    _heartbeat = null;
    _flushRequested = false;
    await _lineSubscription?.cancel();
    _lineSubscription = null;
    final socket = _socket;
    _socket = null;
    if (socket != null) {
      await socket.close();
    }
  }

  String _normaliseFingerprint(String value) {
    return value.replaceAll(RegExp(r'[^a-fA-F0-9]'), '').toUpperCase();
  }

  String _normalisePairingCode(String value) {
    // The easy development format may be displayed as 12345-67890.
    return value.replaceAll(RegExp(r'[\s-]'), '');
  }

  bool _sameFingerprint(String first, String second) {
    if (first.length != second.length) {
      return false;
    }

    // Fingerprints are public identifiers, but avoiding an early-return
    // comparison still makes the pin check consistent.
    var difference = 0;
    for (var index = 0; index < first.length; index++) {
      difference |= first.codeUnitAt(index) ^ second.codeUnitAt(index);
    }
    return difference == 0;
  }
}

class TapBridgeHome extends StatefulWidget {
  const TapBridgeHome({super.key});

  @override
  State<TapBridgeHome> createState() => _TapBridgeHomeState();
}

class _TapBridgeHomeState extends State<TapBridgeHome>
    with WidgetsBindingObserver {
  final TapBridgeConnection _connection = TapBridgeConnection();
  final BiometricGate _biometricGate = BiometricGate();
  final HapticController _haptics = HapticController();
  int _selectedIndex = 0;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    // Leaving the app immediately removes control access from the foreground.
    // The secure socket is closed as well, so an unlocked app cannot leave a
    // controller session active while the phone is unattended.
    if (state == AppLifecycleState.paused ||
        state == AppLifecycleState.detached) {
      if (_biometricGate.isUnlocked) {
        _biometricGate.lock('Locked because TapBridge left the foreground.');
        unawaited(_connection.disconnect());
      }
    }
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _biometricGate.dispose();
    _haptics.dispose();
    _connection.dispose();
    super.dispose();
  }

  void _lockNow() {
    _biometricGate.lock('TapBridge was locked manually.');
    unawaited(_connection.disconnect());
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: _biometricGate,
      builder: (context, _) {
        if (!_biometricGate.isUnlocked) {
          return BiometricLockScreen(gate: _biometricGate);
        }

        final pages = [
          ControllerScreen(connection: _connection, haptics: _haptics),
          KeyboardScreen(connection: _connection, haptics: _haptics),
          RemoteScreen(connection: _connection, haptics: _haptics),
          PairingScreen(connection: _connection, biometricGate: _biometricGate),
          MoreScreen(haptics: _haptics),
        ];

        return AnimatedBuilder(
          animation: _connection,
          builder: (context, _) {
            return Scaffold(
              appBar: AppBar(
                title: const Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('TapBridge'),
                    Text(
                      'Control. Connect. Access.',
                      style: TextStyle(
                        fontSize: 12,
                        fontWeight: FontWeight.normal,
                      ),
                    ),
                  ],
                ),
                actions: [
                  Padding(
                    padding: const EdgeInsets.only(right: 4),
                    child: Center(
                      child: ConnectionPill(phase: _connection.phase),
                    ),
                  ),
                  IconButton(
                    tooltip: 'Lock TapBridge',
                    onPressed: _lockNow,
                    icon: const Icon(Icons.lock_outline),
                  ),
                ],
              ),
              body: SafeArea(
                child: Column(
                  children: [
                    StatusCard(
                      phase: _connection.phase,
                      message: _connection.message,
                      onDisconnect: _connection.isConnected
                          ? () => unawaited(_connection.disconnect())
                          : null,
                    ),
                    Expanded(child: pages[_selectedIndex]),
                  ],
                ),
              ),
              bottomNavigationBar: NavigationBar(
                selectedIndex: _selectedIndex,
                onDestinationSelected: (index) =>
                    setState(() => _selectedIndex = index),
                destinations: const [
                  NavigationDestination(
                    icon: Icon(Icons.touch_app_outlined),
                    selectedIcon: Icon(Icons.touch_app),
                    label: 'Control',
                  ),
                  NavigationDestination(
                    icon: Icon(Icons.keyboard_outlined),
                    selectedIcon: Icon(Icons.keyboard),
                    label: 'Keyboard',
                  ),
                  NavigationDestination(
                    icon: Icon(Icons.settings_remote_outlined),
                    selectedIcon: Icon(Icons.settings_remote),
                    label: 'Remote',
                  ),
                  NavigationDestination(
                    icon: Icon(Icons.qr_code_scanner_outlined),
                    selectedIcon: Icon(Icons.qr_code_scanner),
                    label: 'Pairing',
                  ),
                  NavigationDestination(
                    icon: Icon(Icons.more_horiz),
                    selectedIcon: Icon(Icons.more),
                    label: 'More',
                  ),
                ],
              ),
            );
          },
        );
      },
    );
  }
}

class BiometricLockScreen extends StatelessWidget {
  const BiometricLockScreen({super.key, required this.gate});

  final BiometricGate gate;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(32),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                CircleAvatar(
                  radius: 42,
                  backgroundColor: Theme.of(context)
                      .colorScheme
                      .primaryContainer,
                  child: Icon(
                    Icons.fingerprint,
                    size: 48,
                    color: Theme.of(context).colorScheme.primary,
                  ),
                ),
                const SizedBox(height: 24),
                Text(
                  'TapBridge is locked',
                  style: Theme.of(context).textTheme.headlineSmall,
                ),
                const SizedBox(height: 10),
                Text(gate.message, textAlign: TextAlign.center),
                const SizedBox(height: 24),
                SizedBox(
                  width: double.infinity,
                  child: FilledButton.icon(
                    onPressed: gate.isAuthenticating
                        ? null
                        : () => unawaited(gate.unlock()),
                    icon: gate.isAuthenticating
                        ? const SizedBox(
                            width: 18,
                            height: 18,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : const Icon(Icons.fingerprint),
                    label: Text(
                      gate.isAuthenticating
                          ? 'Waiting for verification…'
                          : 'Unlock with biometrics',
                    ),
                  ),
                ),
                const SizedBox(height: 16),
                const Text(
                  'Fingerprint or face data never enters TapBridge and is never sent to the PC. Android verifies it locally.',
                  textAlign: TextAlign.center,
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class ConnectionPill extends StatelessWidget {
  const ConnectionPill({super.key, required this.phase});

  final ConnectionPhase phase;

  @override
  Widget build(BuildContext context) {
    final (label, background, foreground) = switch (phase) {
      ConnectionPhase.connected => (
        'Securely connected',
        Colors.green.shade100,
        Colors.green.shade900,
      ),
      ConnectionPhase.connecting => (
        'Connecting…',
        Colors.blue.shade100,
        Colors.blue.shade900,
      ),
      ConnectionPhase.failed => (
        'Connection failed',
        Colors.red.shade100,
        Colors.red.shade900,
      ),
      ConnectionPhase.disconnected => (
        'Not connected',
        Colors.orange.shade100,
        Colors.orange.shade900,
      ),
    };

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
      decoration: BoxDecoration(
        color: background,
        borderRadius: BorderRadius.circular(20),
      ),
      child: Text(
        label,
        style: TextStyle(
          color: foreground,
          fontSize: 12,
          fontWeight: FontWeight.w700,
        ),
      ),
    );
  }
}

class StatusCard extends StatelessWidget {
  const StatusCard({
    super.key,
    required this.phase,
    required this.message,
    required this.onDisconnect,
  });

  final ConnectionPhase phase;
  final String message;
  final VoidCallback? onDisconnect;

  @override
  Widget build(BuildContext context) {
    final connected = phase == ConnectionPhase.connected;
    return Card(
      margin: const EdgeInsets.fromLTRB(16, 12, 16, 4),
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Row(
          children: [
            CircleAvatar(
              backgroundColor: connected
                  ? Colors.green.shade100
                  : Theme.of(context).colorScheme.primaryContainer,
              child: Icon(
                connected
                    ? Icons.verified_user_outlined
                    : Icons.desktop_windows_outlined,
                color: connected
                    ? Colors.green.shade900
                    : Theme.of(context).colorScheme.primary,
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    connected ? 'Paired PC' : 'TapBridge status',
                    style: const TextStyle(fontWeight: FontWeight.w700),
                  ),
                  const SizedBox(height: 2),
                  Text(
                    message,
                    maxLines: 3,
                    overflow: TextOverflow.ellipsis,
                    style: Theme.of(context).textTheme.bodySmall,
                  ),
                ],
              ),
            ),
            if (onDisconnect != null)
              IconButton(
                tooltip: 'Disconnect',
                onPressed: onDisconnect,
                icon: const Icon(Icons.link_off),
              ),
          ],
        ),
      ),
    );
  }
}

class AdaptivePointerPhysics {
  AdaptivePointerPhysics({required this.onMove});

  final void Function(int dx, int dy) onMove;
  static const _frameInterval = Duration(milliseconds: 16);

  Offset _filteredDelta = Offset.zero;
  Duration? _lastTimestamp;
  double _pendingX = 0;
  double _pendingY = 0;
  double _residualX = 0;
  double _residualY = 0;
  Timer? _frameTimer;

  void begin(Duration timestamp) {
    _filteredDelta = Offset.zero;
    _lastTimestamp = timestamp;
    _pendingX = 0;
    _pendingY = 0;
    _residualX = 0;
    _residualY = 0;
    _frameTimer?.cancel();
    _frameTimer = null;
  }

  void add(Offset rawDelta, Duration timestamp, double sensitivity) {
    var elapsedMicros = _lastTimestamp == null
        ? _frameInterval.inMicroseconds
        : (timestamp - _lastTimestamp!).inMicroseconds;
    _lastTimestamp = timestamp;
    if (elapsedMicros <= 0 || elapsedMicros > 50000) {
      elapsedMicros = _frameInterval.inMicroseconds;
    }

    final distance = rawDelta.distance;
    final speed = distance / (elapsedMicros / Duration.microsecondsPerSecond);

    // Reject sub-pixel sensor noise without adding a visible movement delay.
    if (distance < 0.30 && speed < 55) {
      return;
    }

    // A small speed-dependent low-pass filter removes hand jitter. Fast motion
    // gets less filtering, so the cursor stays responsive rather than lagging.
    final blend = speed < 260 ? 0.46 : 0.76;
    _filteredDelta = Offset(
      _filteredDelta.dx * (1 - blend) + rawDelta.dx * blend,
      _filteredDelta.dy * (1 - blend) + rawDelta.dy * blend,
    );

    if (speed < 60 && _filteredDelta.distance < 0.70) {
      return;
    }

    // Laptop-style acceleration: slow finger movement remains precise; fast
    // movement crosses a large Windows display without a large fixed gain.
    final normalizedSpeed = (speed / 1550).clamp(0.0, 1.0).toDouble();
    final accelerationCurve = math.pow(normalizedSpeed, 1.30).toDouble();
    final gain = sensitivity * (0.90 + 1.25 * accelerationCurve);

    _pendingX += _filteredDelta.dx * gain;
    _pendingY += _filteredDelta.dy * gain;
    _frameTimer ??= Timer(_frameInterval, _flush);
  }

  void flushNow() {
    _frameTimer?.cancel();
    _frameTimer = null;
    _flush();
  }

  void _flush() {
    _frameTimer = null;
    final outputX = _pendingX + _residualX;
    final outputY = _pendingY + _residualY;
    final dx = outputX.truncate();
    final dy = outputY.truncate();
    _residualX = outputX - dx;
    _residualY = outputY - dy;
    _pendingX = 0;
    _pendingY = 0;

    if (dx != 0 || dy != 0) {
      onMove(dx, dy);
    }
  }

  void reset() {
    _frameTimer?.cancel();
    _frameTimer = null;
    _filteredDelta = Offset.zero;
    _lastTimestamp = null;
    _pendingX = 0;
    _pendingY = 0;
    _residualX = 0;
    _residualY = 0;
  }

  void dispose() => reset();
}

class ControllerScreen extends StatefulWidget {
  const ControllerScreen({
    super.key,
    required this.connection,
    required this.haptics,
  });

  final TapBridgeConnection connection;
  final HapticController haptics;

  @override
  State<ControllerScreen> createState() => _ControllerScreenState();
}

class _ControllerScreenState extends State<ControllerScreen> {
  final Map<int, Offset> _pointers = <int, Offset>{};
  Offset? _lastCentroid;
  Timer? _longPressTimer;
  late final AdaptivePointerPhysics _pointerPhysics;

  bool _twoFingerGesture = false;
  bool _didMove = false;
  bool _dragActive = false;
  double _travelDistance = 0;
  double _scrollRemainder = 0;
  double _sensitivity = 1.15;
  String _gestureStatus = 'One finger moves · two fingers scroll';

  @override
  void initState() {
    super.initState();
    _pointerPhysics = AdaptivePointerPhysics(
      onMove: widget.connection.sendPointerMove,
    );
  }

  @override
  void dispose() {
    _longPressTimer?.cancel();
    _pointerPhysics.dispose();
    super.dispose();
  }

  Offset _centroid() {
    var x = 0.0;
    var y = 0.0;
    for (final point in _pointers.values) {
      x += point.dx;
      y += point.dy;
    }
    return Offset(x / _pointers.length, y / _pointers.length);
  }

  void _sendAction(String command, String description, {bool haptic = true}) {
    if (haptic) {
      widget.haptics.selection();
    }
    widget.connection.send(command, description);
  }

  void _startLongPressTimer() {
    _longPressTimer?.cancel();
    _longPressTimer = Timer(const Duration(milliseconds: 450), () {
      if (!mounted || _pointers.length != 1 || _didMove || _twoFingerGesture) {
        return;
      }
      _dragActive = true;
      widget.haptics.impact();
      _sendAction('button left down', 'Drag started', haptic: false);
      setState(() => _gestureStatus = 'Dragging — lift your finger to release');
    });
  }

  void _onPointerDown(PointerDownEvent event) {
    final wasEmpty = _pointers.isEmpty;
    _pointers[event.pointer] = event.localPosition;

    if (wasEmpty) {
      _lastCentroid = event.localPosition;
      _twoFingerGesture = false;
      _didMove = false;
      _dragActive = false;
      _travelDistance = 0;
      _scrollRemainder = 0;
      _pointerPhysics.begin(event.timeStamp);
      _startLongPressTimer();
    } else {
      _twoFingerGesture = true;
      _longPressTimer?.cancel();
      _pointerPhysics.reset();
      _lastCentroid = _centroid();
      setState(() => _gestureStatus = 'Two-finger gesture');
    }
  }

  void _onPointerMove(PointerMoveEvent event) {
    if (!_pointers.containsKey(event.pointer)) {
      return;
    }

    _pointers[event.pointer] = event.localPosition;
    final currentCentroid = _centroid();
    final previousCentroid = _lastCentroid ?? currentCentroid;
    final delta = currentCentroid - previousCentroid;
    _lastCentroid = currentCentroid;

    _travelDistance += delta.distance;
    if (_travelDistance > 5) {
      _didMove = true;
      if (!_dragActive) {
        _longPressTimer?.cancel();
      }
    }

    if (_pointers.length >= 2 || _twoFingerGesture) {
      _twoFingerGesture = true;
      _scrollRemainder += delta.dy;
      final notches = (-_scrollRemainder / 22).truncate();
      if (notches != 0) {
        _scrollRemainder += notches * 22;
        widget.connection.send('scroll $notches', 'Two-finger scroll');
      }
      return;
    }

    _pointerPhysics.add(delta, event.timeStamp, _sensitivity);
  }

  void _finishPointer(int pointer, {bool cancelled = false}) {
    if (!_pointers.containsKey(pointer)) {
      return;
    }

    final wasTwoFingerGesture = _twoFingerGesture || _pointers.length >= 2;
    _pointers.remove(pointer);

    if (_pointers.isNotEmpty) {
      _lastCentroid = _centroid();
      return;
    }

    _longPressTimer?.cancel();
    _pointerPhysics.flushNow();

    if (_dragActive) {
      _sendAction('button left up', 'Drag released', haptic: false);
      widget.haptics.impact();
    } else if (!cancelled && !_didMove) {
      if (wasTwoFingerGesture) {
        _sendAction('click right', 'Two-finger right click');
      } else {
        _sendAction('click left', 'Tap left click');
      }
    }

    _lastCentroid = null;
    _twoFingerGesture = false;
    _didMove = false;
    _dragActive = false;
    _scrollRemainder = 0;
    _pointerPhysics.reset();
    if (mounted) {
      setState(() => _gestureStatus = 'One finger moves · two fingers scroll');
    }
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 16, 16, 6),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Laptop-style Touchpad',
                style: Theme.of(context).textTheme.titleLarge,
              ),
              const SizedBox(height: 4),
              Text(
                _gestureStatus,
                style: Theme.of(context).textTheme.bodyMedium,
              ),
            ],
          ),
        ),
        Expanded(
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16),
            child: Listener(
              behavior: HitTestBehavior.opaque,
              onPointerDown: _onPointerDown,
              onPointerMove: _onPointerMove,
              onPointerUp: (event) => _finishPointer(event.pointer),
              onPointerCancel: (event) =>
                  _finishPointer(event.pointer, cancelled: true),
              child: Container(
                decoration: BoxDecoration(
                  color: Colors.white,
                  borderRadius: BorderRadius.circular(28),
                  border: Border.all(
                    color: Theme.of(context).colorScheme.primary
                        .withValues(alpha: 0.30),
                    width: 2,
                  ),
                  boxShadow: const [
                    BoxShadow(
                      color: Color(0x12000000),
                      blurRadius: 12,
                      offset: Offset(0, 5),
                    ),
                  ],
                ),
                child: Center(
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Icon(
                        Icons.touch_app_outlined,
                        size: 72,
                        color: Theme.of(context).colorScheme.primary,
                      ),
                      const SizedBox(height: 12),
                      const Text(
                        'TapBridge Touchpad',
                        style: TextStyle(
                          fontSize: 22,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      const SizedBox(height: 8),
                      const Padding(
                        padding: EdgeInsets.symmetric(horizontal: 28),
                        child: Text(
                          'Tap: left click\nTwo-finger tap: right click\nTwo-finger drag: scroll\nHold, then move: drag',
                          textAlign: TextAlign.center,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ),
        ),
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 8, 16, 12),
          child: Column(
            children: [
              Row(
                children: [
                  const Icon(Icons.speed_outlined),
                  const SizedBox(width: 8),
                  const Text('Sensitivity'),
                  Expanded(
                    child: Slider(
                      value: _sensitivity,
                      min: 0.70,
                      max: 1.80,
                      divisions: 22,
                      label: '${_sensitivity.toStringAsFixed(2)}×',
                      onChanged: (value) =>
                          setState(() => _sensitivity = value),
                    ),
                  ),
                  Text('${_sensitivity.toStringAsFixed(2)}×'),
                ],
              ),
              const Text(
                'Adaptive acceleration: slow moves are precise; fast moves travel farther. This page does not scroll.',
                textAlign: TextAlign.center,
              ),
            ],
          ),
        ),
      ],
    );
  }
}

class KeyboardScreen extends StatefulWidget {
  const KeyboardScreen({
    super.key,
    required this.connection,
    required this.haptics,
  });

  final TapBridgeConnection connection;
  final HapticController haptics;

  @override
  State<KeyboardScreen> createState() => _KeyboardScreenState();
}

class _KeyboardScreenState extends State<KeyboardScreen> {
  final _textController = TextEditingController();

  @override
  void dispose() {
    _textController.dispose();
    super.dispose();
  }

  void _sendText() {
    final text = _textController.text.replaceAll(RegExp(r'[\r\n]'), ' ');
    if (text.trim().isEmpty) {
      widget.connection.send('help', 'Type text for the PC first.');
      return;
    }
    widget.haptics.selection();
    widget.connection.send(
      'text $text',
      'Sent ${text.runes.length} character(s) to the PC',
    );
    _textController.clear();
  }

  void _sendKey(String key) {
    widget.haptics.selection();
    widget.connection.send('key $key', 'Sent key: $key');
  }

  void _sendShortcut(String modifier, String key) {
    widget.haptics.selection();
    widget.connection.send(
      'combo $modifier $key',
      'Sent shortcut: $modifier+$key',
    );
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Text('Keyboard', style: Theme.of(context).textTheme.titleLarge),
        const SizedBox(height: 10),
        TextField(
          controller: _textController,
          minLines: 2,
          maxLines: 4,
          decoration: const InputDecoration(
            labelText: 'Type text for the PC',
            hintText: 'Hello from TapBridge',
            border: OutlineInputBorder(),
          ),
        ),
        const SizedBox(height: 10),
        FilledButton.icon(
          onPressed: _sendText,
          icon: const Icon(Icons.send),
          label: const Text('Send Text'),
        ),
        const SizedBox(height: 20),
        const Text(
          'Special Keys',
          style: TextStyle(fontWeight: FontWeight.bold),
        ),
        const SizedBox(height: 10),
        Wrap(
          spacing: 8,
          runSpacing: 8,
          children: [
            for (final key in [
              'escape',
              'tab',
              'enter',
              'backspace',
              'delete',
              'up',
              'down',
              'left',
              'right',
            ])
              OutlinedButton(onPressed: () => _sendKey(key), child: Text(key)),
          ],
        ),
        const SizedBox(height: 20),
        const Text('Shortcuts', style: TextStyle(fontWeight: FontWeight.bold)),
        const SizedBox(height: 10),
        Wrap(
          spacing: 8,
          runSpacing: 8,
          children: [
            for (final shortcut in [
              ('ctrl', 'a'),
              ('ctrl', 'c'),
              ('ctrl', 'v'),
              ('ctrl', 'x'),
              ('ctrl', 'z'),
              ('ctrl', 's'),
            ])
              OutlinedButton(
                onPressed: () => _sendShortcut(shortcut.$1, shortcut.$2),
                child: Text(
                  '${shortcut.$1.toUpperCase()} + ${shortcut.$2.toUpperCase()}',
                ),
              ),
          ],
        ),
      ],
    );
  }
}

class PairingScreen extends StatefulWidget {
  const PairingScreen({
    super.key,
    required this.connection,
    required this.biometricGate,
  });

  final TapBridgeConnection connection;
  final BiometricGate biometricGate;

  @override
  State<PairingScreen> createState() => _PairingScreenState();
}

class _PairingScreenState extends State<PairingScreen> {
  final _formKey = GlobalKey<FormState>();
  final _addressController = TextEditingController();
  final _portController = TextEditingController(text: '7878');
  final _fingerprintController = TextEditingController();
  final _codeController = TextEditingController();
  ConnectionRoute _route = ConnectionRoute.wifi;
  bool _isUsbConfirming = false;

  @override
  void dispose() {
    _addressController.dispose();
    _portController.dispose();
    _fingerprintController.dispose();
    _codeController.dispose();
    super.dispose();
  }

  Future<void> _connect() async {
    if (!(_formKey.currentState?.validate() ?? false)) {
      return;
    }

    if (_route == ConnectionRoute.usbTether) {
      setState(() => _isUsbConfirming = true);
      final approved = await widget.biometricGate.unlock(
        reason: 'Confirm this offline USB tethering session before controlling your PC.',
      );
      if (!mounted) {
        return;
      }
      setState(() => _isUsbConfirming = false);
      if (!approved) {
        return;
      }
    }

    await widget.connection.connect(
      host: _addressController.text.trim(),
      port: int.parse(_portController.text),
      fingerprint: _fingerprintController.text,
      pairingCode: _codeController.text,
      transportLabel: _route.label,
    );
  }

  @override
  Widget build(BuildContext context) {
    final isConnecting = widget.connection.phase == ConnectionPhase.connecting;
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Text(
          'Secure local pairing',
          style: Theme.of(context).textTheme.titleLarge,
        ),
        const SizedBox(height: 8),
        const Text(
          'Use only values displayed by the TapBridge agent running on your own PC. The fingerprint pins that PC certificate; the code is valid only while that agent run is active.',
        ),
        const SizedBox(height: 12),
        Text('Connection route', style: Theme.of(context).textTheme.titleSmall),
        RadioGroup<ConnectionRoute>(
          groupValue: _route,
          onChanged: (value) {
            if (value != null) {
              setState(() => _route = value);
            }
          },
          child: Column(
            children: [
              RadioListTile<ConnectionRoute>(
                value: ConnectionRoute.wifi,
                contentPadding: EdgeInsets.zero,
                title: const Text('Wi-Fi LAN'),
                subtitle: const Text(
                  'Phone and PC are on the same private Wi-Fi network.',
                ),
              ),
              RadioListTile<ConnectionRoute>(
                value: ConnectionRoute.usbTether,
                contentPadding: EdgeInsets.zero,
                title: const Text('Offline USB tethering'),
                subtitle: const Text(
                  'Connect the USB cable and enable USB tethering in Android Settings.',
                ),
              ),
              if (_route == ConnectionRoute.usbTether)
                Card(
                  color: Colors.blue.shade50,
                  child: const Padding(
                    padding: EdgeInsets.all(12),
                    child: Text(
                      'TapBridge uses the same certificate-pinned TLS connection over the USB Ethernet link. Wi-Fi and internet are not required. Before every USB session, TapBridge asks for a fresh on-device biometric confirmation. Enter the IPv4 address shown for the PC USB-tether adapter in ipconfig.',
                    ),
                  ),
                ),
            ],
          ),
        ),
        const SizedBox(height: 12),
        Form(
          key: _formKey,
          child: Column(
            children: [
              TextFormField(
                controller: _addressController,
                keyboardType: const TextInputType.numberWithOptions(
                  decimal: true,
                ),
                decoration: InputDecoration(
                  labelText: _route == ConnectionRoute.usbTether
                      ? 'PC USB-tether IPv4 address'
                      : 'PC Wi-Fi IPv4 address',
                  hintText: _route == ConnectionRoute.usbTether
                      ? '192.168.42.164'
                      : '192.168.1.25',
                  border: const OutlineInputBorder(),
                ),
                validator: (value) => (value == null || value.trim().isEmpty)
                    ? 'Enter the PC IPv4 address.'
                    : null,
              ),
              const SizedBox(height: 12),
              TextFormField(
                controller: _portController,
                keyboardType: TextInputType.number,
                decoration: const InputDecoration(
                  labelText: 'Port',
                  border: OutlineInputBorder(),
                ),
                validator: (value) {
                  final port = int.tryParse(value ?? '');
                  return (port == null || port < 1 || port > 65535)
                      ? 'Enter a port from 1 to 65535.'
                      : null;
                },
              ),
              const SizedBox(height: 12),
              TextFormField(
                controller: _fingerprintController,
                textCapitalization: TextCapitalization.characters,
                autocorrect: false,
                enableSuggestions: false,
                decoration: const InputDecoration(
                  labelText: 'Certificate SHA-256 fingerprint',
                  helperText: 'Paste the 64-character fingerprint from the PC.',
                  border: OutlineInputBorder(),
                ),
                validator: (value) {
                  final normalised = (value ?? '').replaceAll(
                    RegExp(r'[^a-fA-F0-9]'),
                    '',
                  );
                  return normalised.length == 64
                      ? null
                      : 'Enter all 64 hexadecimal characters.';
                },
              ),
              const SizedBox(height: 12),
              TextFormField(
                controller: _codeController,
                autocorrect: false,
                enableSuggestions: false,
                obscureText: true,
                decoration: const InputDecoration(
                  labelText: 'One-time pairing code',
                  helperText: 'Enter the 48-character code, or the 10-digit easy development code.',
                  border: OutlineInputBorder(),
                ),
                validator: (value) {
                  final code = (value ?? '').replaceAll(RegExp(r'[\s-]'), '');
                  final isStrong = RegExp(r'^[a-fA-F0-9]{48}$').hasMatch(code);
                  final isEasy = RegExp(r'^\d{10}$').hasMatch(code);
                  return (isStrong || isEasy)
                      ? null
                      : 'Enter a 48-character code or 10-digit development code.';
                },
              ),
              const SizedBox(height: 16),
              SizedBox(
                width: double.infinity,
                child: FilledButton.icon(
                  onPressed: (isConnecting || _isUsbConfirming)
                      ? null
                      : _connect,
                  icon: Icon(
                    _route == ConnectionRoute.usbTether
                        ? Icons.fingerprint
                        : Icons.verified_user_outlined,
                  ),
                  label: Text(
                    _isUsbConfirming
                        ? 'Confirm with biometrics…'
                        : isConnecting
                        ? 'Verifying secure connection…'
                        : _route == ConnectionRoute.usbTether
                        ? 'Confirm biometrics and connect'
                        : 'Connect securely',
                  ),
                ),
              ),
              if (widget.connection.isConnected) ...[
                const SizedBox(height: 8),
                SizedBox(
                  width: double.infinity,
                  child: OutlinedButton.icon(
                    onPressed: () => unawaited(widget.connection.disconnect()),
                    icon: const Icon(Icons.link_off),
                    label: const Text('Disconnect'),
                  ),
                ),
              ],
            ],
          ),
        ),
        const SizedBox(height: 20),
        Card(
          color: Colors.amber.shade50,
          child: const Padding(
            padding: EdgeInsets.all(14),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Development-stage boundary',
                  style: TextStyle(fontWeight: FontWeight.bold),
                ),
                SizedBox(height: 6),
                Text(
                  'This build does not save a paired device. Each agent restart creates a new code. QR scanning, Android Keystore storage, Windows DPAPI, device revocation, and user approval are the next security milestone.',
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }
}

class RemoteScreen extends StatelessWidget {
  const RemoteScreen({
    super.key,
    required this.connection,
    required this.haptics,
  });

  final TapBridgeConnection connection;
  final HapticController haptics;

  void _send(String command, String label) {
    haptics.selection();
    connection.send(command, 'Remote: $label');
  }

  @override
  Widget build(BuildContext context) {
    final actions = <(IconData, String, String)>[
      (Icons.volume_off_outlined, 'Mute', 'key volume_mute'),
      (Icons.volume_down_outlined, 'Volume Down', 'key volume_down'),
      (Icons.volume_up_outlined, 'Volume Up', 'key volume_up'),
      (Icons.play_circle_outline, 'Play / Pause', 'key media_play_pause'),
      (Icons.skip_previous_outlined, 'Previous Track', 'key media_previous'),
      (Icons.skip_next_outlined, 'Next Track', 'key media_next'),
      (Icons.arrow_back, 'Previous Slide', 'key left'),
      (Icons.arrow_forward, 'Next Slide', 'key right'),
    ];

    return GridView.builder(
      padding: const EdgeInsets.all(16),
      itemCount: actions.length,
      gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: 2,
        crossAxisSpacing: 12,
        mainAxisSpacing: 12,
        childAspectRatio: 1.22,
      ),
      itemBuilder: (context, index) {
        final action = actions[index];
        return Card(
          child: InkWell(
            borderRadius: BorderRadius.circular(12),
            onTap: () => _send(action.$3, action.$2),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Icon(action.$1, size: 36),
                const SizedBox(height: 10),
                Text(
                  action.$2,
                  textAlign: TextAlign.center,
                  style: const TextStyle(fontWeight: FontWeight.w600),
                ),
              ],
            ),
          ),
        );
      },
    );
  }
}

class MoreScreen extends StatelessWidget {
  const MoreScreen({super.key, required this.haptics});

  final HapticController haptics;

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: haptics,
      builder: (context, _) {
        return ListView(
          padding: const EdgeInsets.all(16),
          children: [
            Text('Settings', style: Theme.of(context).textTheme.titleLarge),
            const SizedBox(height: 8),
            Card(
              child: SwitchListTile(
                secondary: const Icon(Icons.vibration_outlined),
                title: const Text('Haptic feedback'),
                subtitle: Text(
                  haptics.enabled
                      ? 'Feedback is on for clicks, keys and remote buttons.'
                      : 'Feedback is off.',
                ),
                value: haptics.enabled,
                onChanged: haptics.setEnabled,
              ),
            ),
            const SizedBox(height: 20),
            Text(
              'PC Data Portal',
              style: Theme.of(context).textTheme.titleLarge,
            ),
            const SizedBox(height: 8),
            const Card(
              child: Padding(
                padding: EdgeInsets.all(16),
                child: Row(
                  children: [
                    Icon(Icons.folder_shared_outlined),
                    SizedBox(width: 12),
                    Expanded(
                      child: Text(
                        'Selected-folder access, clipboard sync, and PC storage browsing remain disabled until durable pairing and approved-folder policy are complete.',
                      ),
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 16),
            const Card(
              child: ListTile(
                leading: Icon(Icons.security_outlined),
                title: Text('Security status'),
                subtitle: Text(
                  'Biometric lock and background disconnect are enabled in this development build.',
                ),
              ),
            ),
          ],
        );
      },
    );
  }
}

class ActionButton extends StatelessWidget {
  const ActionButton({
    super.key,
    required this.icon,
    required this.label,
    required this.onPressed,
  });

  final IconData icon;
  final String label;
  final VoidCallback onPressed;

  @override
  Widget build(BuildContext context) {
    return OutlinedButton.icon(
      onPressed: onPressed,
      icon: Icon(icon),
      label: Text(label),
      style: OutlinedButton.styleFrom(
        padding: const EdgeInsets.symmetric(vertical: 16),
      ),
    );
  }
}

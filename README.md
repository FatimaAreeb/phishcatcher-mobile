# PhishCatcher Mobile

On-device phishing URL detection for Android. Kotlin + Jetpack Compose port of my original Python/scikit-learn PhishCatcher project — the ML inference runs entirely on the phone, no network calls.

## How it works

1. **Feature extraction** — parses the URL and computes 15 numeric features (length metrics, IP-as-host, suspicious keywords, HTTPS usage, URL-shortener detection, etc.), mirroring the feature engineering from the Python training pipeline.
2. **Classification** — logistic regression implemented directly in Kotlin: standardizes the feature vector, applies the model weights, and outputs a phishing probability plus the top contributing signals.
3. **UI** — single-screen Jetpack Compose app: URL input, verdict card with confidence and key signals, and a session history list.

## Tech stack

- Kotlin, Jetpack Compose, Material 3
- On-device ML inference (logistic regression ported from scikit-learn)
- Min SDK 26

## Try it

Open the project in Android Studio, run on an emulator or device, and test:
- `https://www.google.com` → ✓ Looks Safe
- `http://192.168.1.1/login-verify-account` → ⚠ Likely Phishing

## Why on-device inference

- Zero latency, works offline
- URLs never leave the phone (privacy)
- The model is small enough that reimplementing it in Kotlin is simpler and lighter than bundling a TFLite model

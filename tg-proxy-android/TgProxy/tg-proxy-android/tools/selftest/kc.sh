#!/usr/bin/env bash
# Компилирует чистое JVM-ядро (app/src/main/java/app/tgproxy/core) вместе с тест-стендом.
# Использует Kotlin-компилятор, поставляемый внутри Gradle (не требует интернета).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GRADLE_LIB="${GRADLE_LIB:-/opt/gradle/lib}"
OUT="${1:-/tmp/tgproxy-selftest-out}"
CP="$GRADLE_LIB/kotlin-compiler-embeddable-2.0.21.jar:$GRADLE_LIB/kotlin-stdlib-2.0.21.jar:$GRADLE_LIB/kotlin-reflect-2.0.21.jar:$GRADLE_LIB/kotlin-script-runtime-2.0.21.jar:$GRADLE_LIB/kotlin-daemon-embeddable-2.0.21.jar:$GRADLE_LIB/kotlinx-coroutines-core-jvm-1.6.4.jar:$GRADLE_LIB/annotations-24.0.1.jar:$GRADLE_LIB/trove4j-1.0.20200330.jar"
rm -rf "$OUT"; mkdir -p "$OUT"
java -Xmx1g -cp "$CP" org.jetbrains.kotlin.cli.jvm.K2JVMCompiler \
  -no-stdlib -no-reflect -jvm-target 17 \
  -cp "$GRADLE_LIB/kotlin-stdlib-2.0.21.jar" \
  -d "$OUT" \
  "$ROOT"/app/src/main/java/app/tgproxy/core/*.kt \
  "$ROOT"/tools/selftest/*.kt
echo "compiled -> $OUT"

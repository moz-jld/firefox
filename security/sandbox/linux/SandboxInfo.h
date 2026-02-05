/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_SandboxInfo_h
#define mozilla_SandboxInfo_h

#include "mozilla/Assertions.h"
#include "mozilla/Types.h"
#include <cstdint>

// Information on what parts of sandboxing are enabled in this build
// and/or supported by the system.

namespace mozilla {

class SandboxInfo {
 public:
  // Implicitly copy-constructible; this is essentially just an int or
  // two so it doesn't matter.

  // All processes, parent and child, must call this early in startup
  // before any non-main threads are started (this will be asserted on
  // debug builds).
  static void Init() { sSingleton.InitThis(); }

  static const SandboxInfo& Get() {
    MOZ_ASSERT(sSingleton.mInited);
    return sSingleton;
  }

  enum Flags {
    // System call filtering; kernel config option CONFIG_SECCOMP_FILTER.
    kHasSeccompBPF = 1 << 0,
    // Whether to use a sandbox for content processes; env var
    // MOZ_DISABLE_CONTENT_SANDBOX
    kEnabledForContent = 1 << 1,
    // Whether to use a sandbox for GMP processes; env var
    // MOZ_DISABLE_GMP_SANDBOX.
    kEnabledForMedia = 1 << 2,
    // Env var MOZ_SANDBOX_LOGGING.
    kVerbose = 1 << 3,
    // Kernel can atomically set system call filtering on entire thread group.
    kHasSeccompTSync = 1 << 4,
    // Can this process create user namespaces? (Man page user_namespaces(7).)
    kHasUserNamespaces = 1 << 5,
    // Could a more privileged process have user namespaces, even if we can't?
    kHasPrivilegedUserNamespaces = 1 << 6,
    // Env var MOZ_PERMISSIVE_CONTENT_SANDBOX
    kPermissive = 1 << 7,
    // Something is creating threads when we need to still be single-threaded.
    kUnexpectedThreads = 1 << 8,
    // MOZ_SANDBOX_LOGGING_FOR_TESTS
    kVerboseTests = 1 << 9,
    // Landlock LSM: https://docs.kernel.org/userspace-api/landlock.html
    kLandlock = 1 << 10,
  };

  bool Test(Flags aFlag) const { return (mFlags & aFlag) == aFlag; }

  // Returns true if SetContentProcessSandbox may be called.
  bool CanSandboxContent() const {
    return !Test(kEnabledForContent) || Test(kHasSeccompBPF);
  }

  // Returns true if SetMediaPluginSandbox may be called.
  bool CanSandboxMedia() const {
    return !Test(kEnabledForMedia) || Test(kHasSeccompBPF);
  }

  // For telemetry / crash annotation uses.
  uint32_t AsInteger() const { return mFlags; }

  // Landlock ABI version (>=1) if supported by the kernel, otherwise 0.
  //
  // WARNING: always test kLandlock; if Landlock is supported but
  // can't be used for some reason, the kLandlock bit will be clear
  // but this will still return nonzero (to indicate that we could
  // have used Landlock if that other condition weren't the case).
  uint32_t LandlockABI() const { return mLandlockABI; }

  // Defined in glue/SandboxTelemetryBridge.cpp to be able to call
  // into Glean in libxul.  This should be called somewhat early in
  // parent and child processes, but not too early for Glean to work.
  void CollectTelemetry() const;

 private:
  // Thread safety: these are written in Init(), which should be
  // called when single-threaded, and only read afterwards.
  enum Flags mFlags;
  // This could a smaller type if needed.
  uint32_t mLandlockABI = 0;
  bool mInited = false;
  static MOZ_EXPORT SandboxInfo sSingleton;

  SandboxInfo() = default;

  void MOZ_EXPORT InitThis();
};

}  // namespace mozilla

#endif  // mozilla_SandboxInfo_h

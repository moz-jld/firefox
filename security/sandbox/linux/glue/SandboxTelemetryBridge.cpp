/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "SandboxInfo.h"

#include "mozilla/ProcessType.h"
#include "mozilla/glean/SecuritySandboxMetrics.h"

#include <prenv.h>
#include <string.h>

namespace mozilla {

static unsigned ClassifyPreload() {
  if (const char* preload = PR_GetEnv("LD_PRELOAD")) {
    if (strstr(preload, "libGL")) {
      return 2;
    }
    return 1;
  }
  return 0;
}

void SandboxInfo::CollectTelemetry() const {
  if (XRE_IsParentProcess()) {
    glean::sandbox::unexpected_threads_parent.Set(Test(kUnexpectedThreads));
    glean::sandbox::suspicious_preloading.Set(ClassifyPreload());
  } else if (Test(kUnexpectedThreads)) {
    glean::sandbox::unexpected_threads_child.Add(1);
  }
}

}  // namespace mozilla

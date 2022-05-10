/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "rust/cxx.h"

rust::Vec<rust::String> get_hal_names();
rust::Vec<rust::String> get_hal_names_and_versions();
rust::Vec<rust::String> get_hidl_instances(rust::Str package, size_t major_version,
                                           size_t minor_version, rust::Str interfaceName);
rust::Vec<rust::String> get_aidl_instances(rust::Str package, size_t version,
                                           rust::Str interfaceName);

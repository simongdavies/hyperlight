/*
Copyright 2025 The Hyperlight Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
 * Userspace (ring 3) hardening linker script for simpleguest.
 *
 * Gathers the runtime's ring-0-only critical statics (tagged
 * `#[link_section = ".kdata"]` in hyperlight_guest_bin: the guest function
 * pointer table, the PEB handle, the exception handler table) into a single
 * page-aligned, bounded output section. The guest re-protects
 * [__kdata_start, __kdata_end) supervisor-only at boot
 * (`hyperlight_guest_bin::arch::ring3::protect_kernel_data`) so ring 3 can
 * neither read nor copy-on-write corrupt them.
 *
 * Page alignment of *both* bounds is essential: re-protection works a whole
 * page at a time, so .kdata must not share a page with anything ring 3 still
 * needs (e.g. the CPL-routed allocator's dispatch state).
 *
 * This AUGMENTS lld's default script via INSERT rather than replacing it. The
 * `.text` anchor is always present; a writable-data anchor such as `.data` is
 * not guaranteed to exist. The host loads the whole guest image as a single
 * read/write/execute region regardless of segment, and the guest overrides the
 * permissions of these pages at boot, so the choice of anchor segment does not
 * affect the final protection.
 */
SECTIONS {
  .kdata : ALIGN(0x1000) {
    __kdata_start = .;
    KEEP(*(.kdata))
    KEEP(*(.kdata.*))
    . = ALIGN(0x1000);
    __kdata_end = .;
  }
} INSERT AFTER .text;

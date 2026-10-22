// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { isHosted } from "./mode";

const MIB = 1024 * 1024;

/** The server's message cap for the email check: 25 MiB locally, 10 MiB on the hosted service. */
export function maxMessageBytes(): number {
  return (isHosted() ? 10 : 25) * MIB;
}

/** The server's upload cap for file forensics: 50 MiB locally, 10 MiB on the hosted service. */
export function maxUploadBytes(): number {
  return (isHosted() ? 10 : 50) * MIB;
}

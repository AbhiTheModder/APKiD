/*
 * Copyright (C) 2023  RedNaga. https://rednaga.io
 * All rights reserved. Contact: rednaga@protonmail.com
 *
 *
 * This file is part of APKiD
 *
 *
 * Commercial License Usage
 * ------------------------
 * Licensees holding valid commercial APKiD licenses may use this file
 * in accordance with the commercial license agreement provided with the
 * Software or, alternatively, in accordance with the terms contained in
 * a written agreement between you and RedNaga.
 *
 *
 * GNU General Public License Usage
 * --------------------------------
 * Alternatively, this file may be used under the terms of the GNU General
 * Public License version 3.0 as published by the Free Software Foundation
 * and appearing in the file LICENSE.GPL included in the packaging of this
 * file. Please visit http://www.gnu.org/copyleft/gpl.html and review the
 * information to ensure the GNU General Public License version 3.0
 * requirements will be met.
 *
 **/

import "elf"

rule is_elf : file_type
{
  meta:
    description = "ELF"

  condition:
    elf.number_of_sections >= 0
}

rule is_dart : file_type
{
  meta:
    description = "Dart"

    strings:
        $s1   = "dart:core" ascii
        $s2   = "dart:async" ascii
        $s3   = "_kDartVmSnapshotData" ascii
        $s4   = "_kDartVmSnapshotInstructions" ascii
        $s5   = "flutter_assets" ascii
        $ksnl = { 4B 53 4E 4C } // "KSNL" in hex

  condition:
        is_elf and 2 of ($s*) or $ksnl
}
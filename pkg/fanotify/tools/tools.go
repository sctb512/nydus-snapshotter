/*
 * Copyright (c) 2023. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package tools

import "sort"

func AccessedFileExist(accessedFiles []string, filePath string) bool {
	tmpAccessedFiles := make([]string, len(accessedFiles))
	copy(tmpAccessedFiles, accessedFiles)
	sort.Strings(tmpAccessedFiles)
	if index := sort.SearchStrings(tmpAccessedFiles, filePath); index < len(tmpAccessedFiles) && tmpAccessedFiles[index] == filePath {
		return true
	}
	return false
}

//go:build !unix

package separate

import "os"

// fileOwner is unknown off Unix.
func fileOwner(os.FileInfo) (uid int, ok bool) { return 0, false }

// fileLinks is unknown off Unix.
func fileLinks(os.FileInfo) (n int, ok bool) { return 0, false }

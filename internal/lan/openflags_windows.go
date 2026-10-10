package lan

import "os"

// openFlags: Windows has no pipes in a folder, and making a link takes
// an administrator; openInbox checks the file is regular before and
// after opening it.
const openFlags = os.O_RDONLY

func isLinkErr(error) bool { return false }

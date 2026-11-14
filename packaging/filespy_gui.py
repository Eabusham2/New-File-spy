"""Entry point of FileSpy.exe (the window). Build with: see .github/workflows/ci.yml"""

import sys

from filespy.gui import main

if __name__ == "__main__":
    sys.exit(main())

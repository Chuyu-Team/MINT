# MINT Release Notes

**MINT 2024.1**

- Update PHNT from System Informer to
  https://github.com/winsiderss/systeminformer/tree/433baa1d8156efc426d5e7257ff8fc8dea0cbc92.
- Update documents.

**MINT 2024.0**

- Use PHNT from System Informer (originally Process Hacker) instead of two years
  ago standalone version, and we can use the MIT License without issues.
- No longer use amalgamated header mode but keep header-only mode to improve 
  the upstream synchronization experience.
- Start containing the kernel mode definitions.
- Start private definition from the PHNT.
- Rewrite the ZwGen tool to improve the maintenance experience.
- Add NuGet packaging support.
- Use Mile.Project.Windows to manage the maintainer tools.
- Update email address for source code.

**MINT 2023.0**

- Initial release.
- Sync from the latest PHNT GitHub repository.
  (https://github.com/winsiderss/phnt/commit/7c1adb8a7391939dfd684f27a37e31f18d303944)
- Use WIN32_NO_STATUS to simplify the NTSTATUS related definitions. (Suggested
  by xenoplastic.)
- Define NTSTATUS for solving some potential compilation issues. (Suggested by
  sonyps5201314.)

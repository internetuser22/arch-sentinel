# Installing Arch Sentinel as a pacman package

From this folder:

    makepkg -si

This builds the app from the project two folders up, runs its tests, installs it as the
`arch-sentinel` package, and pulls in everything it can use from the official repositories:
pacutils, clamav, the full opensnitch firewall (daemon and its pop-up app, plus its optional
extras), rkhunter, unhide, testdisk (PhotoRec), udisks2, bubblewrap and strace (sandbox), polkit, curl, libnotify, zip and unzip.
No AUR helper is needed. It also adds "Scan for viruses (Arch Sentinel)" to the right-click
menu in Dolphin and Nemo (Nautilus users can add it from the app's Settings).

To update later: raise `version` in `Cargo.toml`, then run `makepkg -si` again.
To remove it: `sudo pacman -R arch-sentinel`.

After installing, open Background jobs once and press **Apply scan timers** (and
**Install timer** for freshclam) so the timers point at `/usr/bin/arch-sentinel` instead of
the development copy. If you had "Start in the tray when I log in" on, switch it off and on
again for the same reason.

![Build status](https://github.com/adepierre/Sniffcraft/actions/workflows/automatic_release.yml/badge.svg)
[![Discord](https://badgen.net/badge/icon/discord?icon=discord&label)](https://discord.gg/wECVsTbjA9)

# SniffCraft

SniffCraft is a cross-platform C++ proxy which let you inspect the content of each packet sent through any minecraft client and server. It can run either with a GUI or in headless mode.

It works as a man-in-the-middle: instead of connecting directly to the server, you ask your client to connect to SniffCraft which then is connected to the server. All packets are transmitted to their original recipient and are simultaneously logged on-the-fly.

```
    ┌────────┐       ┌──────────────┐       ┌────────┐
    │        ├───────► - - - - - - -├───────►        │
    │ Client │       │  SniffCraft  │       │ Server │
    │        ◄───────┤- - - - - - - ◄───────┤        │
    └────────┘       └──────┬───────┘       └────────┘
                            │
                            ▼
                         Logfile
```

## Features

- Supported minecraft versions: all official releases from 1.12.2 to 1.21.3
- GUI mode
- Packet logging with different levels of details (ignore packet, log packet name only, log full packet content)
- Detailed network usage recap
- Compression is supported
- Offline ("cracked") mode and online mode (with Microsoft account) are supported
- Secure chat is supported
- Logging raw packets at byte level
- Configuration (which packet to log/ignore) can be changed on-the-fly without restarting
- Automatically create a session file to log information, can also optionally log to console at the same time
- Save full session to binary file and reopen them later in the GUI
- Creating a [replay mod](https://github.com/ReplayMod/ReplayMod) capture of the session is also possible, see [Replay Mod section](#replay-mod) for more details
- No log at all is possible, in this case, SniffCraft becomes a pure proxy that you can adapt to block/modify any packet you want

1.20.5 transfer packet is **not** supported yet.

<img width="600" src="https://github.com/adepierre/SniffCraft/assets/24371370/8c6b04d3-61e6-4fdc-aa1e-7e9505ac6033" alt="Sniffcraft GUI" align="center">


### Encryption is supported

Encryption is supported by moving the authentication step from the client to Sniffcraft. This means that all the traffic from the client to Sniffcraft is not encrypted, but the traffic between Sniffcraft and the server is.

There are two options in the conf file regarding authentication. ``Online`` must be true to connect to a server with authentication activated. SniffCraft will prompt you instructions on the console to log in with a Microsoft account (only the first time, will use cached credentials for the next ones, you can cache multiple Microsoft accounts using different ``MicrosoftAccountCacheKey``).

Depending on the version you are using, there are additional restrictions regarding authentication:
- for versions up to 1.18.2 and 1.19.3+, you can use any client you want ("cracked" or regular with any account) as long as you are authenticated with a valid account in sniffcraft.
- for versions 1.19 to 1.19.2, there are two subcases:
    - if the server has the option `enforce-secure-profile` set to false, then it's the same as for the other versions, you can use any client you want.
    - if the server has the option `enforce-secure-profile` set to true, then you **must** use a client authenticated with the **same** account you are using in Sniffcraft. Otherwise you will be kicked out for signing key mismatch as soon as you try to send a chat message.

If you want to be sure Sniffcraft is using the latest certificates for your account (for 1.19+ versions), you can set botcraft_cached_credentials\["TheMicrosoftAccountCacheKeyYouSet"\]\["certificates"\]\["expires_date"\] to 0 and Sniffcraft will then retreive the latest ones from Mojang server.

### Mod support

Sniffcraft has been confirmed to work with heavily modded client/server using Forge. It is however not regularly tested against all possible modded environments and some adjustments might be required in some cases. If you find such a case, please open an issue or join the [community discord server](https://discord.gg/wECVsTbjA9) and describe the usecase with as much details as possible (minecraft version, server IP, client/server mods etc...).

If you want to print the content of Custom Payload packets (both from client and server), you need to use protocolCraft plugins to extend the protocol knowledge with mod-specific packets. See the [protocolCraft-plugin](https://github.com/adepierre/protocolcraft-plugin) repo for details.

## GUI support

If compiled with the cmake option SNIFFCRAFT_WITH_GUI, a GUI will appear when starting SniffCraft. This can be disabled by launching it with the ``--headless`` command line argument. In GUI mode, packets data are kept in memory while the session is displayed in GUI. This is usually not really an issue for regular usecase. However, if you plan to do some multi-hours long capture sessions or have a lot of sessions running simultaneously, it is recommended to use the ``--headless`` argument (or SniffCraft compiled without GUI enabled). This way, all data will only be stored in files and not in the RAM. SniffCraft binary files (**NOT** text files) can be reimported later in the GUI by simply dragging them onto SniffCraft window.

## Dependencies

You don't have to install any dependency to build SniffCraft, everything that is not already on your system will be automatically downloaded and locally built during the build process.

- [asio](https://think-async.com/Asio/)
- [zlib](https://github.com/madler/zlib)
- [openssl](https://www.openssl.org/) (optional, only if cmake option SNIFFCRAFT_WITH_ENCRYPTION is set)
- [botcraft](https://github.com/adepierre/botcraft)

GUI dependencies (only if cmake option SNIFFCRAFT_WITH_GUI is set)
- [glad](https://github.com/Dav1dde/glad)
- [glfw](https://github.com/glfw/glfw)
- [Dear ImGui](https://github.com/ocornut/imgui)

## Build and launch

Precompiled binaries for the latest game version with encryption and GUI support can be found in the [latest release](https://github.com/adepierre/SniffCraft/releases/tag/latest). If you want to build it yourself:
```
git clone https://github.com/adepierre/SniffCraft.git
cd SniffCraft
mkdir build
cd build
cmake -DGAME_VERSION=latest -DSNIFFCRAFT_WITH_ENCRYPTION=ON -DSNIFFCRAFT_WITH_GUI=ON ..
cmake --build . --config Release
```

If you need more help, you can join the Sniffcraft/Botcraft community [discord server](https://discord.gg/wECVsTbjA9).

Once built, you can start SniffCraft by double clicking the executable (by default, compiled executable file can be found in ``bin`` folder next to the source code), or with the following command line:

```
sniffcraft <optional:--headless> <optional:conf/file/path>
```

conf/file/path is the path to a json file, and can be used to set authentication information and filter out the packets. Examples can be found in the [conf](conf/) directory. If no path is given, a default conf.json file will be created. With the default configuration, only the names of the packets are logged. When a packet is added to an ignored list, it won't appear in the logs, when it's in a detail list, its full content will be logged. Packets can be added either by id or by name (as registered in protocolCraft), but as id can vary from one version to another, using names is safer.

ServerAddress should match the address of the server you want to connect to, with the same format as in a regular minecraft client. Custom URL with DNS SRV records are supported (like MyServer.Example.net for example). You can then connect your official minecraft client to SniffCraft as if it were a regular server using <your computer IP:LocalPort>. If you are running SniffCraft on the same computer as your client, something like 127.0.0.1:LocalPort should work.

## Replay Mod

If ``LogToReplay`` is present and set to true in the configuration file when the session starts, all packets will also be logged in a format compatible with [replay mod](https://github.com/ReplayMod/ReplayMod). When the capture stops, you'll get a ``XXXX.mcpr`` file that can be opened by the replay mod viewer inside minecraft. Note that this is a compressed format. It may take a few seconds after the connection is closed for this file to be created correctly. Make sure you don't close SniffCraft during this time.

The current player will **not** appear on this capture, as the replay mod artificially adds some packets to display it.

## License

GPL v3

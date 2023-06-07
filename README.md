![Build status](https://github.com/adepierre/Sniffcraft/actions/workflows/build.yml/badge.svg)
[![Discord](https://badgen.net/badge/icon/discord?icon=discord&label)](https://discord.gg/wECVsTbjA9)

# SniffCraft

SniffCraft is a cross-platform C++ proxy which let you inspect the content of each packet sent through any minecraft client and server.

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

- Supported minecraft versions: all official releases from 1.12.2 to 1.20
- Packet logging with different levels of details (ignore packet, log packet name only, log full packet content)
- Detailed network usage recap at the end of the session
- Compression is supported
- Offline ("cracked") mode and online mode (with Microsoft account) are supported
- Secure chat is supported
- Logging raw packets at byte level
- Configuration (which packet to log/ignore) can be changed on-the-fly without restarting
- Automatically create a session file to log information, can also optionally log to console at the same time
- Creating a [replay mod](https://github.com/ReplayMod/ReplayMod) capture of the session is also possible, see [Replay Mod section](#replay-mod) for more details

Here is an example of a captured session:
```javascript
[0:00:48:050] [S --> C] Block Changed Ack
[0:00:48:064] [C --> S] Swing
[0:00:48:115] [C --> S] Swing
[0:00:48:166] [C --> S] Swing
[0:00:49:315] [C --> S] Use Item On
{
    "cursor_position_x": 0.0,
    "cursor_position_y": 0.9097926616668701,
    "cursor_position_z": 0.17363852262496948,
    "direction": 4,
    "hand": 0,
    "inside": false,
    "location": {
        "x": -119,
        "y": 83,
        "z": 261
    },
    "sequence": 11
}
[0:00:49:348] [S --> C] Block Changed Ack
```
And an example of the summary you can find at the end of the session logfile:
```bash
+============================================================+  +================================================================+
|                     Server ---> Client                     |  |                       Client ---> Server                       |
+============================================================+  +================================================================+
|          Name          |     Count      |    Bandwidth     |  |              Name              |    Count     |   Bandwidth    |
+------------------------+----------------+------------------+  +--------------------------------+--------------+----------------+
| Total                  | 23862 (100.0%) | 8340248 (100.0%) |  | Total                          | 902 (100.0%) | 28156 (100.0%) |
| Level Chunk With Light |  1558 ( 6.53%) | 7988945 (95.79%) |  | Move Player PosRot             | 481 (53.33%) | 17316 (61.50%) |
| Move Entity PosRot     |  4001 (16.77%) |   55894 ( 0.67%) |  | Move Player Pos                | 368 (40.80%) | 10304 (36.60%) |
| Move Entity Pos        |  4495 (18.84%) |   53568 ( 0.64%) |  | Move Player Rot                |  19 ( 2.11%) |   228 ( 0.81%) |
| Set Entity Motion      |  3854 (16.15%) |   42083 ( 0.50%) |  | Player Command                 |  26 ( 2.88%) |   182 ( 0.65%) |
| Rotate Head            |  6240 (26.15%) |   36836 ( 0.44%) |  | Chat Command                   |   1 ( 0.11%) |    42 ( 0.15%) |
| Set Entity Data        |   745 ( 3.12%) |   27726 ( 0.33%) |  | Keep Alive                     |   3 ( 0.33%) |    33 ( 0.12%) |
| Light Update           |    66 ( 0.28%) |   23880 ( 0.29%) |  | Custom Payload|minecraft:brand |   1 ( 0.11%) |    27 ( 0.10%) |
| Add Entity             |   373 ( 1.56%) |   20832 ( 0.25%) |  | Client Information             |   1 ( 0.11%) |    16 ( 0.06%) |
| Update Recipes         |     1 ( 0.00%) |   19738 ( 0.24%) |  | Accept Teleportation           |   1 ( 0.11%) |     4 ( 0.01%) |
| Update Attributes      |   330 ( 1.38%) |   15965 ( 0.19%) |  | Move Player Status Only        |   1 ( 0.11%) |     4 ( 0.01%) |
| Forget Level Chunk     |  1160 ( 4.86%) |   12760 ( 0.15%) |  |                                |              |                |
+------------------------+----------------+------------------+  +--------------------------------+--------------+----------------+
```


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


## Dependencies

You don't have to install any dependency to build SniffCraft, everything that is not already on your system will be automatically downloaded and locally built during the build process.

- [asio](https://think-async.com/Asio/)
- [zlib](https://github.com/madler/zlib)
- [openssl](https://www.openssl.org/) (optional, only if cmake option SNIFFCRAFT_WITH_ENCRYPTION is set)
- [botcraft](https://github.com/adepierre/botcraft)

## Build and launch

Precompiled binaries for the latest game version with encryption support can be found in the [latest release](https://github.com/adepierre/SniffCraft/releases/tag/latest). If you want to build it yourself:
```
git clone https://github.com/adepierre/SniffCraft.git
cd SniffCraft
mkdir build
cd build
cmake -DGAME_VERSION=latest -DSNIFFCRAFT_WITH_ENCRYPTION=ON ..
cmake --build . --config Release
```

If you need more help, you can join the Sniffcraft/Botcraft community [discord server](https://discord.gg/wECVsTbjA9).

Once built, you can start SniffCraft with the following command line:

```
sniffcraft listening_port server_address conf_filepath
```

conf_filepath is the path to a json file, and can be used to set authentication information and filter out the packets. Examples can be found in the [conf](conf/) directory. With the default configuration, only the names of the packets are logged. When a packet is added to an ignored list, it won't appear in the logs, when it's in a detail list, its full content will be logged. Packets can be added either by id or by name (as registered in protocolCraft), but as id can vary from one version to another, using names is safer.

server_address should match the address of the server you want to connect to, with the same format as in a regular minecraft client. Custom URL with DNS SRV records are supported (like MyServer.Example.net for example). You can then connect your official minecraft client to SniffCraft as if it were a regular server. If you are running SniffCraft on the same computer as your client, something as 127.0.0.1:listening_port should work.

## Replay Mod

If ``LogToReplay`` is present and set to true in the configuration file when the session starts, all packets will also be logged in a format compatible with [replay mod](https://github.com/ReplayMod/ReplayMod). When the capture stops, you'll get a ``XXXX.mcpr`` file that can be opened by the replay mod viewer inside minecraft.

Please note that the current player will **not** appear on this capture, as the replay mod artificially adds some packets to display it.

## License

GPL v3

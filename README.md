
# SniffCraft

SniffCraft is a cross-platform C++ proxy which let you inspect the content of each packet sent through any minecraft client and server. 

It works as a man-in-the-middle: instead of connecting directly to the server, you ask your client to connect to SniffCraft which then is connected to the server. All packets are transmitted to their original recipient and are simultaneously logged on-the-fly.

## Features and limitations

- Supported minecraft versions: 1.12.2, 1.13, 1.13.1, 1.13.2, 1.14, 1.14.1, 1.14.2, 1.14.3, 1.14.4, 1.15, 1.15.1, 1.15.2, 1.16, 1.16.1, 1.16.2, 1.13.3
- Packet logging with different levels of details (ignor packet, log packet name only, log full packet content)
- Compression is supported
- Configuration (which packet to log/ignore) can be changed without restarting
- Automatically create a session file to log information, can also optionally log to console at the same time

Here is an example of a captured session:
```javascript
[0:0:6:6817] [S --> C] Time Update
[0:0:6:6868] [S --> C] Destroy Entities
[0:0:7:7149] [C --> S] Player Block Placement
[0:0:7:7150] [C --> S] Animation (serverbound)
[0:0:7:7169] [S --> C] Set Slot
{
  "slot": 30,
  "slot_data": {
    "block_id": 54,
    "item_count": 1,
    "item_damage": 0
  },
  "window_id": 1
}
[0:0:7:7169] [S --> C] Block change
{
  "block_id": 980,
  "location": {
    "x": -160,
    "y": 67,
    "z": 206
  }
}
```


### /!\ Encryption is not supported /!\

As both the client and the server must share the same public key when authenticating to Mojang's session server, we can't use an intermediate decrypt/encrypt layer. I'd like to support encryption too, but I'm affraid that's simply not possible (feel free to open an issue if you have any suggestion on this matter). Use SniffCraft only with server with online-mode=false.

## Dependencies

You don't have to install any dependency to build SniffCraft, everything that is not already on your system will be automatically downloaded and locally built during the build process.

- [asio](https://think-async.com/Asio/)
- [picoJson](https://github.com/kazuho/picojson)
- [zlib](https://github.com/madler/zlib)
- [botcraft](https://github.com/adepierre/botcraft) (actually, I'm only using protocolCraft lib, but as I haven't separated it from my Botcraft repo, everything is downloaded)

## Building and launch

To build for game version 1.16.3:
```
git clone https://github.com/adepierre/SniffCraft.git
cd sniffcraft
mkdir build
cd build
cmake -DGAME_VERSION=1.16.3 ..
make all
```

If you are on Windows, you can replace the last four steps by launching cmake GUI and then compiling the generated .sln from Visual Studio.

Once built, you can start SniffCraft with the following command line:

```
sniffcraft listening_port server_ip server_port logconf_filepath
```

logconf_filepath is an optional json file, and can be used to filter out the packets. Examples can be found in the [conf](conf/) directory. With the default configuration, only the names of the packets are logged. When a packet is added to an ignored list, it won't appear in the logs, when it's in a detail list, its full content will be logged. Packets can be added either by id or by name (as registered in protocolCraft), but as id can vary from one version to another, using names is safer.

server_ip and server_port should match the address of the server you want to connect to. You can then connect your official minecraft client to SniffCraft as if it were a regular server. If you are running SniffCraft on the same computer as your client, something as 127.0.0.1:listening_port should work.

## License

GPL v3

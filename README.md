# applespi
Apple SPI interfaces/headers and convenience wrappers for them

# applespi-log
Turns out os_log/libtrace firehose is as easy as ~50 lines of C
if you're in the admin group.

```ocaml
event_handler obj: 0x6000005a80f0 desc: '<dictionary: 0x6000005a80f0> { count = 25, transaction: 1, voucher = 0x6000019a80f0, contents =
"action" => <uint64: 0x818847d7e413e6b7>: 6
"subsystem" => <string: 0x6000034a8300> { length = 18, contents = "com.apple.SkyLight" }
"timestamp" => <uint64: 0x8189ed604ba95577>: 58647610087038
"imagepath" => <string: 0x6000034a8330> { length = 72, contents = "/System/Library/PrivateFrameworks/SkyLight.framework/Versions/A/SkyLight" }
"thread" => <uint64: 0x818847d79047ed67>: 243958140
"signpostid" => <uint64: 0x600003aa9340>: 17216892719917625070
"timezoneMinutesWest" => <int64: 0x810847d7e413efe7>: 300
"timeGMTusec" => <int64: 0x810847d7e43ef267>: 369308
"procpath" => <string: 0x6000034a83c0> { length = 86, contents = "/System/Library/PrivateFrameworks/SkyLight.framework/Versions/A/Resources/WindowServer" }
"persisted" => <bool: 0x1e0211780>: true
"buffer" => <data: 0x600002fa8340>: { length = 12 bytes, contents = 0x00010208f1eef5f556350000 }
"offset" => <uint64: 0x818847d7e57730e7>: 2923212
"procid" => <uint64: 0x818847d7b4be8537>: 169192566
"category" => <string: 0x6000034a83f0> { length = 27, contents = "performance_instrumentation" }
"name" => <string: 0x6000034a8420> { length = 45, contents = "%{public, signpost.description:begin_time}llu"" }
"imageuuid" => <uuid: 0x6000034a8450> "F666CCE9-0B6D-3405-BC17-3B963BB96867"
"type" => <uint64: 0x818847d7e413d687>: 1536
"procuuid" => <uuid: 0x6000034a84b0> "A10E0584-2786-38B8-B14C-828C9A9E74C8"
"uid" => <uint64: 0x818847d7e413e447>: 88
"formatstring" => <string: 0x6000034a84e0> { length = 45, contents = "%{public, signpost.description:begin_time}llu"" }
"traceid" => <uint64: 0x600003aa9380>: 431391173136121862
"signpostname" => <string: 0x6000034a8510> { length = 13, contents = "CompositeLoop" }
"timeGMTsec" => <int64: 0x810847d4d9c103e7>: 1740266668
"pid" => <uint64: 0x818847d7e41accef>: 75085
"formatoffset" => <uint64: 0x818847d7cbf73967>: 100441084
}'


```

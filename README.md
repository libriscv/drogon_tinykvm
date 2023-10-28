# TinyKVM in Drogon

This is an example repository that embeds TinyKVM in Drogon. TinyKVM provides safe sandboxing for tenants/programs.

We can reach 1.8M req/s with native performance KVM-based VMs handling requests with ~19us latency.

## Benchmarks

```
-- TINYKVM MULTI-TENANT HELLO WORLD --

$ ./wrk -c32 -t32 http://127.0.0.1:8080/
Running 10s test @ http://127.0.0.1:8080/
  32 threads and 32 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    18.90us   56.21us   5.14ms   99.45%
    Req/Sec    57.70k     7.80k   89.64k    74.78%
  18550339 requests in 10.10s, 2.35GB read
Requests/sec: 1836687.78
Transfer/sec:    238.22MB

$ ./wrk -c16 -t16 http://127.0.0.1:8080/
Running 10s test @ http://127.0.0.1:8080/
  16 threads and 16 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    11.65us   25.02us   6.01ms   99.95%
    Req/Sec    84.51k     6.68k  103.77k    83.66%
  13592105 requests in 10.10s, 1.91GB read
Requests/sec: 1345788.15
Transfer/sec:    193.80MB

$ ./wrk -c8 -t8 http://127.0.0.1:8080/
Running 10s test @ http://127.0.0.1:8080/
  8 threads and 8 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     9.43us    6.38us   1.17ms   97.01%
    Req/Sec   102.25k    15.92k  119.24k    85.52%
  8220606 requests in 10.10s, 1.16GB read
Requests/sec: 813978.61
Transfer/sec:    117.22MB

-- SCOUNTER stateful example --

$ ./wrk -c32 -t32 http://127.0.0.1:8080/ -H "Host: counter"
Running 10s test @ http://127.0.0.1:8080/
  32 threads and 32 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    18.62us   15.44us   3.21ms   95.10%
    Req/Sec    54.52k    14.68k   97.19k    74.16%
  17530839 requests in 10.10s, 2.45GB read
Requests/sec: 1735767.02
Transfer/sec:    248.30MB

$ curl http://127.0.0.1:8080/ -H "Host: counter"
Hello 33436184 World!

$ curl http://127.0.0.1:8080/ -H "Host: counter"
Hello 33436185 World!
```

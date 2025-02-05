# ECSplorer

developed by the [GINO group](https://net.in.tum.de/projects/gino/) and published with the [MPL-2.0 license](LICENSE).

Code contributors:
- [Patrick Sattler](https://net.in.tum.de/~sattler)
- [Roland Reif](https://github.com/RBReif)
- Patrick Grossmann

This ECSplorer implements the response-aware approach as presented in the paper [*ECSeptional DNS Data: Evaluating Nameserver ECS Deployments with Response-Aware Scanning*](https://arxiv.org/abs/2412.08478).
The results presented in this paper where obtained using the scanning tools provided in this repository.

**Authors:**
Patrick Sattler, Johannes Zirngibl, Fahad Hilal, Oliver Gasser, Kevin Vermeulen, Georg Carle, Mattijs Jonker

## Build from Source

Current supported GoLang version: 1.21

```
cd src
go build
```

## Manual
```sh
Usage of ecsplorer:
  -6    Perfom IPv6 scan using BGP prefixes as seed
  -cc int
        CAPACITY of CHANNELS = Number of Domains we can scan concurrently (default 100)
  -config-file string
        Config file path
  -cp string
        CPU PROFILE = File to which cpuProfile shall be written
  -disable-store
        disable all storage
  -domain-outstanding int
        maximum number of domains which are scanned at once,                      == 0 to disable. (default 100)
  -if string
        INPUT FILE = The file in which the list of Domains we want to scan is stored.
  -ip4source string
        ipv4 source address to use during the scan
  -ip6source string
        ipv6 source address to use during the scan
  -lf string
        LOGGING FILE = File we want to log into
  -ll int
         LOGGING LEVEL = Level of how much we log. 0 (no logging) 1(only errors), 2 (informational), 3 (debugging) (default 2)
  -mp string
        MEMORY PROFILE = File to which memProfile shall be written
  -ni int
        NUMBER of IPGENERATORS = Number of concurrently called IPGenerators (default 20)
  -out string
        output Directory to write results
  -pf string
        PREFIX FILE = File where the bgp prefixes are stored
  -pl int
        PREFIX LENGTH = Prefix length we will use for the 'Source' field in the ECS in all our scans (default 24)
  -pr
        PRINT RESULT = Indicates if final result shall be printed
  -query-list string
        List of query parameters to use instead of normal trie based approach
  -query-rate int
        query rate per second,                                                    <= 0 for unlimited. (default 100)
  -randomize
        Randomize scan prefix selection
  -resolver string
        Set this to use a public resolver instead of the authoritative name server
  -retries int
        number of retries on error (default 3)
  -scanBGPOnly
        Only scan prefixes inside the BGP prefix list
  -sf string
        SPECIAL PREFIX FILE = File where the bgp prefixes are stored
  -te int
        TEMPORARY ERRORS = maximum number of temporary errors we accept for one domain-name server pair before stop scanning it (default 3)
  -timeout-dial duration
        Dial timeout (default 2s)
  -timeout-read duration
        Read timeout (default 2s)
  -timeout-write duration
        Write timeout (default 2s)
  -version
        show version string

```

We provide a [sample config file](config.yml.sample).

In [utils/specialPrefixes.csv](utils/specialPrefixes.csv) we collected special purpose prefixes (e.g., RFC1918 prefixes).

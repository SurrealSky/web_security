社会工程学
----------------------------------------

fake flash
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `Fake-flash <https://github.com/r00tSe7en/Fake-flash.cn>`_

OSINT
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `osint <http://osintframework.com/>`_
- `osint git <https://github.com/lockfale/OSINT-Framework>`_
- `OSINT-Collection <https://github.com/Ph055a/OSINT Collection>`_
- `trape <https://github.com/jofpin/trape>`_
- `Photon <https://github.com/s0md3v/Photon>`_
	+ 官方帮助:``https://github.com/s0md3v/Photon/wiki/Usage#dumping-dns-data``
	+ 基本用法:``python photon.py -u http://example.com``
	+ 克隆网站:``python photon.py -u "http://example.com" --clone``
	+ Depth of crawling:``-l or --level | Default: 2``
	+ Number of threads:``-t or --threads | Default: 2``
	+ Delay between each HTTP request:``-d or --delay | Default: 0``
	+ timeout:``--timeout | Default: 5``
	+ Cookies:``python photon.py -u "http://example.com" -c "PHPSESSID=u5423d78fqbaju9a0qke25ca87"``
	+ Specify output directory:``-o or --output | Default: domain name of target``
	+ Verbose output:``-v or --verbose``
	+ Exclude specific URLs:``python photon.py -u "http://example.com" --exclude="/blog/20[17|18]"``
	+ Specify seed URL(s):``python photon.py -u "http://example.com" --seeds "http://example.com/blog/2018,http://example.com/portals.html"``
	+ Specify user-agent(s):``python photon.py -u "http://example.com" --user-agent "curl/7.35.0,Wget/1.15 (linux-gnu)"``
	+ Custom regex pattern:``python photon.py -u "http://example.com" --regex "\d{10}"``
	+ Export formatted result:``python photon.py -u "http://example.com" --export=json``
	+ Use URLs from archive.org as seeds:``python photon.py -u "http://example.com" --wayback``
	+ Skip data extraction:``python photon.py -u "http://example.com" --only-urls``
	+ Update:``python photon.py --update``
	+ Extract secret keys:``python photon.py -u http://example.com --keys``
	+ Piping (Writing to stdout):``python photon.py -u http://example.com --stdout=custom | resolver.py``
	+ Ninja Mode:``--ninja``
	+ Dumping DNS data:``python photon.py -u http://example.com --dns``
- `pockint <https://github.com/netevert/pockint>`_

钓鱼
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `spoofcheck <https://github.com/BishopFox/spoofcheck>`_
- `gophish <https://github.com/gophish/gophish>`_
- `SocialFish <https://github.com/UndeadSec/SocialFish>`_
- `WiFiDuck <https://github.com/spacehuhn/WiFiDuck>`_ Bad USB

wifi
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `wifiphisher <https://github.com/wifiphisher/wifiphisher>`_
- `evilginx <https://github.com/kgretzky/evilginx>`_
- `mana <https://github.com/sensepost/mana>`_
- `pwnagotchi <https://github.com/evilsocket/pwnagotchi>`_

综合框架
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `theHarvester <https://github.com/laramies/theHarvester>`_
- `Th3inspector <https://github.com/Moham3dRiahi/Th3inspector>`_
- `ReconDog <https://github.com/s0md3v/ReconDog>`_

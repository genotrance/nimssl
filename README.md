Nimssl is a [Nim](https://nim-lang.org/) wrapper for the [OpenSSL](https://github.com/openssl/openssl) library.

Nimssl is distributed as a [Nimble](https://github.com/nim-lang/nimble) package and depends on [Nimterop](https://github.com/nimterop/nimterop) to generate the wrappers. The OpenSSL source code is downloaded using Git so having ```git``` in the path is required.

__Installation__

Nimssl can be installed via [Nimble](https://github.com/nim-lang/nimble):

```
> nimble install nimssl
```

This will download, wrap and install nimssl in the standard Nimble package location, typically ~/.nimble. Once installed, it's libraries can be imported into any Nim program.

__Usage__

Module documentation can be found [here](http://nimgen.genotrance.com/nimssl).

```nim
import nimssl/crypto

var test = "Hello, world!"
var hash = SHA256(addr test[0], test.len(), nil)

echo cast[ptr array[dlen, char]](hash).toHex()
```

Nimssl currently wraps almost everything from OpenSSL's libcrypto and libssl, but few things are tested (refer to `tests`). Contributions to the tests pool are appreciated!

__Credits__

Nimssl wraps the OpenSSL source code and all licensing terms of [OpenSSL](https://www.openssl.org/source/license.html) apply to the usage of this package.

Credits go out to [Nimterop](https://github.com/nimterop/nimterop) as well without which this package would be greatly limited in its abilities.

__Feedback__

Nimssl is a work in progress and any feedback or suggestions are welcome. It is hosted on [GitHub](https://github.com/genotrance/nimssl) with an MIT license so issues, forks and PRs are most appreciated.

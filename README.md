Nimssl is a [Nim](https://nim-lang.org/) wrapper for the [OpenSSL](https://github.com/openssl/openssl) library.

Nimssl is distributed as a [Nimble](https://github.com/nim-lang/nimble) package and depends on [nimgen](https://github.com/genotrance/nimgen) and [c2nim](https://github.com/nim-lang/c2nim/) to generate the wrappers. The OpenSSL source code is downloaded using Git so having ```git``` in the path is required.

__Installation__

Nimssl can be installed via [Nimble](https://github.com/nim-lang/nimble):

```> nimble install https://github.com/genotrance/nimssl```

This will download, wrap and install nimssl in the standard Nimble package location, typically ~/.nimble. Once installed, it can be imported into any Nim program.

__Usage__

```nim
import nimssl/sha

var test = "hello world"
var hash = SHA256(addr test[0], test.len(), nil)

echo cast[ptr array[dlen, char]](hash).toHex()
```

```toHex()``` is defined in ```nimssl/sha.nim``` and converts the hash array into a hex string. ```tests/shatest.nim``` has examples for all the hash functions available.

```nimssl/sha``` performs much faster than ```nimSHA2``` in a normal compile, but comparably when compiled with ```-d:release```.

Nimssl currently wraps the SHA functions within OpenSSL. Refer to the ```tests``` directory for examples on how the library can be used. AES is already wrapped but is yet to be tested.

__Credits__

Nimssl wraps the OpenSSL source code and all licensing terms of [OpenSSL](https://www.openssl.org/source/license.html) apply to the usage of this package.

Credits go out to [c2nim](https://github.com/nim-lang/c2nim/) as well without which this package would be greatly limited in its abilities.

__Feedback__

Nimssl is a work in progress and any feedback or suggestions are welcome. It is hosted on [GitHub](https://github.com/genotrance/nimssl) with an MIT license so issues, forks and PRs are most appreciated.

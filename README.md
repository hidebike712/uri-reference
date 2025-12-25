# Java URI Library Compliant with RFC 3986

## Overview

This library is designed in accordance with [RFC 3986](https://datatracker.ietf.org/doc/rfc3986/), the latest authoritative
specification for URIs. It offers advanced URI management capabilities beyond those found in Java's standard `java.net.URI`
class, which still conforms to the outdated [RFC 2396](https://datatracker.ietf.org/doc/rfc2396). Below are some of the
challenges you may encounter with `java.net.URI`:

#### :red_circle: Host containing underscores (`_`)

RFC 3986 permits underscores (`_`) in the host part of URI references; however, RFC 2396 does not allow them. `java.net.URI`
class does not recognize these as valid, resulting in unexpected behaviors:

```java
// Create a URI whose host contains an underscore.
java.net.URI u = new java.net.URI("http://my_host.com");

// This outputs 'null'.
System.out.println(u.getHost());
```

This issue has been acknowledged in multiple bug reports, such as [JDK-8019345](https://bugs.openjdk.org/browse/JDK-8019345)
and [JDK-8221675](https://bugs.openjdk.org/browse/JDK-8221675), yet it remains unresolved, presenting significant challenges
when working with such URIs.

#### :red_circle: IPvFuture Host

RFC 3986 introduces **IPvFuture** as a valid host type, such as in `v9.abc:def`, but `java.net.URI` fails to parse these,
leading to exceptions:

```java
// This throws "java.net.URISyntaxException".
new java.net.URI("http://[v9.abc:def]");
```

#### :red_circle: Scheme-only URI

RFC 3986 allows scheme-only URIs such as `data:` but those URIs can't be parsed by `java.net.URI` class.

```java
// This throws "java.net.URISyntaxException".
new java.net.URI("data:");
```

Using this library ensures compliance with modern URI standards and avoids these and other issues.

The library offers four key functionalities for robust URI management:

- [Parsing](#parsing)
- [Resolving](#resolving)
- [Normalizing](#normalizing)
- [Constructing](#constructing)

Each feature is designed to handle URIs accurately and effectively, ensuring reliable and precise management across various
application contexts.

## Installation

```xml
<dependency>
    <groupId>org.czeal</groupId>
    <artifactId>uri-reference</artifactId>
    <version>{version}</version>
</dependency>
```

## License

Apache License, Version 2.0

## Java Doc

https://hidebike712.github.io/uri-reference/

## Usage

<a id="parsing"></a>
### :white_check_mark: Parsing

To parse URI references, use `URIReference.parse(String uriRef)` or `URIReference.parse(String uriRef, Charset charset)`. Below are some examples of using `URIReference.parse(String uriRef)`.

#### Example 1: Parse Basic URI

```java
URIReference uriRef = URIReference.parse("http://example.com/a/b"); // Parse.

System.out.println(uriRef.toString());                // "http://example.com/a/b"
System.out.println(uriRef.isRelativeReference());     // false
System.out.println(uriRef.getScheme());               // "http"
System.out.println(uriRef.hasAuthority());            // true
System.out.println(uriRef.getAuthority().toString()); // "example.com"
System.out.println(uriRef.getUserinfo());             // null
System.out.println(uriRef.getHost().getType());       // "REGNAME"
System.out.println(uriRef.getHost().getValue());      // "example.com"
System.out.println(uriRef.getPort());                 // -1
System.out.println(uriRef.getPath());                 // "/a/b"
System.out.println(uriRef.getQuery());                // null
System.out.println(uriRef.getFragment());             // null
```

#### Example 2: Parse Relative Reference

```java
URIReference uriRef = URIReference.parse("//example.com/a/b"); // Parse.

System.out.println(uriRef.toString());                // "//example.com/a/b"
System.out.println(uriRef.isRelativeReference());     // false
System.out.println(uriRef.getScheme());               // null
System.out.println(uriRef.hasAuthority());            // true
System.out.println(uriRef.getAuthority().toString()); // "example.com"
System.out.println(uriRef.getUserinfo());             // null
System.out.println(uriRef.getHost().getType());       // "REGNAME"
System.out.println(uriRef.getHost().getValue());      // "example.com"
System.out.println(uriRef.getPort());                 // -1
System.out.println(uriRef.getPath());                 // "/a/b"
System.out.println(uriRef.getQuery());                // null
System.out.println(uriRef.getFragment());             // null
```

#### Example 3: Parse URI with IPV4 Host

```java
URIReference uriRef = URIReference.parse("http://101.102.103.104"); // Parse.

System.out.println(uriRef.toString());                // "http://101.102.103.104"
System.out.println(uriRef.isRelativeReference());     // false
System.out.println(uriRef.getScheme());               // "http"
System.out.println(uriRef.hasAuthority());            // true
System.out.println(uriRef.getAuthority().toString()); // "101.102.103.104"
System.out.println(uriRef.getUserinfo());             // null
System.out.println(uriRef.getHost().getType());       // "IPV4"
System.out.println(uriRef.getHost().getValue());      // "101.102.103.104"
System.out.println(uriRef.getPort());                 // -1
System.out.println(uriRef.getPath());                 // ""
System.out.println(uriRef.getQuery());                // null
System.out.println(uriRef.getFragment());             // null
```

#### Example 4: Parse URI with IPV6 Host

```java
URIReference uriRef = URIReference.parse("http://[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]"); // Parse.

System.out.println(uriRef.toString());                // "http://[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]"
System.out.println(uriRef.isRelativeReference());     // false
System.out.println(uriRef.getScheme());               // "http"
System.out.println(uriRef.hasAuthority());            // true
System.out.println(uriRef.getAuthority().toString()); // "[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]"
System.out.println(uriRef.getUserinfo());             // null
System.out.println(uriRef.getHost().getType());       // "IPV6"
System.out.println(uriRef.getHost().getValue());      // "[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]"
System.out.println(uriRef.getPort());                 // -1
System.out.println(uriRef.getPath());                 // ""
System.out.println(uriRef.getQuery());                // null
System.out.println(uriRef.getFragment());             // null
```

#### Example 5: Parse URI with IPvFuture Host

```java
URIReference uriRef = URIReference.parse("http://[v9.abc:def]"); // Parse.

System.out.println(uriRef.toString());                // "http://[v9.abc:def]"
System.out.println(uriRef.isRelativeReference());     // false
System.out.println(uriRef.getScheme());               // "http"
System.out.println(uriRef.hasAuthority());            // true
System.out.println(uriRef.getAuthority().toString()); // "[v9.abc:def]"
System.out.println(uriRef.getUserinfo());             // null
System.out.println(uriRef.getHost().getType());       // "IPVFUTURE"
System.out.println(uriRef.getHost().getValue());      // "[v9.abc:def]"
System.out.println(uriRef.getPort());                 // -1
System.out.println(uriRef.getPath());                 // ""
System.out.println(uriRef.getQuery());                // null
System.out.println(uriRef.getFragment());             // null
```

#### Example 6: Parse URI with Percent-encoded Host

```java
URIReference uriRef = URIReference.parse("http://%65%78%61%6D%70%6C%65.com"); // Parse.

System.out.println(uriRef.toString());                // "http://%65%78%61%6D%70%6C%65.com"
System.out.println(uriRef.isRelativeReference());     // false
System.out.println(uriRef.getScheme());               // "http"
System.out.println(uriRef.hasAuthority());            // true
System.out.println(uriRef.getAuthority().toString()); // "%65%78%61%6D%70%6C%65.com"
System.out.println(uriRef.getUserinfo());             // null
System.out.println(uriRef.getHost().getType());       // "REGNAME"
System.out.println(uriRef.getHost().getValue());      // "%65%78%61%6D%70%6C%65.com"
System.out.println(uriRef.getPort());                 // -1
System.out.println(uriRef.getPath());                 // ""
System.out.println(uriRef.getQuery());                // null
System.out.println(uriRef.getFragment());             // null
```

> [!WARNING]
> If parsing fails, those methods throws `NullPointerException` or `IllegalArgumentException`. See [Java doc](https://hidebike712.github.io/uri-reference/) for more details.

---

<a id="resolving"></a>
### :white_check_mark: Resolving

To resolve a relative reference against a URI reference, use `resolve(String uriRef)` or `resolve(URIReference uriRef)`. Below is an example demonstrating how to resolve a relative reference against a base URI.

```java
// A base URI.
URIReference baseUri = URIReference.parse("http://example.com");

// A relative reference.
URIReference relRef = URIReference.parse("/a/b");

// Resolve the relative reference against the base URI.
URIReference resolved = baseUri.resolve(relRef);

System.out.println(resolved.toString());                // "http://example.com/a/b"
System.out.println(resolved.isRelativeReference());     // false
System.out.println(resolved.getScheme());               // "http"
System.out.println(resolved.hasAuthority());            // true
System.out.println(resolved.getAuthority().toString()); // "example.com"
System.out.println(resolved.getUserinfo());             // null
System.out.println(resolved.getHost().getType());       // "REGNAME"
System.out.println(resolved.getHost().getValue());      // "example.com"
System.out.println(resolved.getPort());                 // -1
System.out.println(resolved.getPath());                 // "/a/b"
System.out.println(resolved.getQuery());                // null
System.out.println(resolved.getFragment());             // null
```

---

<a id="normalizing"></a>
### :white_check_mark: Normalizing

For normalization, invoke `normalize()` on a `URIReference` instance to normalize.

#### Example 1: Normalize URI with Mixed-Case Scheme

```java
URIReference normalized = URIReference.parse("hTTp://example.com") // Parse.
                                      .normalize();                // Normalize.

System.out.println(normalized.toString());                // "http://example.com/"
System.out.println(normalized.isRelativeReference());     // false
System.out.println(normalized.getScheme());               // "http"
System.out.println(normalized.hasAuthority());            // true
System.out.println(normalized.getAuthority().toString()); // "example.com"
System.out.println(normalized.getUserinfo());             // null
System.out.println(normalized.getHost().getType());       // "REGNAME"
System.out.println(normalized.getHost().getValue());      // "example.com"
System.out.println(normalized.getPort());                 // -1
System.out.println(normalized.getPath());                 // "/"
System.out.println(normalized.getQuery());                // null
System.out.println(normalized.getFragment());             // null
```

#### Example 2: Normalize URI with Percent-Encoded Host

```java
URIReference normalized = URIReference.parse("http://%65%78%61%6D%70%6C%65.com") // Parse.
                                      .normalize();                              // Normalize.

System.out.println(normalized.toString());                // "http://example.com/"
System.out.println(normalized.isRelativeReference());     // false
System.out.println(normalized.getScheme());               // "http"
System.out.println(normalized.hasAuthority());            // true
System.out.println(normalized.getAuthority().toString()); // "example.com"
System.out.println(normalized.getUserinfo());             // null
System.out.println(normalized.getHost().getType());       // "REGNAME"
System.out.println(normalized.getHost().getValue());      // "example.com"
System.out.println(normalized.getPort());                 // -1
System.out.println(normalized.getPath());                 // "/"
System.out.println(normalized.getQuery());                // null
System.out.println(normalized.getFragment());             // null
```

#### Example 3: Normalize URI with Unresolved Path

```java
URIReference normalized = URIReference.parse("http://example.com/a/b/c/../d/") // Parse.
                                      .normalize();                            // Normalize.

System.out.println(normalized.toString());                // "http://example.com/a/b/d/"
System.out.println(normalized.isRelativeReference());     // false
System.out.println(normalized.getScheme());               // "http"
System.out.println(normalized.hasAuthority());            // true
System.out.println(normalized.getAuthority().toString()); // "example.com"
System.out.println(normalized.getUserinfo());             // null
System.out.println(normalized.getHost().getType());       // "REGNAME"
System.out.println(normalized.getHost().getValue());      // "example.com"
System.out.println(normalized.getPort());                 // -1
System.out.println(normalized.getPath());                 // "/a/b/d/"
System.out.println(normalized.getQuery());                // null
System.out.println(normalized.getFragment());             // null
```

#### Example 4: Normalize Relative Reference

```java
// Parse a relative reference.
URIReference relRef = URIReference.parse("/a/b/c/../d/");

// Resolve the relative reference against "http://example.com".
// NOTE: Relative references must be resolved before normalization.
URIReference resolved = relRef.resolve("http://example.com");

// Normalize the resolved URI.
URIReference normalized = resolved.normalize();

System.out.println(normalized.toString());                // "http://example.com/a/b/d/"
System.out.println(normalized.isRelativeReference());     // false
System.out.println(normalized.getScheme());               // "http"
System.out.println(normalized.hasAuthority());            // true
System.out.println(normalized.getAuthority().toString()); // "example.com"
System.out.println(normalized.getUserinfo());             // null
System.out.println(normalized.getHost().getType());       // "REGNAME"
System.out.println(normalized.getHost().getValue());      // "example.com"
System.out.println(normalized.getPort());                 // -1
System.out.println(normalized.getPath());                 // "/a/b/d/"
System.out.println(normalized.getQuery());                // null
System.out.println(normalized.getFragment());             // null
```

> [!CAUTION]
> Relative reference must be resolved before normalization as [RFC 3986, 5.2.1](https://datatracker.ietf.org/doc/html/rfc3986#section-5.2.1) states as below.
> > RFC 3986, 5.2.1. Pre-parse the Base URI
> >
> > A URI reference must be transformed to its target URI before
> > it can be normalized.---

<a id="constructing"></a>
### :white_check_mark: Constructing

To construct URI references, use `URIReferenceBuilder` class.

#### Example 1: Construct Basic URI

```java
URIReference uriRef = new URIReferenceBuilder()
                          .setScheme("http")
                          .setHost("example.com")
                          .setPath("/a/b/c")
                          .appendQueryParam("k1", "v1")
                          .build();

System.out.println(uriRef.toString());                // "http://example.com/a/b/c?k1=v1"
System.out.println(uriRef.isRelativeReference());     // false
System.out.println(uriRef.getScheme());               // "http"
System.out.println(uriRef.hasAuthority());            // true
System.out.println(uriRef.getAuthority().toString()); // "example.com"
System.out.println(uriRef.getUserinfo());             // null
System.out.println(uriRef.getHost().getType());       // "REGNAME"
System.out.println(uriRef.getHost().getValue());      // "example.com"
System.out.println(uriRef.getPort());                 // -1
System.out.println(uriRef.getPath());                 // "/a/b/c"
System.out.println(uriRef.getQuery());                // "k1=v1"
System.out.println(uriRef.getFragment());             // null
```

#### Example 2: Construct URI from Existing URI

```java
URIReference uriRef = new URIReferenceBuilder()
                          .fromURIReference("http://example.com/a/b/c?k1=v1")
                          .appendPath("d", "e", "f")
                          .appendQueryParam("k2", "v2")
                          .build();

System.out.println(uriRef.toString());                // "http://example.comd/a/b/c/d/e/f?k1=v1&k2=v2"
System.out.println(uriRef.isRelativeReference());     // false
System.out.println(uriRef.getScheme());               // "http"
System.out.println(uriRef.hasAuthority());            // true
System.out.println(uriRef.getAuthority().toString()); // "example.com"
System.out.println(uriRef.getUserinfo());             // null
System.out.println(uriRef.getHost().getType());       // "REGNAME"
System.out.println(uriRef.getHost().getValue());      // "example.com"
System.out.println(uriRef.getPort());                 // -1
System.out.println(uriRef.getPath());                 // "/a/b/c/d/e/f"
System.out.println(uriRef.getQuery());                // "k1=v1&k2=&v2"
System.out.println(uriRef.getFragment());             // null
```

> [!WARNING]
> The current implementation of `URIReferenceBuilder` class won't throw an exception until `build()` method is invoked even if invalid input is given since validation for each URI component is performed only when `build()` is called.

## Note

### :pushpin: Immutable class

This library designs most classes such as `URIReference` to be immutable. Here are some examples.

```java
// Example 1: Invoking the "normalize()" method creates a new URIReference instance.
URIReference normalized = URIReference.parse("hTTp://example.com").normalize();

// Example 2: Invoking the "resolve(String uriRef)" method creates a new URIReference instance.
URIReference resolved = URIReference.parse("http://example.com").resolve("/a/b");
```

## See Also

- [RFC 3986 - Uniform Resource Identifier (URI): Generic Syntax](https://datatracker.ietf.org/doc/rfc3986)
- [RFC 2396 - Uniform Resource Identifiers (URI): Generic Syntax](https://datatracker.ietf.org/doc/rfc2396)

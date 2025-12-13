/*
 * Copyright (C) 2024 Hideki Ikeda
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.czeal.rfc3986;


import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.czeal.rfc3986.TestUtils.assertThrowsISE;
import static org.czeal.rfc3986.TestUtils.assertThrowsNPE;
import org.junit.jupiter.api.Test;


public class URIReferenceResolverTest
{
    @Test
    public void test_resolve()
    {
        URIReference uriRef1 = new URIReferenceResolver().resolve(
            URIReference.parse("g:h", UTF_8), URIReference.parse("http://a/b/c/d;p?q", UTF_8));
        assertEquals("g:h", uriRef1.toString());
        assertEquals(false, uriRef1.isRelativeReference());
        assertEquals("g", uriRef1.getScheme());
        assertEquals(false, uriRef1.hasAuthority());
        assertEquals(null, uriRef1.getAuthority());
        assertEquals(null, uriRef1.getUserinfo());
        assertEquals(null, uriRef1.getHost());
        assertEquals(-1, uriRef1.getPort());
        assertEquals("h", uriRef1.getPath());
        assertEquals(null, uriRef1.getQuery());
        assertEquals(null, uriRef1.getFragment());

        URIReference uriRef2 = new URIReferenceResolver().resolve(
            URIReference.parse("g", UTF_8), URIReference.parse("http://a/b/c/d;p?q", UTF_8));
        assertEquals("http://a/b/c/g", uriRef2.toString());
        assertEquals(false, uriRef2.isRelativeReference());
        assertEquals("http", uriRef2.getScheme());
        assertEquals(true, uriRef2.hasAuthority());
        assertEquals("a", uriRef2.getAuthority().toString());
        assertEquals(null, uriRef2.getUserinfo());
        assertEquals("a", uriRef2.getHost().toString());
        assertEquals("a", uriRef2.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef2.getHost().getType());
        assertEquals(-1, uriRef2.getPort());
        assertEquals("/b/c/g", uriRef2.getPath());
        assertEquals(null, uriRef2.getQuery());
        assertEquals(null, uriRef2.getFragment());

        URIReference uriRef3 = new URIReferenceResolver().resolve(
            URIReference.parse("./g", UTF_8), URIReference.parse("http://a/b/c/d;p?q", UTF_8));
        assertEquals("http://a/b/c/g", uriRef3.toString());
        assertEquals(false, uriRef3.isRelativeReference());
        assertEquals("http", uriRef3.getScheme());
        assertEquals(true, uriRef3.hasAuthority());
        assertEquals("a", uriRef3.getAuthority().toString());
        assertEquals(null, uriRef3.getUserinfo());
        assertEquals("a", uriRef3.getHost().toString());
        assertEquals("a", uriRef3.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef3.getHost().getType());
        assertEquals(-1, uriRef3.getPort());
        assertEquals("/b/c/g", uriRef3.getPath());
        assertEquals(null, uriRef3.getQuery());
        assertEquals(null, uriRef3.getFragment());

        URIReference uriRef4 = new URIReferenceResolver().resolve(
            URIReference.parse("g/", UTF_8), URIReference.parse("http://a/b/c/d;p?q", UTF_8));
        assertEquals("http://a/b/c/g/", uriRef4.toString());
        assertEquals(false, uriRef4.isRelativeReference());
        assertEquals("http", uriRef4.getScheme());
        assertEquals(true, uriRef4.hasAuthority());
        assertEquals("a", uriRef4.getAuthority().toString());
        assertEquals(null, uriRef4.getUserinfo());
        assertEquals("a", uriRef4.getHost().toString());
        assertEquals("a", uriRef4.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef4.getHost().getType());
        assertEquals(-1, uriRef4.getPort());
        assertEquals("/b/c/g/", uriRef4.getPath());
        assertEquals(null, uriRef4.getQuery());
        assertEquals(null, uriRef4.getFragment());

        URIReference uriRef5 = new URIReferenceResolver().resolve(
            URIReference.parse("/g", UTF_8), URIReference.parse("http://a/b/c/d;p?q", UTF_8));
        assertEquals("http://a/g", uriRef5.toString());
        assertEquals(false, uriRef5.isRelativeReference());
        assertEquals("http", uriRef5.getScheme());
        assertEquals(true, uriRef4.hasAuthority());
        assertEquals("a", uriRef4.getAuthority().toString());
        assertEquals(null, uriRef4.getUserinfo());
        assertEquals("a", uriRef4.getHost().toString());
        assertEquals("a", uriRef4.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef4.getHost().getType());
        assertEquals(-1, uriRef4.getPort());
        assertEquals("/g", uriRef5.getPath());
        assertEquals(null, uriRef5.getQuery());
        assertEquals(null, uriRef5.getFragment());

        URIReference uriRef6 = new URIReferenceResolver().resolve(
            URIReference.parse("//g", UTF_8), URIReference.parse("http://a/b/c/d;p?q", UTF_8));
        assertEquals("http://g", uriRef6.toString());
        assertEquals(false, uriRef6.isRelativeReference());
        assertEquals("http", uriRef6.getScheme());
        assertEquals(true, uriRef6.hasAuthority());
        assertEquals("g", uriRef6.getAuthority().toString());
        assertEquals(null, uriRef6.getUserinfo());
        assertEquals("g", uriRef6.getHost().toString());
        assertEquals("g", uriRef6.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef6.getHost().getType());
        assertEquals(-1, uriRef6.getPort());
        assertEquals("", uriRef6.getPath());
        assertEquals(null, uriRef6.getQuery());
        assertEquals(null, uriRef6.getFragment());

        URIReference uriRef7 = new URIReferenceResolver().resolve(
            URIReference.parse("?y", UTF_8), URIReference.parse("http://a/b/c/d;p?q", UTF_8));
        assertEquals("http://a/b/c/d;p?y", uriRef7.toString());
        assertEquals(false, uriRef7.isRelativeReference());
        assertEquals("http", uriRef7.getScheme());
        assertEquals(true, uriRef7.hasAuthority());
        assertEquals("a", uriRef7.getAuthority().toString());
        assertEquals(null, uriRef7.getUserinfo());
        assertEquals("a", uriRef7.getHost().toString());
        assertEquals("a", uriRef7.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef7.getHost().getType());
        assertEquals(-1, uriRef7.getPort());
        assertEquals("/b/c/d;p", uriRef7.getPath());
        assertEquals("y", uriRef7.getQuery());
        assertEquals(null, uriRef7.getFragment());

        URIReference uriRef8 = new URIReferenceResolver().resolve(
            URIReference.parse("g?y", UTF_8), URIReference.parse("http://a/b/c/d;p?q", UTF_8));
        assertEquals("http://a/b/c/g?y", uriRef8.toString());
        assertEquals(false, uriRef8.isRelativeReference());
        assertEquals("http", uriRef8.getScheme());
        assertEquals(true, uriRef8.hasAuthority());
        assertEquals("a", uriRef8.getAuthority().toString());
        assertEquals(null, uriRef8.getUserinfo());
        assertEquals("a", uriRef8.getHost().toString());
        assertEquals("a", uriRef8.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef8.getHost().getType());
        assertEquals(-1, uriRef8.getPort());
        assertEquals("/b/c/g", uriRef8.getPath());
        assertEquals("y", uriRef8.getQuery());
        assertEquals(null, uriRef8.getFragment());

        URIReference uriRef9 = new URIReferenceResolver().resolve(
            URIReference.parse("#s", UTF_8), URIReference.parse("http://a/b/c/d;p?q", UTF_8));
        assertEquals("http://a/b/c/d;p?q#s", uriRef9.toString());
        assertEquals(false, uriRef9.isRelativeReference());
        assertEquals("http", uriRef9.getScheme());
        assertEquals(true, uriRef9.hasAuthority());
        assertEquals("a", uriRef9.getAuthority().toString());
        assertEquals(null, uriRef9.getUserinfo());
        assertEquals("a", uriRef9.getHost().toString());
        assertEquals("a", uriRef9.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef9.getHost().getType());
        assertEquals(-1, uriRef9.getPort());
        assertEquals("/b/c/d;p", uriRef9.getPath());
        assertEquals("q", uriRef9.getQuery());
        assertEquals("s", uriRef9.getFragment());

        URIReference uriRef10 = new URIReferenceResolver().resolve(
            URIReference.parse("g#s", UTF_8), URIReference.parse("http://a/b/c/d;p?q", UTF_8));
        assertEquals("http://a/b/c/g#s", uriRef10.toString());
        assertEquals(false, uriRef10.isRelativeReference());
        assertEquals("http", uriRef10.getScheme());
        assertEquals(true, uriRef10.hasAuthority());
        assertEquals("a", uriRef10.getAuthority().toString());
        assertEquals(null, uriRef10.getUserinfo());
        assertEquals("a", uriRef10.getHost().toString());
        assertEquals("a", uriRef10.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef10.getHost().getType());
        assertEquals(-1, uriRef10.getPort());
        assertEquals("/b/c/g", uriRef10.getPath());
        assertEquals(null, uriRef10.getQuery());
        assertEquals("s", uriRef10.getFragment());

        URIReference uriRef11 = new URIReferenceResolver().resolve(
            URIReference.parse("g?y#s", UTF_8), URIReference.parse("http://a/b/c/d;p?q", UTF_8));
        assertEquals("http://a/b/c/g?y#s", uriRef11.toString());
        assertEquals(false, uriRef11.isRelativeReference());
        assertEquals("http", uriRef11.getScheme());
        assertEquals(true, uriRef11.hasAuthority());
        assertEquals("a", uriRef11.getAuthority().toString());
        assertEquals(null, uriRef11.getUserinfo());
        assertEquals("a", uriRef11.getHost().toString());
        assertEquals("a", uriRef11.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef11.getHost().getType());
        assertEquals(-1, uriRef11.getPort());
        assertEquals("/b/c/g", uriRef11.getPath());
        assertEquals("y", uriRef11.getQuery());
        assertEquals("s", uriRef11.getFragment());

        URIReference uriRef12 = new URIReferenceResolver().resolve(
            URIReference.parse(";x", UTF_8), URIReference.parse("http://a/b/c/d;p?q", UTF_8));
        assertEquals("http://a/b/c/;x", uriRef12.toString());
        assertEquals(false, uriRef12.isRelativeReference());
        assertEquals("http", uriRef12.getScheme());
        assertEquals(true, uriRef12.hasAuthority());
        assertEquals("a", uriRef12.getAuthority().toString());
        assertEquals(null, uriRef12.getUserinfo());
        assertEquals("a", uriRef12.getHost().toString());
        assertEquals("a", uriRef12.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef12.getHost().getType());
        assertEquals(-1, uriRef12.getPort());
        assertEquals("/b/c/;x", uriRef12.getPath());
        assertEquals(null, uriRef12.getQuery());
        assertEquals(null, uriRef12.getFragment());

        URIReference uriRef13 = new URIReferenceResolver().resolve(
            URIReference.parse("g;x", UTF_8), URIReference.parse("http://a/b/c/d;p?q", UTF_8));
        assertEquals("http://a/b/c/g;x", uriRef13.toString());
        assertEquals(false, uriRef13.isRelativeReference());
        assertEquals("http", uriRef13.getScheme());
        assertEquals(true, uriRef13.hasAuthority());
        assertEquals("a", uriRef13.getAuthority().toString());
        assertEquals(null, uriRef13.getUserinfo());
        assertEquals("a", uriRef13.getHost().toString());
        assertEquals("a", uriRef13.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef13.getHost().getType());
        assertEquals(-1, uriRef13.getPort());
        assertEquals("/b/c/g;x", uriRef13.getPath());
        assertEquals(null, uriRef13.getQuery());
        assertEquals(null, uriRef13.getFragment());

        URIReference uriRef14 = new URIReferenceResolver().resolve(
            URIReference.parse("g;x?y#s", UTF_8), URIReference.parse("http://a/b/c/d;p?q", UTF_8));
        assertEquals("http://a/b/c/g;x?y#s", uriRef14.toString());
        assertEquals(false, uriRef14.isRelativeReference());
        assertEquals("http", uriRef14.getScheme());
        assertEquals(true, uriRef14.hasAuthority());
        assertEquals("a", uriRef14.getAuthority().toString());
        assertEquals(null, uriRef14.getUserinfo());
        assertEquals("a", uriRef14.getHost().toString());
        assertEquals("a", uriRef14.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef14.getHost().getType());
        assertEquals(-1, uriRef14.getPort());
        assertEquals("/b/c/g;x", uriRef14.getPath());
        assertEquals("y", uriRef14.getQuery());
        assertEquals("s", uriRef14.getFragment());

        URIReference uriRef15 = new URIReferenceResolver().resolve(
            URIReference.parse("", UTF_8), URIReference.parse("http://a/b/c/d;p?q", UTF_8));
        assertEquals("http://a/b/c/d;p?q", uriRef15.toString());
        assertEquals(false, uriRef15.isRelativeReference());
        assertEquals("http", uriRef15.getScheme());
        assertEquals(true, uriRef15.hasAuthority());
        assertEquals("a", uriRef15.getAuthority().toString());
        assertEquals(null, uriRef15.getUserinfo());
        assertEquals("a", uriRef15.getHost().toString());
        assertEquals("a", uriRef15.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef15.getHost().getType());
        assertEquals(-1, uriRef15.getPort());
        assertEquals("/b/c/d;p", uriRef15.getPath());
        assertEquals("q", uriRef15.getQuery());
        assertEquals(null, uriRef15.getFragment());

        URIReference uriRef16 = new URIReferenceResolver().resolve(
            URIReference.parse(".", UTF_8), URIReference.parse("http://a/b/c/d;p?q", UTF_8));
        assertEquals("http://a/b/c/", uriRef16.toString());
        assertEquals(false, uriRef16.isRelativeReference());
        assertEquals("http", uriRef16.getScheme());
        assertEquals(true, uriRef16.hasAuthority());
        assertEquals("a", uriRef16.getAuthority().toString());
        assertEquals(null, uriRef16.getUserinfo());
        assertEquals("a", uriRef16.getHost().toString());
        assertEquals("a", uriRef16.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef16.getHost().getType());
        assertEquals(-1, uriRef16.getPort());
        assertEquals("/b/c/", uriRef16.getPath());
        assertEquals(null, uriRef16.getQuery());
        assertEquals(null, uriRef16.getFragment());

        URIReference uriRef17 = new URIReferenceResolver().resolve(
            URIReference.parse("./", UTF_8), URIReference.parse("http://a/b/c/d;p?q", UTF_8));
        assertEquals("http://a/b/c/", uriRef17.toString());
        assertEquals(false, uriRef17.isRelativeReference());
        assertEquals("http", uriRef17.getScheme());
        assertEquals(true, uriRef17.hasAuthority());
        assertEquals("a", uriRef17.getAuthority().toString());
        assertEquals(null, uriRef17.getUserinfo());
        assertEquals("a", uriRef17.getHost().toString());
        assertEquals("a", uriRef17.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef17.getHost().getType());
        assertEquals(-1, uriRef17.getPort());
        assertEquals("/b/c/", uriRef17.getPath());
        assertEquals(null, uriRef17.getQuery());
        assertEquals(null, uriRef17.getFragment());

        URIReference uriRef18 = new URIReferenceResolver().resolve(
            URIReference.parse("..", UTF_8), URIReference.parse("http://a/b/c/d;p?q", UTF_8));
        assertEquals("http://a/b/", uriRef18.toString());
        assertEquals(false, uriRef18.isRelativeReference());
        assertEquals("http", uriRef18.getScheme());
        assertEquals(true, uriRef18.hasAuthority());
        assertEquals("a", uriRef18.getAuthority().toString());
        assertEquals(null, uriRef18.getUserinfo());
        assertEquals("a", uriRef18.getHost().toString());
        assertEquals("a", uriRef18.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef18.getHost().getType());
        assertEquals(-1, uriRef18.getPort());
        assertEquals("/b/", uriRef18.getPath());
        assertEquals(null, uriRef18.getQuery());
        assertEquals(null, uriRef18.getFragment());

        URIReference uriRef19 = new URIReferenceResolver().resolve(
            URIReference.parse("../", UTF_8), URIReference.parse("http://a/b/c/d;p?q", UTF_8));
        assertEquals("http://a/b/", uriRef19.toString());
        assertEquals(false, uriRef19.isRelativeReference());
        assertEquals("http", uriRef19.getScheme());
        assertEquals(true, uriRef19.hasAuthority());
        assertEquals("a", uriRef19.getAuthority().toString());
        assertEquals(null, uriRef19.getUserinfo());
        assertEquals("a", uriRef19.getHost().toString());
        assertEquals("a", uriRef19.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef19.getHost().getType());
        assertEquals(-1, uriRef19.getPort());
        assertEquals("/b/", uriRef19.getPath());
        assertEquals(null, uriRef19.getQuery());
        assertEquals(null, uriRef19.getFragment());

        URIReference uriRef20 = new URIReferenceResolver().resolve(
            URIReference.parse("../g", UTF_8), URIReference.parse("http://a/b/c/d;p?q", UTF_8));
        assertEquals("http://a/b/g", uriRef20.toString());
        assertEquals(false, uriRef20.isRelativeReference());
        assertEquals("http", uriRef20.getScheme());
        assertEquals(true, uriRef20.hasAuthority());
        assertEquals("a", uriRef20.getAuthority().toString());
        assertEquals(null, uriRef20.getUserinfo());
        assertEquals("a", uriRef20.getHost().toString());
        assertEquals("a", uriRef20.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef20.getHost().getType());
        assertEquals(-1, uriRef20.getPort());
        assertEquals("/b/g", uriRef20.getPath());
        assertEquals(null, uriRef20.getQuery());
        assertEquals(null, uriRef20.getFragment());

        URIReference uriRef21 = new URIReferenceResolver().resolve(
            URIReference.parse("../..", UTF_8), URIReference.parse("http://a/b/c/d;p?q", UTF_8));
        assertEquals("http://a/", uriRef21.toString());
        assertEquals(false, uriRef21.isRelativeReference());
        assertEquals("http", uriRef21.getScheme());
        assertEquals(true, uriRef21.hasAuthority());
        assertEquals("a", uriRef21.getAuthority().toString());
        assertEquals(null, uriRef21.getUserinfo());
        assertEquals("a", uriRef21.getHost().toString());
        assertEquals("a", uriRef21.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef21.getHost().getType());
        assertEquals(-1, uriRef21.getPort());
        assertEquals("/", uriRef21.getPath());
        assertEquals(null, uriRef21.getQuery());
        assertEquals(null, uriRef21.getFragment());

        URIReference uriRef22 = new URIReferenceResolver().resolve(
            URIReference.parse("../../", UTF_8), URIReference.parse("http://a/b/c/d;p?q", UTF_8));
        assertEquals("http://a/", uriRef22.toString());
        assertEquals(false, uriRef22.isRelativeReference());
        assertEquals("http", uriRef22.getScheme());
        assertEquals(true, uriRef22.hasAuthority());
        assertEquals("a", uriRef22.getAuthority().toString());
        assertEquals(null, uriRef22.getUserinfo());
        assertEquals("a", uriRef22.getHost().toString());
        assertEquals("a", uriRef22.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef22.getHost().getType());
        assertEquals(-1, uriRef22.getPort());
        assertEquals("/", uriRef22.getPath());
        assertEquals(null, uriRef22.getQuery());
        assertEquals(null, uriRef22.getFragment());

        URIReference uriRef23 = new URIReferenceResolver().resolve(
            URIReference.parse("../../g", UTF_8), URIReference.parse("http://a/b/c/d;p?q", UTF_8));
        assertEquals("http://a/g", uriRef23.toString());
        assertEquals(false, uriRef23.isRelativeReference());
        assertEquals("http", uriRef23.getScheme());
        assertEquals(true, uriRef23.hasAuthority());
        assertEquals("a", uriRef23.getAuthority().toString());
        assertEquals(null, uriRef23.getUserinfo());
        assertEquals("a", uriRef23.getHost().toString());
        assertEquals("a", uriRef23.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef23.getHost().getType());
        assertEquals(-1, uriRef23.getPort());
        assertEquals("/g", uriRef23.getPath());
        assertEquals(null, uriRef23.getQuery());
        assertEquals(null, uriRef23.getFragment());

        URIReference uriRef24 = new URIReferenceResolver().resolve(
            URIReference.parse("g?y/./x", UTF_8), URIReference.parse("http://a/b/c/d;p?q", UTF_8));
        assertEquals("http://a/b/c/g?y/./x", uriRef24.toString());
        assertEquals(false, uriRef24.isRelativeReference());
        assertEquals("http", uriRef24.getScheme());
        assertEquals(true, uriRef24.hasAuthority());
        assertEquals("a", uriRef24.getAuthority().toString());
        assertEquals(null, uriRef24.getUserinfo());
        assertEquals("a", uriRef24.getHost().toString());
        assertEquals("a", uriRef24.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef24.getHost().getType());
        assertEquals(-1, uriRef24.getPort());
        assertEquals("/b/c/g", uriRef24.getPath());
        assertEquals("y/./x", uriRef24.getQuery());
        assertEquals(null, uriRef24.getFragment());

        URIReference uriRef25 = new URIReferenceResolver().resolve(
            URIReference.parse("g?y/../x", UTF_8), URIReference.parse("http://a/b/c/d;p?q", UTF_8));
        assertEquals("http://a/b/c/g?y/../x", uriRef25.toString());
        assertEquals(false, uriRef25.isRelativeReference());
        assertEquals("http", uriRef25.getScheme());
        assertEquals(true, uriRef25.hasAuthority());
        assertEquals("a", uriRef25.getAuthority().toString());
        assertEquals(null, uriRef25.getUserinfo());
        assertEquals("a", uriRef25.getHost().toString());
        assertEquals("a", uriRef25.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef25.getHost().getType());
        assertEquals(-1, uriRef25.getPort());
        assertEquals("/b/c/g", uriRef25.getPath());
        assertEquals("y/../x", uriRef25.getQuery());
        assertEquals(null, uriRef25.getFragment());

        URIReference uriRef26 = new URIReferenceResolver().resolve(
            URIReference.parse("g#s/./x", UTF_8), URIReference.parse("http://a/b/c/d;p?q", UTF_8));
        assertEquals("http://a/b/c/g#s/./x", uriRef26.toString());
        assertEquals(false, uriRef26.isRelativeReference());
        assertEquals("http", uriRef26.getScheme());
        assertEquals(true, uriRef26.hasAuthority());
        assertEquals("a", uriRef26.getAuthority().toString());
        assertEquals(null, uriRef26.getUserinfo());
        assertEquals("a", uriRef26.getHost().toString());
        assertEquals("a", uriRef26.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef26.getHost().getType());
        assertEquals(-1, uriRef26.getPort());
        assertEquals("/b/c/g", uriRef26.getPath());
        assertEquals(null, uriRef26.getQuery());
        assertEquals("s/./x", uriRef26.getFragment());

        URIReference uriRef27 = new URIReferenceResolver().resolve(
            URIReference.parse("g#s/../x", UTF_8), URIReference.parse("http://a/b/c/d;p?q", UTF_8));
        assertEquals("http://a/b/c/g#s/../x", uriRef27.toString());
        assertEquals(false, uriRef27.isRelativeReference());
        assertEquals("http", uriRef27.getScheme());
        assertEquals(true, uriRef27.hasAuthority());
        assertEquals("a", uriRef27.getAuthority().toString());
        assertEquals(null, uriRef27.getUserinfo());
        assertEquals("a", uriRef27.getHost().toString());
        assertEquals("a", uriRef27.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef27.getHost().getType());
        assertEquals(-1, uriRef27.getPort());
        assertEquals("/b/c/g", uriRef27.getPath());
        assertEquals(null, uriRef27.getQuery());
        assertEquals("s/../x", uriRef27.getFragment());

        assertThrowsNPE(
            "The input string must not be null.",
            () -> new URIReferenceResolver().resolve(
                URIReference.parse((String)null, UTF_8), URIReference.parse("http://a/b/c/d;p?q", UTF_8)));

        assertThrowsISE(
            "The base URI must have a scheme.",
            () -> new URIReferenceResolver().resolve(
                URIReference.parse("g", UTF_8), URIReference.parse("/a/b/c/d;p?q", UTF_8)));

        assertThrowsISE(
            "The base URI must not have a fragment.",
            () -> new URIReferenceResolver().resolve(
                URIReference.parse("g", UTF_8), URIReference.parse("http://a/b/c/d;p?q#s", UTF_8)));
    }
}

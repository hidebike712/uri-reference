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
import static org.czeal.rfc3986.HostType.IPV6;
import static org.czeal.rfc3986.HostType.IPVFUTURE;
import static org.czeal.rfc3986.HostType.REGNAME;
import static org.czeal.rfc3986.TestUtils.assertThrowsIAE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;


public class URIReferenceParserTest
{
    @Test
    public void test_parse()
    {
        URIReference uriRef1 = new URIReferenceParser().parse("http://example.com", UTF_8);
        assertEquals("http://example.com", uriRef1.toString());
        assertEquals(false, uriRef1.isRelativeReference());
        assertEquals("http", uriRef1.getScheme());
        assertEquals(true, uriRef1.hasAuthority());
        assertEquals("example.com", uriRef1.getAuthority().toString());
        assertEquals(null, uriRef1.getUserinfo());
        assertEquals("example.com", uriRef1.getHost().toString());
        assertEquals("example.com", uriRef1.getHost().getValue());
        assertEquals(REGNAME, uriRef1.getHost().getType());
        assertEquals(-1, uriRef1.getPort());
        assertEquals("", uriRef1.getPath());
        assertEquals(null, uriRef1.getQuery());
        assertEquals(null, uriRef1.getFragment());

        URIReference uriRef2 = new URIReferenceParser().parse("hTTp://example.com", UTF_8);;
        assertEquals("hTTp://example.com", uriRef2.toString());
        assertEquals(false, uriRef2.isRelativeReference());
        assertEquals("hTTp", uriRef2.getScheme());
        assertEquals(true, uriRef2.hasAuthority());
        assertEquals("example.com", uriRef2.getAuthority().toString());
        assertEquals(null, uriRef2.getUserinfo());
        assertEquals("example.com", uriRef2.getHost().toString());
        assertEquals("example.com", uriRef2.getHost().getValue());
        assertEquals(REGNAME, uriRef2.getHost().getType());
        assertEquals(-1, uriRef2.getPort());
        assertEquals("", uriRef2.getPath());
        assertEquals(null, uriRef2.getQuery());
        assertEquals(null, uriRef2.getFragment());

        URIReference uriRef3 = new URIReferenceParser().parse("//example.com", UTF_8);;
        assertEquals("//example.com", uriRef3.toString());
        assertEquals(true, uriRef3.isRelativeReference());
        assertEquals(null, uriRef3.getScheme());
        assertEquals(true, uriRef3.hasAuthority());
        assertEquals("example.com", uriRef3.getAuthority().toString());
        assertEquals(null, uriRef3.getUserinfo());
        assertEquals("example.com", uriRef3.getHost().toString());
        assertEquals("example.com", uriRef3.getHost().getValue());
        assertEquals(REGNAME, uriRef3.getHost().getType());
        assertEquals(-1, uriRef3.getPort());
        assertEquals("", uriRef3.getPath());
        assertEquals(null, uriRef3.getQuery());
        assertEquals(null, uriRef3.getFragment());

        URIReference uriRef4 = new URIReferenceParser().parse("http:", UTF_8);;
        assertEquals(false, uriRef4.isRelativeReference());
        assertEquals("http", uriRef4.getScheme());
        assertEquals(false, uriRef4.hasAuthority());
        assertEquals(null, uriRef4.getAuthority());
        assertEquals(null, uriRef4.getUserinfo());
        assertEquals(null, uriRef4.getHost());
        assertEquals(-1, uriRef4.getPort());
        assertEquals("", uriRef4.getPath());
        assertEquals(null, uriRef4.getQuery());
        assertEquals(null, uriRef4.getFragment());

        URIReference uriRef5 = new URIReferenceParser().parse("http://john@example.com", UTF_8);;
        assertEquals("http://john@example.com", uriRef5.toString());
        assertEquals(false, uriRef5.isRelativeReference());
        assertEquals("http", uriRef5.getScheme());
        assertEquals(true, uriRef5.hasAuthority());
        assertEquals("john@example.com", uriRef5.getAuthority().toString());
        assertEquals("john", uriRef5.getUserinfo());
        assertEquals("example.com", uriRef5.getHost().toString());
        assertEquals("example.com", uriRef5.getHost().getValue());
        assertEquals(REGNAME, uriRef5.getHost().getType());
        assertEquals(-1, uriRef5.getPort());
        assertEquals("", uriRef5.getPath());
        assertEquals(null, uriRef5.getQuery());
        assertEquals(null, uriRef5.getFragment());

        URIReference uriRef6 = new URIReferenceParser().parse("http://%6A%6F%68%6E@example.com", UTF_8);;
        assertEquals("http://%6A%6F%68%6E@example.com", uriRef6.toString());
        assertEquals(false, uriRef6.isRelativeReference());
        assertEquals("http", uriRef6.getScheme());
        assertEquals(true, uriRef6.hasAuthority());
        assertEquals("%6A%6F%68%6E@example.com", uriRef6.getAuthority().toString());
        assertEquals("%6A%6F%68%6E", uriRef6.getUserinfo());
        assertEquals("example.com", uriRef6.getHost().toString());
        assertEquals("example.com", uriRef6.getHost().getValue());
        assertEquals(REGNAME, uriRef6.getHost().getType());
        assertEquals(-1, uriRef6.getPort());
        assertEquals("", uriRef6.getPath());
        assertEquals(null, uriRef6.getQuery());
        assertEquals(null, uriRef6.getFragment());

        URIReference uriRef7 = new URIReferenceParser().parse("http://101.102.103.104", UTF_8);;
        assertEquals("http://101.102.103.104", uriRef7.toString());
        assertEquals(false, uriRef7.isRelativeReference());
        assertEquals("http", uriRef7.getScheme());
        assertEquals(true, uriRef7.hasAuthority());
        assertEquals("101.102.103.104", uriRef7.getAuthority().toString());
        assertEquals(null, uriRef7.getUserinfo());
        assertEquals("101.102.103.104", uriRef7.getHost().toString());
        assertEquals("101.102.103.104", uriRef7.getHost().getValue());
        assertEquals(HostType.IPV4, uriRef7.getHost().getType());
        assertEquals(-1, uriRef7.getPort());
        assertEquals("", uriRef7.getPath());
        assertEquals(null, uriRef7.getQuery());
        assertEquals(null, uriRef7.getFragment());

        URIReference uriRef8 = new URIReferenceParser().parse("http://[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]", UTF_8);;
        assertEquals("http://[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]", uriRef8.toString());
        assertEquals(false, uriRef8.isRelativeReference());
        assertEquals("http", uriRef8.getScheme());
        assertEquals(true, uriRef8.hasAuthority());
        assertEquals("[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]", uriRef8.getAuthority().toString());
        assertEquals(null, uriRef8.getAuthority().getUserinfo());
        assertEquals("[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]", uriRef8.getHost().toString());
        assertEquals("[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]", uriRef8.getHost().getValue());
        assertEquals(IPV6, uriRef8.getHost().getType());
        assertEquals(-1, uriRef8.getPort());
        assertEquals("", uriRef8.getPath());
        assertEquals(null, uriRef8.getQuery());
        assertEquals(null, uriRef8.getFragment());

        URIReference uriRef9 = new URIReferenceParser().parse("http://[2001:db8:0:1:1:1:1:1]", UTF_8);;
        assertEquals("http://[2001:db8:0:1:1:1:1:1]", uriRef9.toString());
        assertEquals(false, uriRef9.isRelativeReference());
        assertEquals("http", uriRef9.getScheme());
        assertEquals(true, uriRef9.hasAuthority());
        assertEquals("[2001:db8:0:1:1:1:1:1]", uriRef9.getAuthority().toString());
        assertEquals(null, uriRef9.getUserinfo());
        assertEquals("[2001:db8:0:1:1:1:1:1]", uriRef9.getHost().toString());
        assertEquals("[2001:db8:0:1:1:1:1:1]", uriRef9.getHost().getValue());
        assertEquals(IPV6, uriRef9.getHost().getType());
        assertEquals(-1, uriRef9.getPort());
        assertEquals("", uriRef9.getPath());
        assertEquals(null, uriRef9.getQuery());
        assertEquals(null, uriRef9.getFragment());

        URIReference uriRef10 = new URIReferenceParser().parse("http://[2001:0:9d38:6abd:0:0:0:42]", UTF_8);;
        assertEquals("http://[2001:0:9d38:6abd:0:0:0:42]", uriRef10.toString());
        assertEquals(false, uriRef10.isRelativeReference());
        assertEquals("http", uriRef10.getScheme());
        assertEquals(true, uriRef10.hasAuthority());
        assertEquals("[2001:0:9d38:6abd:0:0:0:42]", uriRef10.getAuthority().toString());
        assertEquals(null, uriRef10.getUserinfo());
        assertEquals("[2001:0:9d38:6abd:0:0:0:42]", uriRef10.getHost().toString());
        assertEquals("[2001:0:9d38:6abd:0:0:0:42]", uriRef10.getHost().getValue());
        assertEquals(IPV6, uriRef10.getHost().getType());
        assertEquals(-1, uriRef10.getPort());
        assertEquals("", uriRef10.getPath());
        assertEquals(null, uriRef10.getQuery());
        assertEquals(null, uriRef10.getFragment());

        URIReference uriRef11 = new URIReferenceParser().parse("http://[fe80::1]", UTF_8);;
        assertEquals("http://[fe80::1]", uriRef11.toString());
        assertEquals(false, uriRef11.isRelativeReference());
        assertEquals("http", uriRef11.getScheme());
        assertEquals(true, uriRef11.hasAuthority());
        assertEquals("[fe80::1]", uriRef11.getAuthority().toString());
        assertEquals(null, uriRef11.getUserinfo());
        assertEquals("[fe80::1]", uriRef11.getHost().toString());
        assertEquals("[fe80::1]", uriRef11.getHost().getValue());
        assertEquals(IPV6, uriRef11.getHost().getType());
        assertEquals(-1, uriRef11.getPort());
        assertEquals("", uriRef11.getPath());
        assertEquals(null, uriRef11.getQuery());
        assertEquals(null, uriRef11.getFragment());

        URIReference uriRef12 = new URIReferenceParser().parse("http://[2001:0:3238:DFE1:63::FEFB]", UTF_8);;
        assertEquals("http://[2001:0:3238:DFE1:63::FEFB]", uriRef12.toString());
        assertEquals(false, uriRef12.isRelativeReference());
        assertEquals("http", uriRef12.getScheme());
        assertEquals(true, uriRef12.hasAuthority());
        assertEquals("[2001:0:3238:DFE1:63::FEFB]", uriRef12.getAuthority().toString());
        assertEquals(null, uriRef12.getUserinfo());
        assertEquals("[2001:0:3238:DFE1:63::FEFB]", uriRef12.getHost().toString());
        assertEquals("[2001:0:3238:DFE1:63::FEFB]", uriRef12.getHost().getValue());
        assertEquals(IPV6, uriRef12.getHost().getType());
        assertEquals(-1, uriRef12.getPort());
        assertEquals("", uriRef12.getPath());
        assertEquals(null, uriRef12.getQuery());
        assertEquals(null, uriRef12.getFragment());

        URIReference uriRef13 = new URIReferenceParser().parse("http://[v1.fe80::a+en1]", UTF_8);;
        assertEquals("http://[v1.fe80::a+en1]", uriRef13.toString());
        assertEquals(false, uriRef13.isRelativeReference());
        assertEquals("http", uriRef13.getScheme());
        assertEquals(true, uriRef13.hasAuthority());
        assertEquals("[v1.fe80::a+en1]", uriRef13.getAuthority().toString());
        assertEquals(null, uriRef13.getUserinfo());
        assertEquals("[v1.fe80::a+en1]", uriRef13.getHost().toString());
        assertEquals("[v1.fe80::a+en1]", uriRef13.getHost().getValue());
        assertEquals(IPVFUTURE, uriRef13.getHost().getType());
        assertEquals(-1, uriRef13.getPort());
        assertEquals("", uriRef13.getPath());
        assertEquals(null, uriRef13.getQuery());
        assertEquals(null, uriRef13.getFragment());

        URIReference uriRef14 = new URIReferenceParser().parse("http://%65%78%61%6D%70%6C%65%2E%63%6F%6D", UTF_8);;
        assertEquals("http://%65%78%61%6D%70%6C%65%2E%63%6F%6D", uriRef14.toString());
        assertEquals(false, uriRef14.isRelativeReference());
        assertEquals("http", uriRef14.getScheme());
        assertEquals(true, uriRef14.hasAuthority());
        assertEquals("%65%78%61%6D%70%6C%65%2E%63%6F%6D", uriRef14.getAuthority().toString());
        assertEquals(null, uriRef14.getUserinfo());
        assertEquals("%65%78%61%6D%70%6C%65%2E%63%6F%6D", uriRef14.getHost().toString());
        assertEquals("%65%78%61%6D%70%6C%65%2E%63%6F%6D", uriRef14.getHost().getValue());
        assertEquals(REGNAME, uriRef14.getHost().getType());
        assertEquals(-1, uriRef14.getPort());
        assertEquals("", uriRef14.getPath());
        assertEquals(null, uriRef14.getQuery());
        assertEquals(null, uriRef14.getFragment());

        URIReference uriRef15 = new URIReferenceParser().parse("http://", UTF_8);;
        assertEquals(false, uriRef15.isRelativeReference());
        assertEquals("http", uriRef15.getScheme());
        assertEquals(true, uriRef15.hasAuthority());
        assertEquals("", uriRef15.getAuthority().toString());
        assertEquals(null, uriRef15.getUserinfo());
        assertEquals("", uriRef15.getHost().toString());
        assertEquals("", uriRef15.getHost().getValue());
        assertEquals(REGNAME, uriRef15.getHost().getType());
        assertEquals(-1, uriRef15.getPort());
        assertEquals("", uriRef15.getPath());
        assertEquals(null, uriRef15.getQuery());
        assertEquals(null, uriRef15.getFragment());

        URIReference uriRef16 = new URIReferenceParser().parse("http:///a", UTF_8);;
        assertEquals(false, uriRef16.isRelativeReference());
        assertEquals("http", uriRef16.getScheme());
        assertEquals(true, uriRef16.hasAuthority());
        assertEquals("", uriRef16.getAuthority().toString());
        assertEquals(null, uriRef16.getUserinfo());
        assertEquals("", uriRef16.getHost().toString());
        assertEquals("", uriRef16.getHost().getValue());
        assertEquals(REGNAME, uriRef16.getHost().getType());
        assertEquals(-1, uriRef16.getPort());
        assertEquals("/a", uriRef16.getPath());
        assertEquals(null, uriRef16.getQuery());
        assertEquals(null, uriRef16.getFragment());

        URIReference uriRef17 = new URIReferenceParser().parse("http://example.com:80", UTF_8);;
        assertEquals(false, uriRef17.isRelativeReference());
        assertEquals("http", uriRef17.getScheme());
        assertEquals(true, uriRef17.hasAuthority());
        assertEquals("example.com:80", uriRef17.getAuthority().toString());
        assertEquals(null, uriRef17.getUserinfo());
        assertEquals("example.com", uriRef17.getHost().toString());
        assertEquals("example.com", uriRef17.getHost().getValue());
        assertEquals(REGNAME, uriRef17.getHost().getType());
        assertEquals(80, uriRef17.getPort());
        assertEquals("", uriRef17.getPath());
        assertEquals(null, uriRef17.getQuery());
        assertEquals(null, uriRef17.getFragment());

        URIReference uriRef18 = new URIReferenceParser().parse("http://example.com:", UTF_8);;
        assertEquals(false, uriRef18.isRelativeReference());
        assertEquals("http", uriRef18.getScheme());
        assertEquals(true, uriRef18.hasAuthority());
        assertEquals("example.com", uriRef18.getAuthority().toString());
        assertEquals(null, uriRef18.getUserinfo());
        assertEquals("example.com", uriRef18.getHost().toString());
        assertEquals("example.com", uriRef18.getHost().getValue());
        assertEquals(REGNAME, uriRef18.getHost().getType());
        assertEquals(-1, uriRef18.getPort());
        assertEquals("", uriRef18.getPath());
        assertEquals(null, uriRef18.getQuery());
        assertEquals(null, uriRef18.getFragment());

        URIReference uriRef19 = new URIReferenceParser().parse("http://example.com:001", UTF_8);;
        assertEquals(false, uriRef19.isRelativeReference());
        assertEquals("http", uriRef19.getScheme());
        assertEquals(true, uriRef19.hasAuthority());
        assertEquals("example.com:1", uriRef19.getAuthority().toString());
        assertEquals(null, uriRef19.getAuthority().getUserinfo());
        assertEquals("example.com", uriRef19.getHost().toString());
        assertEquals("example.com", uriRef19.getHost().getValue());
        assertEquals(REGNAME, uriRef19.getHost().getType());
        assertEquals(1, uriRef19.getPort());
        assertEquals("", uriRef19.getPath());
        assertEquals(null, uriRef19.getQuery());
        assertEquals(null, uriRef19.getFragment());

        URIReference uriRef20 = new URIReferenceParser().parse("http://example.com/a/b/c", UTF_8);;
        assertEquals("http://example.com/a/b/c", uriRef20.toString());
        assertEquals(false, uriRef20.isRelativeReference());
        assertEquals("http", uriRef20.getScheme());
        assertEquals(true, uriRef20.hasAuthority());
        assertEquals("example.com", uriRef20.getAuthority().toString());
        assertEquals(null, uriRef20.getAuthority().getUserinfo());
        assertEquals("example.com", uriRef20.getHost().toString());
        assertEquals("example.com", uriRef20.getHost().getValue());
        assertEquals(REGNAME, uriRef20.getHost().getType());
        assertEquals(-1, uriRef20.getPort());
        assertEquals("/a/b/c", uriRef20.getPath());
        assertEquals(null, uriRef20.getQuery());
        assertEquals(null, uriRef20.getFragment());

        URIReference uriRef21 = new URIReferenceParser().parse("http://example.com/%61/%62/%63", UTF_8);;
        assertEquals("http://example.com/%61/%62/%63", uriRef21.toString());
        assertEquals(false, uriRef21.isRelativeReference());
        assertEquals("http", uriRef21.getScheme());
        assertEquals(true, uriRef21.hasAuthority());
        assertEquals("example.com", uriRef21.getAuthority().toString());
        assertEquals(null, uriRef21.getUserinfo());
        assertEquals("example.com", uriRef21.getHost().toString());
        assertEquals("example.com", uriRef21.getHost().getValue());
        assertEquals(REGNAME, uriRef21.getHost().getType());
        assertEquals(-1, uriRef21.getPort());
        assertEquals("/%61/%62/%63", uriRef21.getPath());
        assertEquals(null, uriRef21.getQuery());
        assertEquals(null, uriRef21.getFragment());

        URIReference uriRef22 = new URIReferenceParser().parse("http:/a", UTF_8);;
        assertEquals(false, uriRef22.isRelativeReference());
        assertEquals("http", uriRef22.getScheme());
        assertEquals(false, uriRef22.hasAuthority());
        assertEquals(null, uriRef22.getAuthority());
        assertEquals(null, uriRef22.getUserinfo());
        assertEquals(null, uriRef22.getHost());
        assertEquals(-1, uriRef22.getPort());
        assertEquals("/a", uriRef22.getPath());
        assertEquals(null, uriRef22.getQuery());
        assertEquals(null, uriRef22.getFragment());

        URIReference uriRef23 = new URIReferenceParser().parse("http:a", UTF_8);;
        assertEquals(false, uriRef23.isRelativeReference());
        assertEquals("http", uriRef23.getScheme());
        assertEquals(false, uriRef23.hasAuthority());
        assertEquals(null, uriRef23.getAuthority());
        assertEquals(null, uriRef23.getUserinfo());
        assertEquals(null, uriRef23.getHost());
        assertEquals(-1, uriRef23.getPort());
        assertEquals("a", uriRef23.getPath());
        assertEquals(null, uriRef23.getQuery());
        assertEquals(null, uriRef23.getFragment());

        URIReference uriRef24 = new URIReferenceParser().parse("//", UTF_8);;
        assertEquals(true, uriRef24.isRelativeReference());
        assertEquals(null, uriRef24.getScheme());
        assertEquals(true, uriRef24.hasAuthority());
        assertEquals("", uriRef24.getAuthority().toString());
        assertEquals(null, uriRef24.getUserinfo());
        assertEquals("", uriRef24.getHost().toString());
        assertEquals("", uriRef24.getHost().getValue());
        assertEquals(REGNAME, uriRef24.getHost().getType());
        assertEquals(-1, uriRef24.getPort());
        assertEquals("", uriRef24.getPath());
        assertEquals(null, uriRef24.getQuery());
        assertEquals(null, uriRef24.getFragment());

        URIReference uriRef25 = new URIReferenceParser().parse("http://example.com?q", UTF_8);;
        assertEquals(false, uriRef25.isRelativeReference());
        assertEquals("http", uriRef25.getScheme());
        assertEquals(true, uriRef25.hasAuthority());
        assertEquals("example.com", uriRef25.getAuthority().toString());
        assertEquals(null, uriRef25.getUserinfo());
        assertEquals("example.com", uriRef25.getHost().toString());
        assertEquals("example.com", uriRef25.getHost().getValue());
        assertEquals(REGNAME, uriRef25.getHost().getType());
        assertEquals(-1, uriRef25.getPort());
        assertEquals("", uriRef25.getPath());
        assertEquals("q", uriRef25.getQuery());
        assertEquals(null, uriRef25.getFragment());

        URIReference uriRef26 = new URIReferenceParser().parse("http://example.com?", UTF_8);;
        assertEquals(false, uriRef26.isRelativeReference());
        assertEquals("http", uriRef26.getScheme());
        assertEquals(true, uriRef26.hasAuthority());
        assertEquals("example.com", uriRef26.getAuthority().toString());
        assertEquals(null, uriRef26.getUserinfo());
        assertEquals("example.com", uriRef26.getHost().toString());
        assertEquals("example.com", uriRef26.getHost().getValue());
        assertEquals(REGNAME, uriRef26.getHost().getType());
        assertEquals(-1, uriRef26.getPort());
        assertEquals("", uriRef26.getPath());
        assertEquals("", uriRef26.getQuery());
        assertEquals(null, uriRef26.getFragment());

        URIReference uriRef27 = new URIReferenceParser().parse("http://example.com#f", UTF_8);;
        assertEquals(false, uriRef27.isRelativeReference());
        assertEquals("http", uriRef27.getScheme());
        assertEquals(true, uriRef27.hasAuthority());
        assertEquals("example.com", uriRef27.getAuthority().toString());
        assertEquals(null, uriRef27.getUserinfo());
        assertEquals("example.com", uriRef27.getHost().toString());
        assertEquals("example.com", uriRef27.getHost().getValue());
        assertEquals(REGNAME, uriRef27.getHost().getType());
        assertEquals(-1, uriRef27.getPort());
        assertEquals("", uriRef27.getPath());
        assertEquals(null, uriRef27.getQuery());
        assertEquals("f", uriRef27.getFragment());

        URIReference uriRef28 = new URIReferenceParser().parse("http://example.com#", UTF_8);;
        assertEquals(false, uriRef28.isRelativeReference());
        assertEquals("http", uriRef28.getScheme());
        assertEquals(true, uriRef28.hasAuthority());
        assertEquals("example.com", uriRef28.getAuthority().toString());
        assertEquals(null, uriRef28.getUserinfo());
        assertEquals("example.com", uriRef28.getHost().toString());
        assertEquals("example.com", uriRef28.getHost().getValue());
        assertEquals(REGNAME, uriRef28.getHost().getType());
        assertEquals(-1, uriRef28.getPort());
        assertEquals("", uriRef28.getPath());
        assertEquals(null, uriRef28.getQuery());
        assertEquals("", uriRef28.getFragment());

        URIReference uriRef29 = new URIReferenceParser().parse("", UTF_8);;
        assertEquals(true, uriRef29.isRelativeReference());
        assertEquals(null, uriRef29.getScheme());
        assertEquals(false, uriRef29.hasAuthority());
        assertEquals(null, uriRef29.getAuthority());
        assertEquals(null, uriRef29.getUserinfo());
        assertEquals(null, uriRef29.getHost());
        assertEquals(-1, uriRef29.getPort());
        assertEquals("", uriRef29.getPath());
        assertEquals(null, uriRef29.getQuery());
        assertEquals(null, uriRef29.getFragment());

        assertThrowsIAE(
            "The path segment value \"1invalid:\" has an invalid character \":\" at the index 8.",
            () -> new URIReferenceParser().parse("1invalid://example.com", UTF_8));

        assertThrowsIAE(
            "The host value \"v@w\" has an invalid character \"@\" at the index 1.",
            () -> new URIReferenceParser().parse("http://u@v@w", UTF_8));

        assertThrowsIAE(
            "The port value \"1:2:3\" has an invalid character \":\" at the index 1.",
            () -> new URIReferenceParser().parse("http://example.com:1:2:3", UTF_8));

        assertThrowsIAE(
            "The query value \"[invalid_query]\" has an invalid character \"[\" at the index 0.",
            () -> new URIReferenceParser().parse("http://example.com?[invalid_query]", UTF_8));

        assertThrowsIAE(
            "The fragment value \"[invalid_fragment]\" has an invalid character \"[\" at the index 0.",
            () -> new URIReferenceParser().parse("http://example.com#[invalid_fragment]", UTF_8));

        assertThrowsIAE(
            "The port value \"b\" has an invalid character \"b\" at the index 0.",
            () -> new URIReferenceParser().parse("//a:b", UTF_8));

        assertThrowsIAE(
            "The port value \":\" has an invalid character \":\" at the index 0.",
            () -> new URIReferenceParser().parse("//::", UTF_8));
    }
}
